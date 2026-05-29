package colasoft

import (
	"cmp"
	"context"
	"crypto/rand"
	"slices"
	"sync/atomic"
	"time"

	lru "github.com/elastic/go-freelru"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pprofile"
	semconv "go.opentelemetry.io/otel/semconv/v1.4.0"

	"go.opentelemetry.io/ebpf-profiler/interpreter/gpu"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/xsync"
	"go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/support"
)

type (
	indexTable[T comparable] map[T]int32
	colaSoftReporter         struct {
		ctrl    Controller
		running atomic.Bool

		cache struct {
			heapHash      map[int64]libpf.TraceHash
			symbolization xsync.RWMutex[map[libpf.FrameID]*samples.SourceInfo]
			events        xsync.RWMutex[map[libpf.PID]map[libpf.Origin]samples.KeyToEventMapping]
			executables   *lru.SyncedLRU[libpf.FileID, samples.ExecInfo]
			frames        *lru.SyncedLRU[libpf.FileID, *xsync.RWMutex[map[libpf.AddressOrLineno]samples.SourceInfo]]
			lifetime      struct{ executables, frames time.Duration }
		}

		onCpuFreq    atomic.Int64
		limit, count atomic.Int64
		interval     atomic.Int64 // time.Duration
	}
)

var _ reporter.Reporter = (*colaSoftReporter)(nil)
var _ gpu.Reporter = (*colaSoftReporter)(nil)

func newColaSoftReporter(ctx context.Context, ctrl Controller) *colaSoftReporter {
	csr := &colaSoftReporter{ctrl: ctrl}
	csr.cache.heapHash = make(map[int64]libpf.TraceHash)
	csr.cache.events = xsync.NewRWMutex(make(map[libpf.PID]map[libpf.Origin]samples.KeyToEventMapping, 3))
	csr.cache.symbolization = xsync.NewRWMutex(make(map[libpf.FrameID]*samples.SourceInfo))
	csr.cache.executables, _ = lru.NewSynced[libpf.FileID, samples.ExecInfo](16384, libpf.FileID.Hash32)
	csr.cache.frames, _ = lru.NewSynced[libpf.FileID, *xsync.RWMutex[map[libpf.AddressOrLineno]samples.SourceInfo]](65536, libpf.FileID.Hash32)
	csr.cache.lifetime.executables = time.Hour
	csr.cache.lifetime.frames = time.Hour
	csr.limit.Store(2000)
	csr.onCpuFreq.Store(19) // default value
	csr.interval.Store(time.Minute.Nanoseconds())
	go csr.loop(ctx)
	return csr
}

func (c *colaSoftReporter) Demangle(n string) string { return c.ctrl.Demangle(n) }

func (c *colaSoftReporter) SetInterval(interval time.Duration) {
	c.interval.Swap(interval.Nanoseconds())
}
func (c *colaSoftReporter) Interval() time.Duration { return time.Duration(c.interval.Load()) }
func (c *colaSoftReporter) SetOnCPUFreq(freq int64) { c.onCpuFreq.Store(freq) }

func (c *colaSoftReporter) ReportFramesForTrace(*libpf.Trace)                                    {}
func (c *colaSoftReporter) ReportCountForTrace(libpf.TraceHash, uint16, *samples.TraceEventMeta) {}

func (c *colaSoftReporter) ReportTraceEvent(trace *libpf.Trace, meta *samples.TraceEventMeta) {
	supported := []libpf.Origin{
		support.TraceOriginSampling,
		support.TraceOriginOffCPU,
		support.TraceOriginHeap,
		support.TraceOriginCuda,
		support.TraceOriginCudaSynchronize,
	}
	if !slices.Contains(supported, meta.Origin) {
		log.Errorf("Skip reporting trace for unexpected %d origin", meta.Origin)
		return
	}

	if heap, ok := meta.Value.(*samples.MetaValueHeap); ok && heap.Bytes > 0 && heap.Addr > 0 {
		if heap.IsFree() {
			// 只有申请内存的时候才新创建event,如果是释放内存但是没有event说明这个地址是开启profile之前申请的，忽略掉
			hash, _ok := c.cache.heapHash[heap.Addr]
			if !_ok {
				return
			}
			delete(c.cache.heapHash, heap.Addr)
			trace.Hash = hash
		} else {
			c.cache.heapHash[heap.Addr] = trace.Hash
		}
		//不同的线程ID，导致key不一样，无法将栈进行合并,内存剖析不上报线程了。
		meta.TID = 0
	}

	key := samples.TraceAndMetaKey{
		Hash:           trace.Hash,
		Comm:           meta.Comm,
		ProcessName:    meta.ProcessName,
		ExecutablePath: meta.ExecutablePath,
		ApmServiceName: meta.APMServiceName,
		Pid:            int64(meta.PID),
		ExtraMeta:      c.ctrl.CollectExtraSampleMeta(trace, meta),
	}

	traceEventsMap := c.cache.events.WLock()
	defer c.cache.events.WUnlock(&traceEventsMap)
	if _, ok := (*traceEventsMap)[meta.PID]; !ok {
		(*traceEventsMap)[meta.PID] = make(map[libpf.Origin]samples.KeyToEventMapping)
	}
	if _, ok := (*traceEventsMap)[meta.PID][meta.Origin]; !ok {
		(*traceEventsMap)[meta.PID][meta.Origin] = make(samples.KeyToEventMapping)
	}
	events, exists := (*traceEventsMap)[meta.PID][meta.Origin][key]
	if !exists {
		events = &samples.TraceEvents{
			Files:              trace.Files,
			Linenos:            trace.Linenos,
			FrameTypes:         trace.FrameTypes,
			MappingStarts:      trace.MappingStart,
			MappingEnds:        trace.MappingEnd,
			MappingFileOffsets: trace.MappingFileOffsets,
		}
		c.count.Add(1)
		(*traceEventsMap)[meta.PID][meta.Origin][key] = events
	}
	events.Timestamps = append(events.Timestamps, uint64(meta.Timestamp))
	switch v := meta.Value.(type) {
	case *samples.MetaValueOffCPU:
		events.Values = append(events.Values, v.OffTime)
	case *samples.MetaValueAI:
		events.Timestamps = events.Timestamps[:len(events.Timestamps)-1] // AI类型时，meta.Timestamp的值是0
		// 采集层不做开关判断，全部落库：哪一侧有数据就记录哪一侧。
		// 上游 traceFixer 只在 host/kernel 侧存在有效 timing 时才填充对应字段，
		// 因此用 End != 0 判断该侧是否有数据；是否上报由生成层统一按开关决定。
		if v.Host.End != 0 {
			events.AIHost.Timestamps = append(events.AIHost.Timestamps, uint64(v.Host.End))
			events.AIHost.Durations = append(events.AIHost.Durations, v.Host.Duration)
		}
		if v.Kernel.End != 0 {
			events.AIKernel.Timestamps = append(events.AIKernel.Timestamps, uint64(v.Kernel.End))
			events.AIKernel.Durations = append(events.AIKernel.Durations, v.Kernel.Duration)
		}
	case *samples.MetaValueSynchronize:
		events.Values = append(events.Values, v.Duration)
	case *samples.MetaValueHeap:
		events.Timestamps[0] = slices.Max(events.Timestamps)
		events.Timestamps = events.Timestamps[:1] // 只记录最新的时间
		if events.Values == nil {
			if v.Addr > 0 {
				events.Values = []int64{0, 0, 0, 0}
			} else {
				events.Values = []int64{0, 0, -1, -1} // 不支持inuse
			}
		}
		allocSpace := &events.Values[0]
		allocCount := &events.Values[1]
		inuseSpace := &events.Values[2]
		inuseAllocCount := &events.Values[3]
		if v.IsFree() {
			*inuseSpace -= v.Bytes
			*inuseAllocCount--
		} else {
			*allocSpace += v.Bytes
			*allocCount += v.Count
			if v.Addr > 0 {
				*inuseSpace += v.Bytes
				*inuseAllocCount += v.Count
			}
		}
	default:
		events.Values = []int64{1} // ON-CPU
	}
	symbolization := c.cache.symbolization.WLock()
	defer c.cache.symbolization.WUnlock(&symbolization)
	for i, ft := range trace.FrameTypes {
		if ft != libpf.NativeFrame {
			continue
		}
		frameId := libpf.NewFrameID(trace.Files[i], trace.Linenos[i])
		if c.FrameKnown(frameId) {
			continue
		}
		(*symbolization)[frameId] = nil // lookup
	}
}

func (c *colaSoftReporter) SupportsReportTraceEvent() bool { return true }

func (c *colaSoftReporter) ExecutableKnown(fileID libpf.FileID) bool {
	_, known := c.cache.executables.GetAndRefresh(fileID, c.cache.lifetime.executables)
	return known || c.ctrl.ExecutableKnown(fileID)
}

func (c *colaSoftReporter) ExecutableMetadata(args *reporter.ExecutableMetadataArgs) {
	if args.Interp == libpf.Native {
		c.ctrl.ExecutableMetadata(args)
	}
	c.cache.executables.Add(args.FileID, samples.ExecInfo{FileName: args.FileName, GnuBuildID: args.GnuBuildID})
}

func (c *colaSoftReporter) FrameKnown(frameID libpf.FrameID) bool {
	known := false
	if frameMapLock, exists := c.cache.frames.GetAndRefresh(frameID.FileID(), c.cache.lifetime.frames); exists {
		frameMap := frameMapLock.RLock()
		defer frameMapLock.RUnlock(&frameMap)
		_, known = (*frameMap)[frameID.AddressOrLine()]
	}
	return known
}

func (c *colaSoftReporter) FrameMetadata(args *reporter.FrameMetadataArgs) {
	fileID := args.FrameID.FileID()
	addressOrLine := args.FrameID.AddressOrLine()
	info := samples.SourceInfo{
		LineNumber:     args.SourceLine,
		FilePath:       args.SourceFile,
		FunctionOffset: args.FunctionOffset,
		FunctionName:   args.FunctionName,
	}
	if frameMapLock, exists := c.cache.frames.GetAndRefresh(fileID, c.cache.lifetime.frames); exists {
		frameMap := frameMapLock.WLock()
		defer frameMapLock.WUnlock(&frameMap)

		info.FilePath = cmp.Or(args.SourceFile, (*frameMap)[addressOrLine].FilePath)
		(*frameMap)[addressOrLine] = info
		return
	}
	mu := xsync.NewRWMutex(map[libpf.AddressOrLineno]samples.SourceInfo{addressOrLine: info})
	c.cache.frames.Add(fileID, &mu)
}

func (c *colaSoftReporter) ReportHostMetadata(map[string]string) {}
func (c *colaSoftReporter) ReportHostMetadataBlocking(context.Context, map[string]string, int, time.Duration) error {
	return nil
}
func (c *colaSoftReporter) ConsumeTimeEvent(timeline *support.Timeline) {
	offset := c.ctrl.TimeOffset().Nanoseconds()
	start, end := int64(timeline.Start), int64(timeline.End)
	timeline.Start, timeline.End = uint64(start+offset), uint64(end+offset)
	c.ctrl.ConsumeTimeEvent(timeline)
	timeline.Start, timeline.End = uint64(start), uint64(end)
}

func (c *colaSoftReporter) ConsumeErrorEvent(evt *support.ErrorEvent) {
	c.ctrl.ConsumeErrorEvent(evt)
}

func (c *colaSoftReporter) Start(context.Context) error {
	c.running.Store(true)
	return nil
}
func (c *colaSoftReporter) Stop() { c.running.Store(false) }

func (c *colaSoftReporter) generate(events map[libpf.Origin]samples.KeyToEventMapping, symbolization map[libpf.FrameID]*samples.SourceInfo) pprofile.Profiles {
	profiles := pprofile.NewProfiles()
	profs := profiles.ResourceProfiles().AppendEmpty().ScopeProfiles().AppendEmpty().Profiles()
	for origin, evts := range events {
		if len(evts) == 0 {
			continue
		}
		prof := profs.AppendEmpty()
		var id pprofile.ProfileID
		if _, err := rand.Read(id[:]); err != nil {
			copy(id[:], "opentelemetry-ebpf-profiler")
		}
		prof.SetProfileID(id)
		c.setProfile(origin, evts, prof, symbolization)
		if prof.Sample().Len() == 0 {
			profs.RemoveIf(func(p pprofile.Profile) bool { return id == p.ProfileID() })
		}
	}
	return profiles
}

func (c *colaSoftReporter) setProfile(origin libpf.Origin, events map[samples.TraceAndMetaKey]*samples.TraceEvents, profile pprofile.Profile, symbolization map[libpf.FrameID]*samples.SourceInfo) {
	stringTab := newIndexTable[string]()
	funcTab := newIndexTable[samples.FuncInfo]()
	var sampleType [][2]string // [ [Type, Unit] ]
	var hostOn, kernelOn = gpu.GPU.EnableHostAPI(), gpu.GPU.EnableKernel()
	periodType := profile.PeriodType()
	switch origin {
	case support.TraceOriginSampling:
		freq := c.onCpuFreq.Load()
		if freq == 0 {
			return
		}
		sampleType = [][2]string{{"samples", "count"}}
		periodType.SetTypeStrindex(stringTab.Get("cpu"))
		periodType.SetUnitStrindex(stringTab.Get("nanoseconds"))
		profile.SetPeriod(1e9 / freq)
	case support.TraceOriginOffCPU:
		sampleType = [][2]string{{"events", "nanoseconds"}}
	case support.TraceOriginHeap:
		sampleType = [][2]string{
			{"heap", "bytes"},
			{"heap", "count"},
			{"heap", "using-byte"},
			{"heap", "using-count"},
		}
		periodType.SetTypeStrindex(stringTab.Get("heap"))
		periodType.SetUnitStrindex(stringTab.Get("bytes"))
	case support.TraceOriginCuda:
		if hostOn {
			sampleType = append(sampleType, [2]string{"ai-launch", "nanoseconds"})
		}
		if kernelOn {
			sampleType = append(sampleType, [2]string{"ai-execution", "nanoseconds"})
		}
		if len(sampleType) == 0 {
			return
		}
		periodType.SetTypeStrindex(stringTab.Get("ai"))
		periodType.SetUnitStrindex(stringTab.Get("nanoseconds"))
	case support.TraceOriginCudaSynchronize:
		// ai-sync-wait 属于 host-api 观测侧：开关关闭时在生成层丢弃。
		if !hostOn {
			return
		}
		sampleType = [][2]string{{"ai-synchronous-wait", "nanoseconds"}}
		periodType.SetTypeStrindex(stringTab.Get("ai"))
		periodType.SetUnitStrindex(stringTab.Get("nanoseconds"))
	default:
		log.Errorf("Generating profile for unsupported origin %d", origin)
		return
	}
	for _, stype := range sampleType {
		st := profile.SampleType().AppendEmpty()
		st.SetTypeStrindex(stringTab.Get(stype[0]))
		st.SetUnitStrindex(stringTab.Get(stype[1]))
	}

	// Temporary lookup to reference existing Mappings.
	fileIDtoMapping := make(map[libpf.FileID]int32)

	attrMgr := samples.NewAttrTableManager(profile.AttributeTable())
	var locationIndex int32
	var startTS, endTS pcommon.Timestamp
	now := time.Now()
	offset := c.ctrl.TimeOffset().Nanoseconds()
	for traceKey, traceInfo := range events {
		values := traceInfo.Values
		timestamps := traceInfo.Timestamps
		if origin == support.TraceOriginCuda {
			values = make([]int64, 0, 2)
			timestamps = make([]uint64, 0, len(traceInfo.AIHost.Timestamps)+len(traceInfo.AIKernel.Timestamps))
			if hostOn {
				var sum int64
				for _, d := range traceInfo.AIHost.Durations {
					sum += d
				}
				values = append(values, sum)
				timestamps = append(timestamps, traceInfo.AIHost.Timestamps...)
			}
			if kernelOn {
				var sum int64
				for _, d := range traceInfo.AIKernel.Durations {
					sum += d
				}
				values = append(values, sum)
				timestamps = append(timestamps, traceInfo.AIKernel.Timestamps...)
			}
			// 开关已开启，但该 trace 在 host/kernel 两侧都没有采集到有效 timing
			// （典型：开关中途切换后残留了另一侧的数据）。此时 timestamps 为空，
			// 之后 timestamps[0] 会越界崩溃，直接跳过该样本。
			if len(timestamps) == 0 {
				continue
			}
		} else if origin == support.TraceOriginHeap {
			// 内存profile生成时，所有调用用链的时间戳统一使用当前时间
			timestamps = []uint64{uint64(now.UnixNano())}
		}

		sample := profile.Sample().AppendEmpty()
		sample.SetLocationsStartIndex(locationIndex)
		sample.Value().Append(values...)

		slices.Sort(timestamps)
		for idx, ts := range timestamps {
			timestamps[idx] = uint64(int64(ts) + offset)
		}
		startTS = pcommon.Timestamp(timestamps[0])
		endTS = pcommon.Timestamp(timestamps[len(timestamps)-1])

		sample.TimestampsUnixNano().FromRaw(timestamps)

		// Walk every frame of the trace.
		for i := range traceInfo.FrameTypes {
			loc := profile.LocationTable().AppendEmpty()
			loc.SetAddress(uint64(traceInfo.Linenos[i]))

			switch frameKind := traceInfo.FrameTypes[i]; frameKind {
			case libpf.NativeFrame:
				frameId := libpf.NewFrameID(traceInfo.Files[i], traceInfo.Linenos[i])
				if si, ok := symbolization[frameId]; ok {
					line := loc.Line().AppendEmpty()
					line.SetLine(int64(si.LineNumber))
					line.SetFunctionIndex(funcTab.Get(samples.FuncInfo{Name: si.FunctionName, FileName: si.FilePath}))
				}

				var locationMappingIndex int32
				if tmpMappingIndex, exists := fileIDtoMapping[traceInfo.Files[i]]; exists {
					locationMappingIndex = tmpMappingIndex
				} else {
					idx := int32(len(fileIDtoMapping))
					fileIDtoMapping[traceInfo.Files[i]] = idx
					locationMappingIndex = idx

					var fileName = "UNKNOWN"
					ei, ok := c.cache.executables.GetAndRefresh(traceInfo.Files[i], c.cache.lifetime.executables)
					if ok {
						fileName = ei.FileName
					}

					mapping := profile.MappingTable().AppendEmpty()
					mapping.SetMemoryStart(uint64(traceInfo.MappingStarts[i]))
					mapping.SetMemoryLimit(uint64(traceInfo.MappingEnds[i]))
					mapping.SetFileOffset(traceInfo.MappingFileOffsets[i])
					mapping.SetFilenameStrindex(stringTab.Get(fileName))

					attrMgr.AppendOptionalString(mapping.AttributeIndices(), "process.executable.build_id.gnu", ei.GnuBuildID)
					attrMgr.AppendOptionalString(mapping.AttributeIndices(), "process.executable.build_id.htlhash", traceInfo.Files[i].StringNoQuotes())
				}
				loc.SetMappingIndex(locationMappingIndex)
			case libpf.AbortFrame:
				// Next step: Figure out how the OTLP protocol
				// could handle artificial frames, like AbortFrame,
				// that are not originated from a native or interpreted
				// program.
			default:
				// Store interpreted frame information as a Line message:
				line := loc.Line().AppendEmpty()
				fileIDInfoLock, exists := c.cache.frames.GetAndRefresh(traceInfo.Files[i], c.cache.lifetime.frames)
				var si samples.SourceInfo
				if !exists {
					si = samples.SourceInfo{FilePath: frameKind.String(), FunctionName: "UNREPORTED"}
				} else {
					fileIDInfo := fileIDInfoLock.RLock()
					if si, exists = (*fileIDInfo)[traceInfo.Linenos[i]]; !exists {
						si = samples.SourceInfo{FilePath: frameKind.String(), FunctionName: "UNRESOLVED"}
					}
					fileIDInfoLock.RUnlock(&fileIDInfo)
				}
				line.SetLine(int64(si.LineNumber))
				line.SetFunctionIndex(funcTab.Get(samples.FuncInfo{Name: si.FunctionName, FileName: si.FilePath}))

				fileId := traceInfo.Files[i]
				if mappingIndex, ok := fileIDtoMapping[fileId]; ok {
					loc.SetMappingIndex(mappingIndex)
				} else {
					locationMappingIndex := int32(len(fileIDtoMapping))
					fileIDtoMapping[fileId] = locationMappingIndex

					mapping := profile.MappingTable().AppendEmpty()
					mapping.SetFilenameStrindex(stringTab.Get(""))
					attrMgr.AppendOptionalString(mapping.AttributeIndices(), "process.executable.build_id.htlhash", fileId.StringNoQuotes())
					loc.SetMappingIndex(locationMappingIndex)
				}
			}
		}

		attrMgr.AppendOptionalString(sample.AttributeIndices(), semconv.ContainerIDKey, traceKey.ContainerID)
		attrMgr.AppendOptionalString(sample.AttributeIndices(), semconv.ThreadNameKey, traceKey.Comm)
		attrMgr.AppendOptionalString(sample.AttributeIndices(), semconv.ProcessExecutableNameKey, traceKey.ProcessName)
		attrMgr.AppendOptionalString(sample.AttributeIndices(), semconv.ProcessExecutablePathKey, traceKey.ExecutablePath)
		attrMgr.AppendOptionalString(sample.AttributeIndices(), semconv.ServiceNameKey, traceKey.ApmServiceName)
		attrMgr.AppendInt(sample.AttributeIndices(), semconv.ProcessPIDKey, traceKey.Pid)

		sample.AttributeIndices().Append(c.ctrl.ExtraSampleAttrs(attrMgr, traceKey.ExtraMeta)...)

		sample.SetLocationsLength(int32(len(traceInfo.FrameTypes)))
		locationIndex += sample.LocationsLength()
	}
	log.Tracef("Reporting OTLP profile with %d samples", profile.Sample().Len())

	// Populate the deduplicated functions into profile.
	funcTable := profile.FunctionTable()
	funcTable.EnsureCapacity(funcTab.Len())
	for _, f := range funcTab.All() {
		empty := funcTable.AppendEmpty()
		empty.SetNameStrindex(stringTab.Get(f.Name))
		empty.SetFilenameStrindex(stringTab.Get(f.FileName))
	}

	for _, v := range stringTab.All() {
		profile.StringTable().Append(v)
	}

	// profile.LocationIndices is not optional, and we only write elements into
	// profile.Location that at least one sample references.
	for i := int32(0); i < int32(profile.LocationTable().Len()); i++ {
		profile.LocationIndices().Append(i)
	}

	profile.SetDuration(endTS - startTS)
	profile.SetStartTime(startTS)
}

func (c *colaSoftReporter) loop(ctx context.Context) {
	var prev = time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}
		if !c.running.Load() {
			c.cache.frames.Purge()
			c.cache.executables.Purge()
			cache := c.cache.events.WLock()
			clear(*cache)
			c.cache.events.WUnlock(&cache)
			prev = time.Now()
			continue
		}
		now := time.Now()
		if c.count.Load() < c.limit.Load() && now.Sub(prev) < c.Interval() {
			continue
		}
		c.count.Swap(0)
		prev = now
		events := c.cache.events.WLock()
		pdata := make(map[uint32]pprofile.Profiles)
		symbolization := c.cache.symbolization.WLock()
		c.ctrl.Symbolization(*symbolization)
		for pid, evts := range *events {
			pp := c.generate(evts, *symbolization)
			if pp.SampleCount() == 0 {
				continue
			}
			pdata[pid.Hash32()] = pp
		}
		*symbolization = make(map[libpf.FrameID]*samples.SourceInfo)
		c.cache.symbolization.WUnlock(&symbolization)
		clear(*events)
		c.cache.events.WUnlock(&events)
		if len(pdata) == 0 {
			continue
		}
		if c.running.Load() {
			c.ctrl.ConsumeProfiles(pdata)
		}
	}
}

func newIndexTable[T comparable]() indexTable[T] {
	it := make(indexTable[T])
	var empty T
	it[empty] = 0
	return it
}

func (i indexTable[T]) Get(v T) int32 {
	if idx, exists := i[v]; exists {
		return idx
	}
	idx := int32(len(i))
	i[v] = idx
	return idx
}

func (i indexTable[T]) Len() int { return len(i) }
func (i indexTable[T]) All() []T {
	r := make([]T, len(i))
	for k, v := range i {
		r[v] = k
	}
	return r
}
