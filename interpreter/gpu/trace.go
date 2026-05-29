package gpu

import (
	"maps"
	"slices"
	"sync"
	"unsafe"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/xsync"
	"go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/support"
	"go.opentelemetry.io/ebpf-profiler/traceutil"
)

type (
	Reporter interface {
		reporter.SymbolReporter
		reporter.TraceReporter
		Demangle(string) string
		ConsumeTimeEvent(timing *support.Timeline)
		ConsumeErrorEvent(evt *support.ErrorEvent)
	}

	traceFixer struct {
		lock             sync.Mutex
		launch           map[uint32]*launchState
		trace            map[uint32]*traceEvent
		maxCorrelationID uint32
	}
	eventTracer struct {
		reporter Reporter
		pids     xsync.RWMutex[map[libpf.PID]*traceFixer]
	}
)

func newEventTracer(reporter Reporter) *eventTracer {
	return &eventTracer{reporter: reporter, pids: xsync.NewRWMutex(make(map[libpf.PID]*traceFixer))}
}

func (e *eventTracer) ReportTrace(trace *libpf.Trace, meta *samples.TraceEventMeta) {
	switch meta.Origin {
	case support.TraceOriginCuda:
		e.reportCudaTrace(trace, meta)
	case support.TraceOriginCudaSynchronize:
		e.reportSynchronizeTrace(trace, meta)
	}
}

func (e *eventTracer) reportCudaTrace(trace *libpf.Trace, meta *samples.TraceEventMeta) {
	idx := slices.Index(trace.FrameTypes, libpf.CUDAKernelFrame)
	if idx == -1 {
		return
	}
	pids := e.pids.WLock()
	if _, ok := (*pids)[meta.PID]; !ok {
		(*pids)[meta.PID] = newTraceFixer()
	}
	fixer := (*pids)[meta.PID]
	e.pids.WUnlock(&pids)
	packed := trace.Linenos[idx]
	correlationID := uint32(packed)
	// FIXME(liushi): CUpti_CallbackId:暂时不需要用到这个字段
	//cbid := int32(packed >> 32)
	input := &traceEvent{cudaFrameIndex: idx, correlationID: correlationID, trace: trace, meta: meta}
	fixer.ReportTrace(e.reporter, input)
}

func (e *eventTracer) reportSynchronizeTrace(trace *libpf.Trace, meta *samples.TraceEventMeta) {
	idx := slices.Index(trace.FrameTypes, libpf.CUDAKernelFrame)
	if idx != -1 {
		if name := syncKindName(trace.Linenos[idx]); name != "" {
			frameID := libpf.NewFrameID(trace.Files[idx], trace.Linenos[idx])
			if !e.reporter.FrameKnown(frameID) {
				e.reporter.FrameMetadata(&reporter.FrameMetadataArgs{
					FrameID:      frameID,
					FunctionName: name,
				})
			}
		}
	}
	if e.reporter.SupportsReportTraceEvent() {
		e.reporter.ReportTraceEvent(trace, meta)
	}
}

// syncKindName maps the synchronize kind enumerated on the .so side back to the
// CUDA driver API function name. An empty string marks an unknown kind.
func syncKindName(kind libpf.AddressOrLineno) string {
	switch uint32(kind) {
	case 100:
		return "cuStreamSynchronize"
	case 101:
		return "cuCtxSynchronize"
	case 102:
		return "cuEventSynchronize"
	case 103:
		return "cuStreamSynchronize_ptsz"
	default:
		return ""
	}
}

func (e *eventTracer) ReportTiming(timing *support.Timeline) {
	if timing.Kind == support.ActivityKindMemcpy || timing.Kind == support.ActivityKindKernel {
		e.reporter.ConsumeTimeEvent(timing)
	}
	if timing.Kind == support.ActivityKindMemcpy {
		return
	}
	pid := libpf.PID(timing.Pid)
	pids := e.pids.WLock()
	if _, ok := (*pids)[pid]; !ok {
		(*pids)[pid] = newTraceFixer()
	}
	fixer := (*pids)[pid]
	e.pids.WUnlock(&pids)
	fixer.ReportTiming(e.reporter, timing)
}

func (e *eventTracer) ReportError(evt *support.ErrorEvent) {
	e.reporter.ConsumeErrorEvent(evt)
}

func (e *eventTracer) Expire(all bool) {
	pids := e.pids.WLock()
	defer e.pids.WUnlock(&pids)
	var limit uint32 = 10000
	if all {
		limit = 0
	}
	maps.DeleteFunc(*pids, func(pid libpf.PID, fixer *traceFixer) bool { return fixer.Expire(limit) })
}

func newTraceFixer() *traceFixer {
	return &traceFixer{launch: make(map[uint32]*launchState), trace: make(map[uint32]*traceEvent)}
}

func (t *traceFixer) Expire(limit uint32) bool {
	t.lock.Lock()
	defer t.lock.Unlock()
	if len(t.launch) >= int(limit) || len(t.trace) >= int(limit) {
		boundary := t.maxCorrelationID - limit/2
		maps.DeleteFunc(t.launch, func(u uint32, _ *launchState) bool { return u <= boundary })
		maps.DeleteFunc(t.trace, func(u uint32, _ *traceEvent) bool { return u <= boundary })
	}
	return len(t.launch) == 0 && len(t.trace) == 0
}

func (t *traceFixer) ReportTrace(rpt Reporter, input *traceEvent) {
	t.lock.Lock()
	defer t.lock.Unlock()
	t.updateMaxCorrelationID(input.correlationID)
	t.trace[input.correlationID] = input
	t.flushReport(rpt, input.correlationID)
}

func (t *traceFixer) ReportTiming(rpt Reporter, timing *support.Timeline) {
	t.lock.Lock()
	defer t.lock.Unlock()
	t.updateMaxCorrelationID(timing.CorrelationId)
	ls := t.launch[timing.CorrelationId]
	if ls == nil {
		ls = new(launchState)
		t.launch[timing.CorrelationId] = ls
	}
	switch timing.Kind {
	case support.ActivityKindHostApi:
		ls.host = timing
	case support.ActivityKindKernel:
		ls.kernels = append(ls.kernels, timing)
	}
	t.flushReport(rpt, timing.CorrelationId)
}

// flushReport reports pending events for a correlationId once the CPU trace and
// every switch-enabled piece is present: host timing if the host-api switch is
// on, kernel timing if the kernel switch is on. The switch state is read at
// report time, so closing a switch mid-flight simply drops its data, and the
// two sides are decoupled (report may see host==nil or kernel==nil).
func (t *traceFixer) flushReport(rpt Reporter, id uint32) {
	ls := t.launch[id]
	if ls == nil {
		return
	}
	te, cached := t.trace[id]
	if !cached {
		return
	}

	hostOn := GPU.EnableHostAPI()
	kernelOn := GPU.EnableKernel()
	if !hostOn && !kernelOn {
		return
	}

	var host *support.Timeline
	if hostOn {
		if ls.host == nil {
			return
		}
		host = ls.host
	}

	if kernelOn {
		for _, kernel := range ls.kernels {
			t.report(rpt, te, host, kernel)
		}
		ls.kernels = ls.kernels[:0]
		return
	}

	// kernel switch off: host-only report (ai-launch) without kernel data.
	t.report(rpt, te, host, nil)
}

func (t *traceFixer) report(rpt Reporter, input *traceEvent, host, kernel *support.Timeline) {
	trace := input.trace
	meta := input.meta
	metaValue := &samples.MetaValueAI{}

	// The two switches are decoupled: host==nil for kernel-only (ai-execution),
	// kernel==nil for host-only (ai-launch). CorrelationID comes from whichever
	// piece is present (both carry the same value when both switches are on).
	if host != nil {
		metaValue.CorrelationID = host.CorrelationId
		metaValue.Host.End = int64(host.End)
		metaValue.Host.Duration = int64(host.End) - int64(host.Start)
	}
	if kernel != nil {
		metaValue.Stream = kernel.StreamId
		metaValue.Device = kernel.DeviceId
		metaValue.Graph = kernel.GraphId
		metaValue.CorrelationID = kernel.CorrelationId
		metaValue.GraphNodeID = kernel.GraphNodeId
		metaValue.Kernel.End = int64(kernel.End)
		metaValue.Kernel.Duration = int64(kernel.End) - int64(kernel.Start)
	}

	if metaValue.Graph != 0 {
		trace = &libpf.Trace{
			Files:              slices.Clone(input.trace.Files),
			Linenos:            slices.Clone(input.trace.Linenos),
			FrameTypes:         slices.Clone(input.trace.FrameTypes),
			MappingStart:       slices.Clone(input.trace.MappingStart),
			MappingEnd:         slices.Clone(input.trace.MappingEnd),
			MappingFileOffsets: slices.Clone(input.trace.MappingFileOffsets),
			Hash:               input.trace.Hash,
		}
		metaCpy := *meta
		meta = &metaCpy
	}
	meta.Value = metaValue

	if kernel != nil {
		// FileID 组合 Stream 与 GraphNodeId：graph 场景靠 graphNodeId 区分同 launch 的不同 kernel，非 graph 场景 graphNodeId=0 退化为原行为。
		// 只有 kernel 侧开时才用 kernel 名象征化关联帧；host-only 时没有 kernel 名，直接保留原始 launch 调用栈。
		fileid := libpf.NewFileID(uint64(metaValue.Stream), metaValue.GraphNodeID)
		trace.Files[input.cudaFrameIndex] = fileid
		frameId := libpf.NewFrameID(fileid, trace.Linenos[input.cudaFrameIndex])
		if !rpt.FrameKnown(frameId) {
			idx := slices.Index(kernel.Name[:], 0)
			if idx == -1 {
				idx = len(kernel.Name[:])
			}
			funcName := rpt.Demangle(unsafe.String((*byte)(unsafe.Pointer(&kernel.Name[0])), idx))
			arg := &reporter.FrameMetadataArgs{
				FrameID:      frameId,
				FunctionName: funcName,
			}
			rpt.FrameMetadata(arg)
		}
	}
	if rpt.SupportsReportTraceEvent() {
		trace.Hash = traceutil.HashTrace(trace)
		rpt.ReportTraceEvent(trace, meta)
	}
}

func (t *traceFixer) updateMaxCorrelationID(id uint32) {
	if id > t.maxCorrelationID || t.maxCorrelationID-id > 1<<31 { // 需要考虑内存溢出的情况
		t.maxCorrelationID = id
	}
}
