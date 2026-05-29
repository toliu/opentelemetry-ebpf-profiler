package main

import (
	"cmp"
	"context"
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unsafe"

	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pprofile"
	"go.opentelemetry.io/collector/pdata/pprofile/pprofileotlp"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/ebpf-profiler/colasoft"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/xsync"
	"go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/support"
)

type (
	// FlameNode 表示火焰图树中的一个节点。
	FlameNode struct {
		Name     string       `json:"name"`
		Value    int64        `json:"value"`
		Children []*FlameNode `json:"children,omitempty"`
	}
	State struct {
		Interval     string   `json:"interval"`
		CPUOnFreq    int64    `json:"cpu_on_frequency"`
		CPUOffThresh int64    `json:"cpu_off_threshold"`
		MemoryBlock  uint64   `json:"memory_block"`
		PIDs         []uint32 `json:"pids"`
		GPUHostAPI   bool     `json:"gpu_host_api"`
		GPUKernel    bool     `json:"gpu_kernel"`
	}
	// timelineItem 是 /api/timeline 返回的单条记录。
	timelineItem struct {
		PID           uint32 `json:"pid"`
		TID           uint32 `json:"tid"`
		Kind          uint64 `json:"kind"`
		Start         string `json:"start"`
		End           string `json:"end"`
		CorrelationID uint32 `json:"correlation_id"`
		DeviceID      uint32 `json:"device_id"`
		StreamID      uint32 `json:"stream_id"`
		Bytes         string `json:"bytes"`
		CopyKind      uint16 `json:"copy_kind"`
		Sync          uint16 `json:"sync"`
		GraphID       uint32 `json:"graph_id"`
		GraphNodeID   string `json:"graph_node_id"`
		Name          string `json:"name"`
	}
	controller struct {
		mux      *http.ServeMux
		state    xsync.RWMutex[State]
		profiles xsync.RWMutex[map[uint32]pprofile.ProfilesSlice]
		timeline xsync.RWMutex[[]*support.Timeline]
		errors   xsync.RWMutex[[]*support.ErrorEvent]
		output   struct {
			profiles, timelines, errors string
			last                        struct {
				timelines uint64
				errors    struct {
					when time.Time
					evt  *support.ErrorEvent
				}
			}
		}
	}
)

//go:embed index.html
var indexHTML string

var _ colasoft.Controller = (*controller)(nil)
var _ http.Handler = (*controller)(nil)

func (c *controller) Demangle(n string) string                                         { return n }
func (c *controller) CollectExtraSampleMeta(*libpf.Trace, *samples.TraceEventMeta) any { return nil }
func (c *controller) ExtraSampleAttrs(*samples.AttrTableManager, any) []int32          { return nil }
func (c *controller) ExecutableKnown(libpf.FileID) bool                                { return true }
func (c *controller) ExecutableMetadata(*reporter.ExecutableMetadataArgs)              {}
func (c *controller) TimeOffset() time.Duration                                        { return 0 }
func (c *controller) Symbolization(lookup map[libpf.FrameID]*samples.SourceInfo) {
	for key := range lookup {
		lookup[key] = &samples.SourceInfo{FunctionName: fmt.Sprintf("func.0x%x", key.AddressOrLine()), FilePath: fmt.Sprintf("filename.%s", key.FileID().ToUUIDString())}
	}
}
func (c *controller) GetProfilingStat(_ *colasoft.State) (expect *colasoft.State) {
	state := c.state.RLock()
	defer c.state.RUnlock(&state)
	pid := make(colasoft.PIDState)
	for _, p := range state.PIDs {
		pid[p] = true
	}
	interval, _ := time.ParseDuration(state.Interval)
	expect = colasoft.NewState(true, interval)
	disabled := map[libpf.InterpreterType]bool{
		libpf.Python: true,
		libpf.Native: true,
	}
	return expect.
		WithCPUState(state.CPUOnFreq, state.CPUOffThresh, pid).
		WithMemoryState(state.MemoryBlock, disabled, pid).
		WithGPUState(state.GPUHostAPI, state.GPUKernel)
}

func (c *controller) ConsumeProfiles(tds map[uint32]pprofile.Profiles) {
	profs := c.profiles.WLock()
	defer c.profiles.WUnlock(&profs)
	clear(*profs)
	root := filepath.Join(c.output.profiles, time.Now().Format(time.RFC3339Nano))
	if err := os.MkdirAll(root, 0777); err != nil {
		log.Errorf("failed to mkdir: %s", err)
		return
	}
	log.Infof("write profile to %s", root)
	for pid, data := range tds {
		rp := data.ResourceProfiles()
		if rp.Len() == 0 {
			continue
		}
		sp := rp.At(0).ScopeProfiles()
		if sp.Len() == 0 {
			continue
		}
		profiles := sp.At(0).Profiles()
		var multiple []pprofile.Profile
		profiles.RemoveIf(func(profile pprofile.Profile) bool {
			if stypeLen := profile.SampleType().Len(); stypeLen != 1 {
				multiple = append(multiple, profile)
				return true
			}
			return false
		})
		for _, base := range multiple {
			stype := base.SampleType()
			for i := range stype.Len() {
				baseVtype := stype.At(i)
				extra := profiles.AppendEmpty()
				base.CopyTo(extra)
				extra.SampleType().RemoveIf(func(vtype pprofile.ValueType) bool {
					return baseVtype.TypeStrindex() != vtype.TypeStrindex() || baseVtype.UnitStrindex() != vtype.UnitStrindex()
				})
				extra.Sample().RemoveIf(func(sample pprofile.Sample) bool {
					values := sample.Value()
					values.SetAt(0, values.At(i))
					return false
				})
			}
		}
		(*profs)[pid] = profiles
		export := pprofileotlp.NewExportRequestFromProfiles(data)
		if protoData, err := export.MarshalProto(); err == nil {
			_ = os.WriteFile(filepath.Join(root, fmt.Sprintf("%d.profile", pid)), protoData, os.ModePerm)
		}
	}
}

func (c *controller) ConsumeTimeEvent(timeline *support.Timeline) {
	ts := c.timeline.WLock()
	defer c.timeline.WUnlock(&ts)
	limit := timeline.End - uint64(time.Minute.Nanoseconds())
	*ts = append(*ts, timeline)
	c.output.last.timelines = cmp.Or(c.output.last.timelines, timeline.End)
	if timeline.End-c.output.last.timelines >= uint64(time.Second.Nanoseconds())*30 {
		idx := slices.IndexFunc(*ts, func(timing *support.Timeline) bool { return timing.End == c.output.last.timelines })
		if idx == -1 {
			idx = 0
		}
		if err := c.writeTimelines((*ts)[idx:]); err != nil {
			log.Errorf("failed to write timelines: %s", err)
		}
		c.output.last.timelines = timeline.End
	}
	*ts = slices.DeleteFunc(*ts, func(timing *support.Timeline) bool { return timing.End < limit })
}

func (c *controller) writeTimelines(events []*support.Timeline) error {
	var data = struct {
		Pid       []uint32 `json:"pid"`
		ProcessId []uint64 `json:"process_id"`
		ThreadID  []uint32 `json:"thread_id"`
		DeviceID  []uint32 `json:"device_id"`
		Stream    []uint32 `json:"stream"`
		Kind      []uint32 `json:"kind"`
		Start     []uint64 `json:"start"`
		Duration  []uint64 `json:"duration"`
		Extra     []string `json:"extra"`
	}{}
	for _, event := range events {
		data.Pid = append(data.Pid, event.Pid)
		data.ProcessId = append(data.ProcessId, uint64(event.Pid))
		data.ThreadID = append(data.ThreadID, event.Tid)
		data.DeviceID = append(data.DeviceID, event.DeviceId)
		data.Stream = append(data.Stream, event.StreamId)
		data.Start = append(data.Start, event.Start)
		data.Duration = append(data.Duration, event.End-event.Start)
		var extra string
		switch event.Kind {
		case support.ActivityKindKernel:
			data.Kind = append(data.Kind, 1)
		case support.ActivityKindMemcpy:
			data.Kind = append(data.Kind, uint32(event.CopyKind))
			extra = fmt.Sprintf("%d,%d", event.Bytes, event.Sync)
		default:
			data.Kind = append(data.Kind, 0) // ?
		}
		data.Extra = append(data.Extra, extra)
	}
	file, err := os.Create(filepath.Join(c.output.timelines, time.Now().Format(time.TimeOnly)))
	if err != nil {
		return err
	}
	log.Infof("write timeline to %s", file.Name())
	defer file.Close()
	enc := json.NewEncoder(file)
	enc.SetIndent("", "  ")
	return enc.Encode(data)
}

func (c *controller) ConsumeErrorEvent(evt *support.ErrorEvent) {
	es := c.errors.WLock()
	defer c.errors.WUnlock(&es)
	*es = append(*es, evt)
	if c.output.last.errors.when.IsZero() {
		c.output.last.errors.when = time.Now()
		c.output.last.errors.evt = evt
	}
	if time.Since(c.output.last.errors.when) > time.Second*10 {
		idx := slices.Index(*es, c.output.last.errors.evt) + 1
		if idx < len(*es) {
			if err := c.writeErrorEvent((*es)[idx:]); err != nil {
				log.Errorf("failed to write event: %s", err)
			}
		}
		c.output.last.errors.when = time.Now()
		c.output.last.errors.evt = evt
	}
	if len(*es) > 10000 {
		*es = (*es)[len(*es)-10000:]
	}
}

func (c *controller) writeErrorEvent(errors []*support.ErrorEvent) error {
	var data = struct {
		Pid       []uint32 `json:"pid"`
		ProcessID []uint64 `json:"process_id"`
		ThreadID  []uint32 `json:"thread_id"`
		API       []string `json:"api"`
		Errors    []string `json:"errors"`
	}{}
	for _, evt := range errors {
		comLen := slices.Index(evt.Component[:], 0)
		if comLen == -1 {
			comLen = len(evt.Component)
		}
		msgLen := slices.Index(evt.Message[:], 0)
		if msgLen == -1 {
			msgLen = len(evt.Message)
		}
		data.Pid = append(data.Pid, evt.Pid)
		data.ProcessID = append(data.ProcessID, uint64(evt.Pid))
		data.ThreadID = append(data.ThreadID, evt.Tid)
		data.API = append(data.API, unsafe.String((*byte)(unsafe.Pointer(&evt.Component[0])), comLen))
		data.Errors = append(data.Errors, unsafe.String((*byte)(unsafe.Pointer(&evt.Message[0])), msgLen))
	}

	file, err := os.Create(filepath.Join(c.output.errors, time.Now().Format(time.TimeOnly)))
	if err != nil {
		return err
	}
	log.Infof("write error event to %s", file.Name())
	defer file.Close()
	enc := json.NewEncoder(file)
	enc.SetIndent("", "  ")
	return enc.Encode(data)
}

func (c *controller) ServeHTTP(rw http.ResponseWriter, req *http.Request) { c.mux.ServeHTTP(rw, req) }

func (c *controller) httpIndex(rw http.ResponseWriter, _ *http.Request) {
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(rw, indexHTML)
}
func (c *controller) httpGetState(rw http.ResponseWriter, _ *http.Request) {
	state := c.state.RLock()
	defer c.state.RUnlock(&state)
	c.httpResponse(rw, state)
}
func (c *controller) httpPostState(rw http.ResponseWriter, r *http.Request) {
	var req State
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(rw, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	state := c.state.WLock()
	defer c.state.WUnlock(&state)
	if _, err := time.ParseDuration(req.Interval); err != nil {
		http.Error(rw, "invalid interval: "+err.Error(), http.StatusBadRequest)
		return
	}
	*state = req
	log.Infof("状态已更新: cpu_freq=%d offcpu_thresh=%d mem_block=%d pids=%v gpu_host_api=%t gpu_kernel=%t", req.CPUOnFreq, req.CPUOffThresh, req.MemoryBlock, req.PIDs, req.GPUHostAPI, req.GPUKernel)
	c.httpResponse(rw, state)
}
func (c *controller) httpGetTimeline(rw http.ResponseWriter, req *http.Request) {
	ts := c.timeline.RLock()
	defer c.timeline.RUnlock(&ts)

	q := req.URL.Query()
	filterPID, _ := strconv.Atoi(q.Get("pid"))
	filterKind, _ := strconv.Atoi(q.Get("kind"))
	filterName := q.Get("name")

	items := make([]timelineItem, 0, len(*ts))
	for _, t := range *ts {
		if filterPID > 0 && t.Pid != uint32(filterPID) {
			continue
		}
		if filterKind > 0 && t.Kind != uint64(filterKind) {
			continue
		}
		nameLength := slices.Index(t.Name[:], 0)
		if nameLength == -1 {
			nameLength = len(t.Name)
		}
		name := unsafe.String((*byte)(unsafe.Pointer(&t.Name[0])), nameLength)
		if filterName != "" && !strings.Contains(name, filterName) {
			continue
		}
		items = append(items, timelineItem{
			PID:           t.Pid,
			TID:           t.Tid,
			Kind:          t.Kind,
			Start:         strconv.FormatUint(t.Start, 10),
			End:           strconv.FormatUint(t.End, 10),
			CorrelationID: t.CorrelationId,
			DeviceID:      t.DeviceId,
			StreamID:      t.StreamId,
			Bytes:         strconv.FormatUint(t.Bytes, 10),
			CopyKind:      t.CopyKind,
			Sync:          t.Sync,
			GraphID:       t.GraphId,
			GraphNodeID:   strconv.FormatUint(t.GraphNodeId, 10),
			Name:          name,
		})
	}
	c.httpResponse(rw, items)
}

func (c *controller) httpGetErrors(rw http.ResponseWriter, _ *http.Request) {
	es := c.errors.RLock()
	defer c.errors.RUnlock(&es)
	type errorItem struct {
		PID       uint32 `json:"pid"`
		TID       uint32 `json:"tid"`
		Code      int32  `json:"code"`
		Message   string `json:"message"`
		Component string `json:"component"`
	}
	items := make([]errorItem, 0, len(*es))
	for _, e := range *es {
		msgLen := slices.Index(e.Message[:], 0)
		if msgLen == -1 {
			msgLen = len(e.Message)
		}
		compLen := slices.Index(e.Component[:], 0)
		if compLen == -1 {
			compLen = len(e.Component)
		}
		items = append(items, errorItem{
			PID:       e.Pid,
			TID:       e.Tid,
			Code:      e.Code,
			Message:   unsafe.String((*byte)(unsafe.Pointer(&e.Message[0])), msgLen),
			Component: unsafe.String((*byte)(unsafe.Pointer(&e.Component[0])), compLen),
		})
	}
	c.httpResponse(rw, items)
}

func (c *controller) httpGetProfiles(rw http.ResponseWriter, _ *http.Request) {
	profs := c.profiles.RLock()
	defer c.profiles.RUnlock(&profs)
	resp := make([]map[string]any, 0)
	for pid, prof := range *profs {
		infos := make([]map[string]string, 0)
		var idx int
		prof.RemoveIf(func(profile pprofile.Profile) bool {
			stype := "unknown"
			st := profile.SampleType().At(0)
			stable := profile.StringTable()
			typeIdx, unitIdx := int(st.TypeStrindex()), int(st.UnitStrindex())
			stype = stable.At(typeIdx) + "-" + stable.At(unitIdx)
			infos = append(infos, map[string]string{"index": fmt.Sprint(idx), "sample_type": stype})
			idx++
			return false
		})
		resp = append(resp, map[string]any{"pid": pid, "profiles": infos})
	}
	c.httpResponse(rw, resp)
}
func (c *controller) httpGetFlamegraph(rw http.ResponseWriter, req *http.Request) {
	pid, _ := strconv.Atoi(req.URL.Query().Get("pid"))
	typ, _ := strconv.Atoi(req.URL.Query().Get("type"))
	if pid == 0 {
		msg := fmt.Sprintf("invalid parameter: pid(%s), type(%s)",
			req.URL.Query().Get("pid"),
			req.URL.Query().Get("type"),
		)
		http.Error(rw, msg, http.StatusBadRequest)
		return
	}
	profs := c.profiles.RLock()
	defer c.profiles.RUnlock(&profs)
	profSlice := (*profs)[uint32(pid)]
	if profSlice.Len() <= typ {
		http.Error(rw, "profile index out of range", http.StatusBadRequest)
		return
	}

	tree := NewFlameTree(profSlice.At(typ))
	c.httpResponse(rw, tree)
}
func (c *controller) httpResponse(rw http.ResponseWriter, data any) {
	rw.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(rw).Encode(data)
}

func (c *controller) setupHttpMux() {
	c.mux.HandleFunc("GET /", c.httpIndex)
	c.mux.HandleFunc("GET /api/state", c.httpGetState)
	c.mux.HandleFunc("POST /api/state", c.httpPostState)
	c.mux.HandleFunc("GET /api/profiles", c.httpGetProfiles)
	c.mux.HandleFunc("GET /api/flamegraph", c.httpGetFlamegraph)
	c.mux.HandleFunc("GET /api/timeline", c.httpGetTimeline)
	c.mux.HandleFunc("GET /api/errors", c.httpGetErrors)
}

func newController() *controller {
	defaultState := State{
		Interval:     "5s",
		CPUOnFreq:    19,
		CPUOffThresh: 99,
		MemoryBlock:  128,
		PIDs:         []uint32{uint32(os.Getpid())},
		GPUHostAPI:   true,
		GPUKernel:    true,
	}
	ctrl := &controller{
		mux:      http.NewServeMux(),
		state:    xsync.NewRWMutex(defaultState),
		profiles: xsync.NewRWMutex(make(map[uint32]pprofile.ProfilesSlice)),
		timeline: xsync.NewRWMutex(make([]*support.Timeline, 0)),
		errors:   xsync.NewRWMutex(make([]*support.ErrorEvent, 0)),
	}
	if output, err := os.MkdirTemp("", "otlp-profile-*"); err != nil {
		log.Fatal(err)
	} else {
		subdirs := map[string]*string{
			`profiles`:  &ctrl.output.profiles,
			`timelines`: &ctrl.output.timelines,
			`errors`:    &ctrl.output.errors,
		}
		for name, root := range subdirs {
			subdir := filepath.Join(output, name)
			if err = os.MkdirAll(subdir, os.ModePerm); err != nil {
				log.Fatal(err)
			}
			*root = subdir
			log.Infof("set %s output to: %s", name, subdir)
		}
	}
	ctrl.setupHttpMux()
	return ctrl
}

func NewFlameTree(profile pprofile.Profile) *FlameNode {
	root := &FlameNode{Name: "all", Value: 0}
	if profile.Sample().Len() == 0 {
		return root
	}

	totalSamples := profile.Sample().Len()

	strTable := profile.StringTable()
	funcTable := profile.FunctionTable()
	locTable := profile.LocationTable()
	mapTable := profile.MappingTable()

	for si := 0; si < totalSamples; si++ {
		sample := profile.Sample().At(si)
		value := int64(0)
		if sample.Value().Len() > 0 {
			value = sample.Value().At(0)
		}
		if value == 0 {
			value = 1
		}

		startIdx := sample.LocationsStartIndex()
		length := sample.LocationsLength()
		if length == 0 {
			continue
		}

		// 从根帧（栈底）向叶帧（栈顶）遍历
		current := root
		current.Value += value
		endIdx := startIdx + length
		for li := endIdx - 1; li >= startIdx; li-- {
			loc := locTable.At(int(li))
			name := resolveFuncName(loc, strTable, funcTable, mapTable)
			child := current.findOrCreateChild(name)
			child.Value += value
			current = child
		}
	}

	// 按 value 降序排列子节点
	sortChildren(root)
	return root
}

// findOrCreateChild 查找或创建子节点。
func (n *FlameNode) findOrCreateChild(name string) *FlameNode {
	for _, child := range n.Children {
		if child.Name == name {
			return child
		}
	}
	child := &FlameNode{Name: name}
	n.Children = append(n.Children, child)
	return child
}

// sortChildren 递归按 value 降序排列所有子节点。
func sortChildren(node *FlameNode) {
	if len(node.Children) == 0 {
		return
	}
	sort.Slice(node.Children, func(i, j int) bool {
		return node.Children[i].Value > node.Children[j].Value
	})
	for _, child := range node.Children {
		sortChildren(child)
	}
}

// resolveFuncName 从 location 中解析函数名。
func resolveFuncName(loc pprofile.Location, strTable pcommon.StringSlice, funcTable pprofile.FunctionSlice, mapTable pprofile.MappingSlice) string {
	// 优先从 Line -> Function 获取函数名
	if loc.Line().Len() > 0 {
		line := loc.Line().At(0)
		fnIdx := line.FunctionIndex()
		if fnIdx >= 0 && int(fnIdx) < funcTable.Len() {
			fn := funcTable.At(int(fnIdx))
			if nameIdx := int(fn.NameStrindex()); nameIdx < strTable.Len() {
				return strTable.At(nameIdx)
			}
		}
	}

	// 回退：使用 mapping 名称 + 地址
	addr := loc.Address()
	mapIdx := loc.MappingIndex()
	if mapIdx >= 0 && int(mapIdx) < mapTable.Len() {
		mapping := mapTable.At(int(mapIdx))
		filename := "unknown"
		if fnIdx := int(mapping.FilenameStrindex()); fnIdx < strTable.Len() {
			filename = strTable.At(fnIdx)
			if idx := strings.LastIndexByte(filename, '/'); idx >= 0 {
				filename = filename[idx+1:]
			}
		}
		if filename == "" {
			filename = "unknown"
		}
		return fmt.Sprintf("%s+0x%x", filename, addr)
	}

	return fmt.Sprintf("0x%x", addr)
}

func main() {
	addr := flag.String("addr", ":9090", "HTTP 服务监听地址")
	flag.Parse()

	ctx, cancel := signal.NotifyContext(context.Background(), unix.SIGINT, unix.SIGTERM, unix.SIGABRT)
	defer cancel()

	ctrl := newController()
	colasoft.Setup(ctx, ctrl)

	srv := &http.Server{
		Addr:         *addr,
		Handler:      ctrl,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		log.Infof("Web 服务启动: http://%s", *addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Errorf("HTTP 服务错误: %v", err)
		}
	}()

	<-ctx.Done()
	log.Info("正在关闭...")
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	srv.Shutdown(shutdownCtx)
}
