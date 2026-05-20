package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pprofile"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/ebpf-profiler/colasoft"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
)

type (
	// FlameNode 表示火焰图树中的一个节点。
	FlameNode struct {
		Name     string       `json:"name"`
		Value    int64        `json:"value"`
		Children []*FlameNode `json:"children,omitempty"`
	}
	// profileEntry 存储一个解析后的 profile 及其类型信息。
	profileEntry struct {
		SampleType string           `json:"sample_type"`
		Profile    pprofile.Profile `json:"-"`
	}
	// cachedEntry 存储一个 PID 的所有 profiles。
	cachedEntry struct {
		PID       uint32
		Profiles  []profileEntry
		Timestamp time.Time
	}
	// profileCache 线程安全的 profile 缓存。
	profileCache struct {
		mu      sync.RWMutex
		entries map[uint32]cachedEntry
	}

	// webController 实现 colasoft.Controller 接口。
	webController struct {
		state atomic.Pointer[colasoft.State]
		cache *profileCache
	}
)

var _ colasoft.Controller = (*webController)(nil)

func newProfileCache() *profileCache {
	return &profileCache{entries: make(map[uint32]cachedEntry)}
}

func (pc *profileCache) store(pidHash uint32, profiles []profileEntry) {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	pc.entries[pidHash] = cachedEntry{PID: pidHash, Profiles: profiles, Timestamp: time.Now()}
}

func (pc *profileCache) list() []cachedEntry {
	pc.mu.RLock()
	defer pc.mu.RUnlock()
	result := make([]cachedEntry, 0, len(pc.entries))
	for _, e := range pc.entries {
		result = append(result, e)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].PID < result[j].PID })
	return result
}

func (pc *profileCache) get(pidHash uint32) (cachedEntry, bool) {
	pc.mu.RLock()
	defer pc.mu.RUnlock()
	e, ok := pc.entries[pidHash]
	return e, ok
}

func (c *webController) TimeOffset() time.Duration { return 0 }

func (c *webController) Symbolization(lookup map[libpf.FrameID]*samples.SourceInfo) {
	for key := range lookup {
		lookup[key] = &samples.SourceInfo{
			FunctionName: fmt.Sprintf("func.0x%x", key.AddressOrLine()),
			FilePath:     fmt.Sprintf("file.%s", key.FileID().ToUUIDString()),
		}
	}
}
func (c *webController) ExecutableKnown(libpf.FileID) bool                   { return true }
func (c *webController) ExecutableMetadata(*reporter.ExecutableMetadataArgs) {}

func (c *webController) State() colasoft.State { return *c.state.Load() }

func (c *webController) ConsumeProfiles(tds map[uint32]pprofile.Profiles) {
	for pidHash, profs := range tds {
		entries := extractProfiles(profs)
		if len(entries) > 0 {
			c.cache.store(pidHash, entries)
		}
	}
}

func (c *webController) CollectExtraSampleMeta(*libpf.Trace, *samples.TraceEventMeta) any { return nil }
func (c *webController) ExtraSampleAttrs(*samples.AttrTableManager, any) []int32          { return nil }

// extractProfiles 从 pprofile.Profiles 中提取所有 profile。
func extractProfiles(profs pprofile.Profiles) []profileEntry {
	var entries []profileEntry
	for i := 0; i < profs.ResourceProfiles().Len(); i++ {
		rp := profs.ResourceProfiles().At(i)
		for j := 0; j < rp.ScopeProfiles().Len(); j++ {
			sp := rp.ScopeProfiles().At(j)
			for k := 0; k < sp.Profiles().Len(); k++ {
				profile := sp.Profiles().At(k)
				stype := "unknown"
				if profile.SampleType().Len() > 0 {
					st := profile.SampleType().At(0)
					stable := profile.StringTable()
					typeIdx, unitIdx := int(st.TypeStrindex()), int(st.UnitStrindex())
					if typeIdx < stable.Len() && unitIdx < stable.Len() {
						stype = stable.At(typeIdx) + "-" + stable.At(unitIdx)
					}
				}
				entries = append(entries, profileEntry{
					SampleType: stype,
					Profile:    profile,
				})
			}
		}
	}
	return entries
}

// buildFlameTree 将 pprofile.Profile 转换为火焰图树。
func buildFlameTree(profile pprofile.Profile, maxSamples int) *FlameNode {
	root := &FlameNode{Name: "all", Value: 0}
	if profile.Sample().Len() == 0 {
		return root
	}

	totalSamples := profile.Sample().Len()
	if maxSamples > 0 && totalSamples > maxSamples {
		totalSamples = maxSamples
	}

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

// --- HTTP handlers ---
func (c *webController) handleIndex(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := indexTmpl.Execute(w, nil); err != nil {
		log.Errorf("模板渲染失败: %v", err)
	}
}

type (
	// apiProfileItem 是 /api/profiles 返回的条目。
	apiProfileItem struct {
		PID      uint32           `json:"pid"`
		Profiles []apiProfileInfo `json:"profiles"`
	}
	apiProfileInfo struct {
		Index      int    `json:"index"`
		SampleType string `json:"sample_type"`
	}
)

func (c *webController) handleProfiles(w http.ResponseWriter, _ *http.Request) {
	entries := c.cache.list()
	result := make([]apiProfileItem, 0, len(entries))
	for _, e := range entries {
		item := apiProfileItem{PID: e.PID}
		for idx, pe := range e.Profiles {
			item.Profiles = append(item.Profiles, apiProfileInfo{
				Index:      idx,
				SampleType: pe.SampleType,
			})
		}
		result = append(result, item)
	}
	writeJSON(w, result)
}

func (c *webController) handleFlamegraph(w http.ResponseWriter, r *http.Request) {
	pidStr := r.URL.Query().Get("pid")
	typeStr := r.URL.Query().Get("type")
	maxStr := r.URL.Query().Get("maxSamples")

	if pidStr == "" || typeStr == "" {
		http.Error(w, "missing pid or type parameter", http.StatusBadRequest)
		return
	}

	pidHash, err := strconv.ParseUint(pidStr, 10, 32)
	if err != nil {
		http.Error(w, "invalid pid", http.StatusBadRequest)
		return
	}

	profileIdx, err := strconv.Atoi(typeStr)
	if err != nil {
		http.Error(w, "invalid type", http.StatusBadRequest)
		return
	}

	maxSamples := 10000
	if maxStr != "" {
		if n, err := strconv.Atoi(maxStr); err == nil && n > 0 {
			maxSamples = n
		}
	}

	entry, ok := c.cache.get(uint32(pidHash))
	if !ok {
		http.Error(w, "profile not found", http.StatusNotFound)
		return
	}

	if profileIdx < 0 || profileIdx >= len(entry.Profiles) {
		http.Error(w, "profile index out of range", http.StatusBadRequest)
		return
	}

	tree := buildFlameTree(entry.Profiles[profileIdx].Profile, maxSamples)
	writeJSON(w, tree)
}

func writeJSON(w http.ResponseWriter, v any) {
	data, err := json.Marshal(v)
	if err != nil {
		log.Errorf("JSON 序列化失败: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

// --- State API ---

type (
	// apiState 是 profiling 状态的 JSON 表示。
	apiState struct {
		Overload     bool     `json:"overload"`
		Interval     string   `json:"interval"`
		CPUOnFreq    int64    `json:"cpu_on_frequency"`
		CPUOffThresh int64    `json:"cpu_off_threshold"`
		CPUPIDs      []uint32 `json:"cpu_pids"`
		MemoryBlock  uint64   `json:"memory_block"`
		MemoryPIDs   []uint32 `json:"memory_pids"`
	}
)

func stateToAPI(s colasoft.State) apiState {
	cpuPIDs := make([]uint32, 0, len(s.CPU.PIDs))
	for pid := range s.CPU.PIDs {
		cpuPIDs = append(cpuPIDs, pid)
	}
	sort.Slice(cpuPIDs, func(i, j int) bool { return cpuPIDs[i] < cpuPIDs[j] })

	memPIDs := make([]uint32, 0, len(s.Memory.PIDs))
	for pid := range s.Memory.PIDs {
		memPIDs = append(memPIDs, pid)
	}
	sort.Slice(memPIDs, func(i, j int) bool { return memPIDs[i] < memPIDs[j] })

	return apiState{
		Overload:     s.Overload,
		Interval:     s.Interval.String(),
		CPUOnFreq:    s.CPU.OnFrequency,
		CPUOffThresh: s.CPU.OffThreshold,
		CPUPIDs:      cpuPIDs,
		MemoryBlock:  s.Memory.Block,
		MemoryPIDs:   memPIDs,
	}
}

func (c *webController) handleGetState(w http.ResponseWriter, _ *http.Request) {
	s := c.State()
	writeJSON(w, stateToAPI(s))
}

func (c *webController) handleUpdateState(w http.ResponseWriter, r *http.Request) {
	var update apiState
	if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	old := *c.state.Load()
	next := old

	if update.Interval != "" {
		if d, err := time.ParseDuration(update.Interval); err == nil {
			next.Interval = d
		}
	}
	if update.CPUOnFreq != 0 || update.CPUOffThresh != 0 {
		next.CPU.OnFrequency = update.CPUOnFreq
		next.CPU.OffThreshold = update.CPUOffThresh
	}
	if len(update.CPUPIDs) > 0 {
		pids := make(colasoft.PIDState)
		for _, pid := range update.CPUPIDs {
			pids[pid] = true
		}
		pids[uint32(os.Getpid())] = true
		next.CPU.PIDs = pids
	}
	if update.MemoryBlock != 0 {
		next.Memory.Block = update.MemoryBlock
	}
	if len(update.MemoryPIDs) > 0 {
		pids := make(colasoft.PIDState)
		for _, pid := range update.MemoryPIDs {
			pids[pid] = true
		}
		pids[uint32(os.Getpid())] = true
		next.Memory.PIDs = pids
	}
	next.Overload = update.Overload

	c.state.Store(&next)
	log.Infof("状态已更新: cpu_freq=%d offcpu_thresh=%d mem_block=%d cpu_pids=%v mem_pids=%v",
		next.CPU.OnFrequency, next.CPU.OffThreshold, next.Memory.Block,
		update.CPUPIDs, update.MemoryPIDs)

	writeJSON(w, stateToAPI(next))
}

// --- HTML 模板 ---

var indexTmpl = template.Must(template.New("index").Parse(indexHTML))

const indexHTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>eBPF Profiler - Flame Graph</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  background: #1a1a2e; color: #e0e0e0; font-family: -apple-system, BlinkMacSystemFont,
    "Segoe UI", Roboto, sans-serif; padding: 20px; min-height: 100vh;
}
.header { margin-bottom: 16px; }
.header h1 { font-size: 22px; font-weight: 600; color: #e94560; }
.header p { font-size: 13px; color: #888; margin-top: 4px; }
.controls { display: flex; align-items: center; gap: 10px; margin-bottom: 12px; flex-wrap: wrap; }
.controls label { font-size: 13px; color: #aaa; }
.controls select, .controls button {
  padding: 6px 12px; border: 1px solid #444; border-radius: 4px;
  background: #16213e; color: #e0e0e0; font-size: 13px; cursor: pointer;
}
.controls button:hover { background: #1f3460; }
.controls select:focus, .controls button:focus { outline: none; border-color: #e94560; }
.breadcrumb { margin-bottom: 8px; font-size: 13px; min-height: 20px; }
.breadcrumb-item { color: #4ea6d2; cursor: pointer; }
.breadcrumb-item:hover { text-decoration: underline; }
.breadcrumb-sep { color: #666; margin: 0 4px; }
.canvas-wrap {
  background: #0f0f23; border: 1px solid #333; border-radius: 4px;
  overflow-x: auto; position: relative;
}
#flamegraph { display: block; cursor: pointer; }
.tooltip {
  position: fixed; background: rgba(0,0,0,0.9); color: #fff; padding: 6px 10px;
  border-radius: 4px; font-size: 12px; pointer-events: none; display: none;
  z-index: 1000; max-width: 500px; word-break: break-all;
}
.legend { margin-top: 8px; font-size: 12px; color: #666; }
.no-data { text-align: center; padding: 60px; color: #666; font-size: 14px; }
.no-data.hidden { display: none; }
.canvas-wrap.hidden { display: none; }
.settings {
  background: #16213e; border: 1px solid #333; border-radius: 4px;
  padding: 12px; margin-bottom: 12px;
}
.settings-header {
  display: flex; align-items: center; justify-content: space-between;
  cursor: pointer; user-select: none;
}
.settings-header h3 { font-size: 14px; color: #e94560; margin: 0; }
.settings-header .arrow { color: #888; font-size: 12px; transition: transform 0.2s; }
.settings-header .arrow.open { transform: rotate(90deg); }
.settings-body { display: none; margin-top: 10px; }
.settings-body.open { display: block; }
.settings-row { display: flex; align-items: center; gap: 12px; margin-bottom: 8px; flex-wrap: wrap; }
.settings-row label { font-size: 12px; color: #aaa; min-width: 100px; }
.settings-row input {
  padding: 5px 8px; border: 1px solid #444; border-radius: 3px;
  background: #0f0f23; color: #e0e0e0; font-size: 13px; width: 200px;
}
.settings-row input:focus { outline: none; border-color: #e94560; }
.settings-actions { display: flex; gap: 8px; margin-top: 10px; }
.settings-actions button {
  padding: 6px 16px; border: 1px solid #444; border-radius: 4px;
  background: #1f3460; color: #e0e0e0; font-size: 13px; cursor: pointer;
}
.settings-actions button:hover { background: #2a4478; }
.settings-actions button.primary { background: #e94560; border-color: #e94560; }
.settings-actions button.primary:hover { background: #f06078; }
.settings-msg { font-size: 12px; color: #5cbea6; margin-top: 6px; min-height: 18px; }
.settings-msg.error { color: #e94560; }
</style>
</head>
<body>
<div class="header">
  <h1>eBPF Profiler - Flame Graph</h1>
  <p>实时性能分析数据可视化</p>
</div>

<div class="settings" id="settings-panel">
  <div class="settings-header" onclick="toggleSettings()">
    <h3>Profiling 配置</h3>
    <span class="arrow" id="settings-arrow">&#9654;</span>
  </div>
  <div class="settings-body" id="settings-body">
    <div class="settings-row">
      <label>目标 PID（逗号分隔）</label>
      <input id="cfg-pids" placeholder="留空则 profile 自身">
    </div>
    <div class="settings-row">
      <label>On-CPU 采样频率</label>
      <input id="cfg-cpu-freq" type="number" placeholder="19">
    </div>
    <div class="settings-row">
      <label>Off-CPU 阈值 (ns)</label>
      <input id="cfg-offcpu" type="number" placeholder="99">
    </div>
    <div class="settings-row">
      <label>内存采样 Block</label>
      <input id="cfg-mem-block" type="number" placeholder="128">
    </div>
    <div class="settings-row">
      <label>上报间隔</label>
      <input id="cfg-interval" placeholder="5s">
    </div>
    <div class="settings-actions">
      <button onclick="loadState()">加载当前配置</button>
      <button class="primary" onclick="applyState()">应用配置</button>
    </div>
    <div class="settings-msg" id="settings-msg"></div>
  </div>
</div>

<div class="controls">
  <label for="pid-select">进程 (PID Hash):</label>
  <select id="pid-select"><option value="">-- 选择 --</option></select>
  <label for="type-select">Profile:</label>
  <select id="type-select"><option value="">-- 选择 --</option></select>
  <button id="refresh-btn" onclick="refreshProfiles()">刷新</button>
</div>

<div class="breadcrumb" id="breadcrumb"></div>

<div class="canvas-wrap hidden" id="canvas-wrap">
  <canvas id="flamegraph"></canvas>
</div>
<div class="tooltip" id="tooltip"></div>
<div class="legend" id="legend"></div>
<div class="no-data" id="no-data">加载 profile 列表中...</div>

<script>
const FRAME_H = 22, MIN_W = 1, FONT_SZ = 12;
const COLORS = [
  '#F2674E','#F89C4A','#F1C14B','#5CBEA6','#4EA6D2',
  '#9264A8','#F05050','#E8762D','#F0B928','#52B85A',
  '#3A8EC2','#7B5DA7','#E64B4B','#E8922A','#F3C834',
  '#4DAF6E','#2E8AC4','#8B62A3','#D93E3E','#F1802C',
];

let allProfiles = [];
let profileTypes = [];
let flameData = null;
let zoomStack = [];
let selectedPid = null, selectedIdx = null;

const pidSel = document.getElementById('pid-select');
const typeSel = document.getElementById('type-select');
const canvas = document.getElementById('flamegraph');
const ctx = canvas.getContext('2d');
const breadcrumb = document.getElementById('breadcrumb');
const tooltip = document.getElementById('tooltip');
const canvasWrap = document.getElementById('canvas-wrap');
const noData = document.getElementById('no-data');
const legend = document.getElementById('legend');

function getColor(name) {
  let h = 0;
  for (let i = 0; i < name.length; i++) { h = ((h << 5) - h + name.charCodeAt(i)) | 0; }
  return COLORS[Math.abs(h) % COLORS.length];
}

function refreshProfiles() {
  fetch('/api/profiles')
    .then(r => r.json())
    .then(data => {
      allProfiles = data;
      renderPidSelector();
    })
    .catch(err => { console.error(err); });
}

function renderPidSelector() {
  const cur = pidSel.value;
  pidSel.innerHTML = '<option value="">-- 选择进程 --</option>';
  allProfiles.forEach(p => {
    pidSel.innerHTML += '<option value="' + p.pid + '">' + p.pid + ' (' + p.profiles.length + ' profiles)</option>';
  });
  pidSel.value = cur;
  if (allProfiles.length > 0) {
    noData.classList.add('hidden');
  } else {
    noData.classList.remove('hidden');
    noData.textContent = '等待 profiling 数据...';
  }
}

pidSel.addEventListener('change', function() {
  selectedPid = this.value;
  typeSel.innerHTML = '<option value="">-- 选择 profile --</option>';
  profileTypes = [];
  if (!selectedPid) return;

  const entry = allProfiles.find(p => String(p.pid) === selectedPid);
  if (!entry) return;
  profileTypes = entry.profiles;
  profileTypes.forEach((pt, i) => {
    typeSel.innerHTML += '<option value="' + i + '">' + pt.sample_type + '</option>';
  });
  if (profileTypes.length > 0) {
    typeSel.value = '0';
    loadAndRender();
  }
});

typeSel.addEventListener('change', function() {
  selectedIdx = this.value;
  if (selectedIdx !== '') loadAndRender();
});

function loadAndRender() {
  if (!selectedPid || selectedIdx === '') return;
  fetch('/api/flamegraph?pid=' + selectedPid + '&type=' + selectedIdx)
    .then(r => { if (!r.ok) throw new Error('Failed'); return r.json(); })
    .then(data => {
      flameData = data;
      zoomStack = [data];
      canvasWrap.classList.remove('hidden');
      noData.classList.add('hidden');
      render();
      updateBreadcrumb();
    })
    .catch(err => {
      console.error(err);
      noData.classList.remove('hidden');
      noData.textContent = '加载火焰图数据失败';
    });
}

// --- Rendering ---

function maxDepth(node) {
  if (!node.children || !node.children.length) return 1;
  let m = 0;
  for (const c of node.children) m = Math.max(m, maxDepth(c));
  return m + 1;
}

function render() {
  const root = zoomStack[zoomStack.length - 1];
  if (!root) return;

  const depth = maxDepth(root);
  const w = Math.max(canvasWrap.clientWidth - 2, 800);
  const h = depth * FRAME_H;
  canvas.width = w;
  canvas.height = h;
  canvas.style.width = w + 'px';
  canvas.style.height = h + 'px';

  ctx.clearRect(0, 0, w, h);
  if (root.value > 0) {
    renderNode(root, 0, 0, w, root.value, 0);
  }
  updateLegend(root);
}

function renderNode(node, x, y, w, totalVal) {
  if (w < MIN_W) return;

  ctx.fillStyle = getColor(node.name);
  ctx.fillRect(x, y, w, FRAME_H - 1);

  if (w > 22) {
    ctx.fillStyle = '#fff';
    ctx.font = FONT_SZ + 'px monospace';
    ctx.save();
    ctx.beginPath();
    ctx.rect(x + 2, y, w - 4, FRAME_H);
    ctx.clip();
    ctx.fillText(node.name, x + 4, y + FRAME_H - 5);
    ctx.restore();
  }

  if (node.children && node.children.length > 0 && totalVal > 0) {
    let cx = x;
    for (const child of node.children) {
      const cw = (child.value / totalVal) * w;
      renderNode(child, cx, y + FRAME_H, cw, child.value);
      cx += cw;
    }
  }
}

function updateBreadcrumb() {
  let html = '';
  zoomStack.forEach((n, i) => {
    if (i > 0) html += '<span class="breadcrumb-sep">&#8250;</span>';
    html += '<span class="breadcrumb-item" data-level="' + i + '">' + esc(n.name) + '</span>';
  });
  breadcrumb.innerHTML = html;

  breadcrumb.querySelectorAll('.breadcrumb-item').forEach(el => {
    el.addEventListener('click', function() {
      zoomTo(parseInt(this.dataset.level));
    });
  });
}

function zoomTo(level) {
  zoomStack = zoomStack.slice(0, level + 1);
  render();
  updateBreadcrumb();
}

function updateLegend(root) {
  const pct = root.value > 0 ? (root.value / root.value * 100).toFixed(0) : 0;
  const sampleType = profileTypes[parseInt(selectedIdx)];
  const typeLabel = sampleType ? sampleType.sample_type : '';
  legend.textContent = '总数: ' + root.value + ' ' + typeLabel + ' | 点击帧可放大，使用面包屑返回';
}

// --- Interaction ---

function findNodeAt(node, tx, ty, nx, nw, totalVal, depth) {
  const ny = depth * FRAME_H;
  if (ty >= ny && ty < ny + FRAME_H && tx >= nx && tx < nx + nw) {
    return node;
  }
  if (node.children && ty >= ny + FRAME_H && totalVal > 0) {
    let cx = nx;
    for (const child of node.children) {
      const cw = (child.value / totalVal) * nw;
      const found = findNodeAt(child, tx, ty, cx, cw, child.value, depth + 1);
      if (found) return found;
      cx += cw;
    }
  }
  return null;
}

canvas.addEventListener('click', function(e) {
  const rect = canvas.getBoundingClientRect();
  const x = e.clientX - rect.left, y = e.clientY - rect.top;
  const root = zoomStack[zoomStack.length - 1];
  if (!root) return;
  const node = findNodeAt(root, x, y, 0, canvas.width, root.value, 0);
  if (node && node.children && node.children.length > 0) {
    zoomStack.push(node);
    render();
    updateBreadcrumb();
  }
});

canvas.addEventListener('mousemove', function(e) {
  const rect = canvas.getBoundingClientRect();
  const x = e.clientX - rect.left, y = e.clientY - rect.top;
  const root = zoomStack[zoomStack.length - 1];
  if (!root) return;
  const node = findNodeAt(root, x, y, 0, canvas.width, root.value, 0);
  if (node) {
    const pct = root.value > 0 ? (node.value / root.value * 100).toFixed(2) : 0;
    tooltip.innerHTML = esc(node.name) + '<br>' + node.value + ' (' + pct + '%)';
    tooltip.style.display = 'block';
    tooltip.style.left = (e.clientX + 12) + 'px';
    tooltip.style.top = (e.clientY - 8) + 'px';
  } else {
    tooltip.style.display = 'none';
  }
});

canvas.addEventListener('mouseleave', function() { tooltip.style.display = 'none'; });

window.addEventListener('resize', function() { if (flameData) render(); });

function esc(s) {
  const d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}

// --- Settings ---

function toggleSettings() {
  const body = document.getElementById('settings-body');
  const arrow = document.getElementById('settings-arrow');
  body.classList.toggle('open');
  arrow.classList.toggle('open');
}

function loadState() {
  document.getElementById('settings-msg').textContent = '';
  document.getElementById('settings-msg').className = 'settings-msg';
  fetch('/api/state')
    .then(r => r.json())
    .then(s => {
      document.getElementById('cfg-pids').value = (s.cpu_pids || []).join(',');
      document.getElementById('cfg-cpu-freq').value = s.cpu_on_frequency;
      document.getElementById('cfg-offcpu').value = s.cpu_off_threshold;
      document.getElementById('cfg-mem-block').value = s.memory_block;
      document.getElementById('cfg-interval').value = s.interval;
      showMsg('配置已加载', false);
    })
    .catch(err => {
      console.error(err);
      showMsg('加载配置失败: ' + err, true);
    });
}

function applyState() {
  const pidsStr = document.getElementById('cfg-pids').value.trim();
  const cpuFreq = parseInt(document.getElementById('cfg-cpu-freq').value) || 0;
  const offcpu = parseInt(document.getElementById('cfg-offcpu').value) || 0;
  const memBlock = parseInt(document.getElementById('cfg-mem-block').value) || 0;
  const interval = document.getElementById('cfg-interval').value.trim();

  const body = {
    cpu_on_frequency: cpuFreq,
    cpu_off_threshold: offcpu,
    memory_block: memBlock,
    cpu_pids: pidsStr ? pidsStr.split(',').map(Number).filter(n => n > 0) : [],
    memory_pids: pidsStr ? pidsStr.split(',').map(Number).filter(n => n > 0) : [],
  };
  if (interval) body.interval = interval;

  document.getElementById('settings-msg').textContent = '';
  document.getElementById('settings-msg').className = 'settings-msg';

  fetch('/api/state', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
    .then(r => {
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return r.json();
    })
    .then(() => showMsg('配置已应用，将在下一个周期生效', false))
    .catch(err => {
      console.error(err);
      showMsg('应用配置失败: ' + err, true);
    });
}

function showMsg(msg, isError) {
  const el = document.getElementById('settings-msg');
  el.textContent = msg;
  el.className = 'settings-msg' + (isError ? ' error' : '');
  if (!isError) setTimeout(() => { el.textContent = ''; }, 3000);
}

// Init
refreshProfiles();
setInterval(refreshProfiles, 5000);
</script>
</body>
</html>`

func main() {
	addr := flag.String("addr", ":9090", "HTTP 服务监听地址")
	pidsFlag := flag.String("pids", "", "要 profile 的目标 PID（逗号分隔，默认 profile 自身）")
	flag.Parse()

	ctx, cancel := signal.NotifyContext(context.Background(), unix.SIGINT, unix.SIGTERM, unix.SIGABRT)
	defer cancel()

	state := colasoft.State{
		Interval: time.Second * 5,
	}
	state.CPU.OnFrequency = 19
	state.CPU.OffThreshold = 99
	state.Memory.Block = 128

	// 解析目标 PID
	targetPIDs := parsePIDs(*pidsFlag)
	if len(targetPIDs) == 0 {
		targetPIDs = map[uint32]bool{uint32(os.Getpid()): true}
	}

	state.CPU.PIDs = targetPIDs
	state.Memory.PIDs = targetPIDs

	ctrl := &webController{
		cache: newProfileCache(),
	}
	ctrl.state.Store(&state)

	colasoft.Setup(ctx, ctrl)

	// HTTP 路由
	mux := http.NewServeMux()
	mux.HandleFunc("/", ctrl.handleIndex)
	mux.HandleFunc("/api/profiles", ctrl.handleProfiles)
	mux.HandleFunc("/api/flamegraph", ctrl.handleFlamegraph)
	mux.HandleFunc("/api/state", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			ctrl.handleGetState(w, r)
		case http.MethodPost:
			ctrl.handleUpdateState(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	srv := &http.Server{
		Addr:         *addr,
		Handler:      mux,
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

func parsePIDs(s string) map[uint32]bool {
	if s == "" {
		return nil
	}
	result := make(map[uint32]bool)
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if pid, err := strconv.ParseUint(part, 10, 32); err == nil {
			result[uint32(pid)] = true
		}
	}
	return result
}
