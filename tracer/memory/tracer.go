package memory

import (
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"unsafe"

	cebpf "github.com/cilium/ebpf"
	log "github.com/sirupsen/logrus"

	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/xsync"
	"go.opentelemetry.io/ebpf-profiler/proc"
	pm "go.opentelemetry.io/ebpf-profiler/processmanager"
	"go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/util"
)

type (
	memoryInterpreter interface {
		Type() libpf.InterpreterType
		io.Closer
	}

	// fileInterpreter 表示按文件（inode）挂载的一整套 uprobe，被多个 pid 共享。
	// refs 记录当前引用该文件的 pid 数量，归零时 detach。
	fileInterpreter struct {
		lang libpf.InterpreterType
		mi   memoryInterpreter
		refs int
	}

	// memState 保存内存 profiling 的全部可变状态，由一把大锁保护，
	// 避免多把锁之间出现顺序问题。
	memState struct {
		disabled map[libpf.InterpreterType]bool
		files    map[util.OnDiskFileIdentifier]*fileInterpreter
		probed   map[uint32]util.OnDiskFileIdentifier // pid -> 已挂载的文件（eBPF uprobe 类）
		hotspots map[uint32]memoryInterpreter         // pid -> Java hotspot（每 pid 独立挂载）
		targets  map[uint32]struct{}                  // 用户指定要 profile 的 pid 全集
	}

	Tracer struct {
		progs map[string]*cebpf.Program

		pm       *pm.ProcessManager
		reporter reporter.SymbolReporter
		traceOut chan<- *host.Trace

		block   *atomic.Uint64
		memPids *cebpf.Map // mem_target_pids，内核侧按 tgid 过滤
		state   xsync.RWMutex[memState]
	}
)

func NewMemoryTracer(mgr *pm.ProcessManager, rpt reporter.SymbolReporter,
	progs map[string]*cebpf.Program, maps map[string]*cebpf.Map) *Tracer {
	t := &Tracer{
		pm:       mgr,
		reporter: rpt,
		progs:    progs,
		block:    new(atomic.Uint64),
	}
	if maps != nil {
		if memPids, ok := maps["mem_target_pids"]; ok {
			t.memPids = memPids
		}
	}
	if t.memPids == nil {
		log.Warn("mem_target_pids map not found, memory profiling pid filter unavailable")
	}
	t.state = xsync.NewRWMutex(memState{
		disabled: map[libpf.InterpreterType]bool{
			libpf.Python: true, // python
			libpf.Native: true, // c
		},
		files:    make(map[util.OnDiskFileIdentifier]*fileInterpreter),
		probed:   make(map[uint32]util.OnDiskFileIdentifier),
		hotspots: make(map[uint32]memoryInterpreter),
		targets:  make(map[uint32]struct{}),
	})
	return t
}

func (t *Tracer) SetTraceOut(out chan<- *host.Trace) { t.traceOut = out }

// SetBlock 设置内存 profiling 的分配阈值。当从非 0 变为 0（关闭 profiling）时，
// 立即 detach 所有 uprobe/hotspot，保证关闭状态下无任何开销。
func (t *Tracer) SetBlock(block uint64) {
	if prev := t.block.Load(); prev != 0 && block == 0 {
		t.detachAll()
	}
	t.block.Store(block)
}

func (t *Tracer) DisableInterpreter(m map[libpf.InterpreterType]bool) {
	maps.DeleteFunc(m, func(interpreterType libpf.InterpreterType, b bool) bool { return !b })

	st := t.state.WLock()
	defer t.state.WUnlock(&st)
	if maps.Equal(st.disabled, m) {
		return
	}

	// 语言被启用的情况无需在这里处理：下一轮 MonitorMemProfilePids 会对
	// targets 里未挂载的 pid 重新尝试挂载。这里只需处理"语言被禁用"，
	// detach 对应的文件级 uprobe / hotspot。
	for odfi, fi := range st.files {
		if !m[fi.lang] {
			continue
		}
		_ = fi.mi.Close()
		delete(st.files, odfi)
	}
	// 清理指向已 detach 文件的 pid 引用，并同步内核过滤 map。
	for pid, odfi := range st.probed {
		if _, ok := st.files[odfi]; !ok {
			delete(st.probed, pid)
			t.delMemPid(pid)
		}
	}
	if m[libpf.HotSpot] {
		for pid, mi := range st.hotspots {
			_ = mi.Close()
			delete(st.hotspots, pid)
		}
	}
	st.disabled = maps.Clone(m)
}

func (t *Tracer) UpdateTargetPID(add, remove []uint32) {
	st := t.state.WLock()
	defer t.state.WUnlock(&st)
	for _, pid := range add {
		st.targets[pid] = struct{}{}
	}
	for _, pid := range remove {
		delete(st.targets, pid)
		t.removePidLocked(st, pid)
	}
}

// removePidLocked 清理单个 pid 的全部 per-pid 状态：释放文件引用计数、关闭
// hotspot 解释器，并把 pid 从内核过滤 map 删除。调用方须持 st 写锁。
func (t *Tracer) removePidLocked(st *memState, pid uint32) {
	if odfi, ok := st.probed[pid]; ok {
		delete(st.probed, pid)
		t.releaseFileLocked(st, odfi)
	}
	if mi, ok := st.hotspots[pid]; ok {
		_ = mi.Close()
		delete(st.hotspots, pid)
	}
	t.delMemPid(pid)
}

func (t *Tracer) MonitorMemProfilePids(keys *[]uint32) {
	if t.block.Load() == 0 || t.memPids == nil {
		return
	}
	st := t.state.WLock()
	defer t.state.WUnlock(&st)
	// SetBlock(0) 可能在取锁前完成 detachAll，进入锁后需二次确认，否则会把刚
	// detach 掉的 uprobe 立刻重新挂回，破坏"关闭即零开销"的约束。
	if t.block.Load() == 0 {
		return
	}

	// 清理已退出目标进程的残留状态：uprobe 已全局化、内核只按 tgid 过滤，若不
	// 清理，tgid 被回收后新进程会被按旧配置错误分析。probed/hotspots 里的 pid
	// 都曾存活过，liveness 判断是可靠的。
	for pid := range st.probed {
		if live, _ := proc.IsPIDLive(libpf.PID(pid)); live {
			continue
		}
		delete(st.targets, pid)
		t.removePidLocked(st, pid)
	}
	for pid := range st.hotspots {
		if live, _ := proc.IsPIDLive(libpf.PID(pid)); live {
			continue
		}
		delete(st.targets, pid)
		t.removePidLocked(st, pid)
	}

	for pid := range st.targets {
		if _, ok := st.probed[pid]; ok {
			continue
		}
		if _, ok := st.hotspots[pid]; ok {
			continue
		}
		minfo := t.pm.GetMemProfileInfo(libpf.PID(pid))
		if minfo == nil {
			*keys = append(*keys, pid)
			continue
		}
		lang := minfo.Lang
		if lang == libpf.UnknownInterp {
			if minfo.LibcPath == "" {
				continue
			}
			lang = libpf.Native
		}
		if st.disabled[lang] {
			continue
		}
		switch lang {
		case libpf.Python:
			if minfo.LibPythonPath == "" {
				continue
			}
			if err := t.probeFileLocked(st, lang, minfo.LibPythonPath, pid); err != nil {
				log.Warnf("failed to attach memory probes for pid(%d): %v", pid, err)
				delete(st.targets, pid)
			}
		case libpf.Golang:
			if minfo.ExecAbsPath == "" {
				continue
			}
			if err := t.probeFileLocked(st, lang, minfo.ExecAbsPath, pid); err != nil {
				log.Warnf("failed to attach memory probes for pid(%d): %v", pid, err)
				delete(st.targets, pid)
			}
		case libpf.HotSpot:
			if t.traceOut == nil {
				continue
			}
			if minfo.MajorVersion == 0 {
				if lanV := strings.Split(fmt.Sprintf("%s", minfo.ItData), " "); len(lanV) > 1 {
					for _, s := range lanV[1:] {
						if ver := strings.Split(s, "."); len(ver) > 1 {
							minfo.MajorVersion, _ = strconv.Atoi(ver[0])
							minfo.MinorVersion, _ = strconv.Atoi(ver[1])
							break
						}
					}
				}
			}
			// 需要 java 11 及以上才支持
			if minfo.MajorVersion < 1 && minfo.MinorVersion < 11 {
				log.Infof("unsupported hotspot-memprofile for pid(%d): jdk-%d.%d", pid, minfo.MajorVersion, minfo.MinorVersion)
				delete(st.targets, pid)
				continue
			}
			mi, err := newHotspotInterpreter(pid, t.block, t.reporter, t.traceOut)
			if err != nil {
				log.Warnf("failed to new hotspot interpreter for pid(%d): %v", pid, err)
				delete(st.targets, pid)
				continue
			}
			st.hotspots[pid] = mi
		case libpf.Native:
			if minfo.LibcPath == "" {
				continue
			}
			if err := t.probeFileLocked(st, lang, minfo.LibcPath, pid); err != nil {
				log.Warnf("failed to attach memory probes for pid(%d): %v", pid, err)
				delete(st.targets, pid)
			}
		}
	}
}

// probeFileLocked 把 pid 挂到其语言对应的文件 uprobe 上。若该文件已挂载则仅
// 增加引用计数并复用；否则创建解释器（全局 uprobe，不指定 pid）。
func (t *Tracer) probeFileLocked(st *memState, lang libpf.InterpreterType, path string, pid uint32) error {
	odfi, err := fileIdent(path)
	if err != nil {
		return err
	}
	// 先写内核过滤 map：map 满时在这里失败，从而不留下 refs/probed 的悬空引用；
	// 后续任何失败都会回滚该条目，保证 mem_target_pids 与 probed 一致。
	if err := t.putMemPid(pid); err != nil {
		return err
	}
	if fi, ok := st.files[odfi]; ok {
		if fi.lang != lang {
			t.delMemPid(pid)
			return fmt.Errorf("inode %d:%d already profiled as %s, not %s",
				odfi.DeviceID, odfi.InodeNum, fi.lang, lang)
		}
		fi.refs++
		st.probed[pid] = odfi
		return nil
	}
	var mi memoryInterpreter
	switch lang {
	case libpf.Golang:
		mi, err = newGolangInterpreter(path, t.progs)
	case libpf.Python:
		mi, err = newPythonInterpreter(path, t.progs)
	case libpf.Native:
		mi, err = newCLikeInterpreter(path, t.progs)
	default:
		err = fmt.Errorf("unsupported interpreter language %s", lang)
	}
	if err != nil {
		t.delMemPid(pid)
		return err
	}
	st.files[odfi] = &fileInterpreter{lang: lang, mi: mi, refs: 1}
	st.probed[pid] = odfi
	return nil
}

// releaseFileLocked 递减文件引用计数，归零时 detach 整个文件的 uprobe。
func (t *Tracer) releaseFileLocked(st *memState, odfi util.OnDiskFileIdentifier) {
	if fi, ok := st.files[odfi]; ok {
		fi.refs--
		if fi.refs <= 0 {
			_ = fi.mi.Close()
			delete(st.files, odfi)
		}
	}
}

func (t *Tracer) detachAll() {
	st := t.state.WLock()
	defer t.state.WUnlock(&st)
	for _, fi := range st.files {
		_ = fi.mi.Close()
	}
	clear(st.files)
	for pid := range st.probed {
		t.delMemPid(pid)
	}
	clear(st.probed)
	for _, mi := range st.hotspots {
		_ = mi.Close()
	}
	clear(st.hotspots)
	// targets 保留，block 重新 >0 时 MonitorMemProfilePids 会重新挂载。
}

func (t *Tracer) Close() error {
	st := t.state.WLock()
	defer t.state.WUnlock(&st)
	var errs []error
	for _, fi := range st.files {
		errs = append(errs, fi.mi.Close())
	}
	for _, mi := range st.hotspots {
		errs = append(errs, mi.Close())
	}
	// 保持各 map 非 nil，避免 Close 之后再有 UpdateTargetPID/probe 时写 nil map panic。
	clear(st.files)
	clear(st.probed)
	clear(st.hotspots)
	clear(st.targets)
	clear(st.disabled)
	return errors.Join(errs...)
}

func (t *Tracer) putMemPid(pid uint32) error {
	if t.memPids == nil {
		return nil
	}
	one := uint8(1)
	return t.memPids.Update(unsafe.Pointer(&pid), unsafe.Pointer(&one), cebpf.UpdateAny)
}

func (t *Tracer) delMemPid(pid uint32) {
	if t.memPids == nil {
		return
	}
	_ = t.memPids.Delete(unsafe.Pointer(&pid))
}

// fileIdent 返回文件的 dev+inode 标识，作为按文件去重挂载的 key。
func fileIdent(path string) (util.OnDiskFileIdentifier, error) {
	info, err := os.Stat(path)
	if err != nil {
		return util.OnDiskFileIdentifier{}, err
	}
	sys, ok := info.Sys().(*syscall.Stat_t)
	if !ok || sys == nil {
		return util.OnDiskFileIdentifier{}, fmt.Errorf("failed to get stat_t for %s", path)
	}
	return util.OnDiskFileIdentifier{DeviceID: sys.Dev, InodeNum: sys.Ino}, nil
}
