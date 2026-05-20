package tracer

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"unsafe"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	log "github.com/sirupsen/logrus"

	"go.opentelemetry.io/ebpf-profiler/rlimit"
	"go.opentelemetry.io/ebpf-profiler/support"
	"go.opentelemetry.io/ebpf-profiler/tracer/types"
)

type ebpfLoader struct {
	coll              *cebpf.CollectionSpec
	maps              map[string]*cebpf.Map
	progs             map[string]*cebpf.Program
	tails             map[string]progLoaderHelper
	bpfVerifyLogLevel uint32
}

func newEbpfLoader(coll *cebpf.CollectionSpec, tracers types.IncludedTracers, lvl uint32) *ebpfLoader {
	common := map[string]progLoaderHelper{
		"unwind_stop":    {progID: uint32(support.ProgUnwindStop), enable: true},
		"unwind_native":  {progID: uint32(support.ProgUnwindNative), enable: true},
		"unwind_hotspot": {progID: uint32(support.ProgUnwindHotspot), enable: tracers.Has(types.HotspotTracer)},
		"unwind_perl":    {progID: uint32(support.ProgUnwindPerl), enable: tracers.Has(types.PerlTracer)},
		"unwind_php":     {progID: uint32(support.ProgUnwindPHP), enable: tracers.Has(types.PHPTracer)},
		"unwind_python":  {progID: uint32(support.ProgUnwindPython), enable: tracers.Has(types.PythonTracer)},
		"unwind_ruby":    {progID: uint32(support.ProgUnwindRuby), enable: tracers.Has(types.RubyTracer)},
		"unwind_v8":      {progID: uint32(support.ProgUnwindV8), enable: tracers.Has(types.V8Tracer)},
		"unwind_dotnet":  {progID: uint32(support.ProgUnwindDotnet), enable: tracers.Has(types.DotnetTracer)},
	}
	tails := map[string]progLoaderHelper{
		// 不需要加载的unwinder
		`tracepoint_integration__sched_switch`: {enable: false},
		`dummy`:                                {enable: false},
		`read_task_struct`:                     {enable: false},
		`read_kernel_memory`:                   {enable: false},
	}
	for name, cfg := range common {
		tails[fmt.Sprintf("kprobe_%s", name)] = cfg
		tails[fmt.Sprintf("perf_%s", name)] = cfg
	}
	return &ebpfLoader{
		maps:              make(map[string]*cebpf.Map),
		progs:             make(map[string]*cebpf.Program),
		coll:              coll,
		bpfVerifyLogLevel: lvl,
		tails:             tails,
	}
}

func (e *ebpfLoader) Maps() map[string]*cebpf.Map         { return e.maps }
func (e *ebpfLoader) Programs() map[string]*cebpf.Program { return e.progs }

func (e *ebpfLoader) Load() error {
	if restoreRlimit, err := rlimit.MaximizeMemlock(); err != nil {
		return fmt.Errorf("failed to adjust rlimit: %v", err)
	} else {
		defer restoreRlimit()
	}
	if err := e.loadMaps(); err != nil {
		return err
	}
	perfProgs := e.maps[`perf_progs`]
	kprobeProgs := e.maps[`kprobe_progs`]
	opt := cebpf.ProgramOptions{LogLevel: cebpf.LogLevel(e.bpfVerifyLogLevel)}
	perfEntrypoint := []string{`tracepoint__sched_process_exit`, `native_tracer_entry`}
	isperf := func(name string) bool {
		return strings.HasPrefix(name, `perf_`) || slices.Contains(perfEntrypoint, name)
	}
	names := slices.Collect(maps.Keys(e.coll.Programs))
	// 确保优先加载perf程序，kprobe程序会修改ebpf的map跳转指令
	slices.SortFunc(names, func(a, b string) int {
		if isperf(a) {
			return -1
		}
		if isperf(b) {
			return 1
		}
		return strings.Compare(a, b)
	})
	for _, name := range names {
		tail, isTail := e.tails[name]
		if isTail && !tail.enable {
			continue
		}
		spec := e.coll.Programs[name]
		if !isperf(name) {
			iter := spec.Instructions.Iterate()
			for iter.Next() {
				if asm.OpCode(iter.Ins.OpCode.Class()) != asm.OpCode(asm.LdClass) {
					continue
				}
				m := iter.Ins.Map()
				if m == nil {
					continue
				}
				if perfProgs.FD() == m.FD() {
					if err := iter.Ins.AssociateMap(kprobeProgs); err != nil {
						return fmt.Errorf("failed to rewrite map ptr: %v", err)
					}
				}
			}
		}
		// uprobe ebpf程序不需要绑定内核结构体或方法，此处强制把此字段置为空
		// 后续需要注意：uprobe的ebpf程序将默认有section为'uprobe/'和'uretprobe/'的约定
		if strings.HasPrefix(spec.SectionName, "uprobe/") || strings.HasPrefix(spec.SectionName, "uretprobe/") {
			spec.AttachTo = ""
		}
		unwinder, err := cebpf.NewProgramWithOptions(spec, opt)
		if err != nil {
			var ve *cebpf.VerifierError
			if errors.As(err, &ve) {
				for _, line := range ve.Log {
					log.Error(line)
				}
			}
			return fmt.Errorf("failed to load %s", spec.Name)
		}
		e.progs[spec.Name] = unwinder
		if isTail {
			m := perfProgs
			if strings.HasPrefix(spec.Name, "kprobe") {
				m = kprobeProgs
			}
			fd := unwinder.FD()
			if err = m.Update(unsafe.Pointer(&tail.progID), unsafe.Pointer(&fd), cebpf.UpdateAny); err != nil {
				return fmt.Errorf("failed to update tailcall map: %v", err)
			}
		}
	}
	return nil
}

func (e *ebpfLoader) loadMaps() error {
	// Redefine the maximum number of map entries for selected eBPF maps.
	adaption := make(map[string]uint32, 4)
	const (
		// The following sizes X are used as 2^X, and determined empirically

		// 1 million executable pages / 4GB of executable address space
		pidPageMappingInfoSize = 20

		stackDeltaPageToInfoSize = 16
		exeIDToStackDeltasSize   = 16
	)

	adaption["pid_page_to_mapping_info"] = 1 << uint32(pidPageMappingInfoSize)
	adaption["stack_delta_page_to_info"] = 1 << uint32(stackDeltaPageToInfoSize)

	// To not loose too many scheduling events but also not oversize
	// sched_times, calculate a size based on some assumptions.
	// On modern systems /proc/sys/kernel/pid_max defaults to 4194304.
	// Try to fit this PID space scaled down with cfg.OffCPUThreshold into
	// this map.
	adaption["sched_times"] = 4194304

	for i := support.StackDeltaBucketSmallest; i <= support.StackDeltaBucketLargest; i++ {
		mapName := fmt.Sprintf("exe_id_to_%d_stack_deltas", i)
		adaption[mapName] = 1 << uint32(exeIDToStackDeltasSize)
	}

	for mapName, mapSpec := range e.coll.Maps {
		if newSize, ok := adaption[mapName]; ok {
			mapSpec.MaxEntries = newSize
		}
		ebpfMap, err := cebpf.NewMap(mapSpec)
		if err != nil {
			return fmt.Errorf("failed to load %s: %v", mapName, err)
		}
		e.maps[mapName] = ebpfMap
	}
	return e.coll.RewriteMaps(e.maps)
}

func (e *ebpfLoader) loadProgram(spec *cebpf.ProgramSpec, tail *cebpf.Map, id uint32) error {
	opt := cebpf.ProgramOptions{LogLevel: cebpf.LogLevel(e.bpfVerifyLogLevel)}
	unwinder, err := cebpf.NewProgramWithOptions(spec, opt)
	if err != nil {
		var ve *cebpf.VerifierError
		if errors.As(err, &ve) {
			for _, line := range ve.Log {
				log.Error(line)
			}
		}
		return fmt.Errorf("failed to load %s", spec.Name)
	}

	e.progs[spec.Name] = unwinder
	if tail != nil {
		fd := unwinder.FD()
		if err = tail.Update(unsafe.Pointer(&id), unsafe.Pointer(&fd), cebpf.UpdateAny); err != nil {
			return fmt.Errorf("failed to update tailcall map: %v", err)
		}
	}
	return nil
}
