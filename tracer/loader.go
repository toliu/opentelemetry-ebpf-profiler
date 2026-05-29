package tracer

import (
	"errors"
	"fmt"
	"strings"
	"unsafe"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	log "github.com/sirupsen/logrus"

	"go.opentelemetry.io/ebpf-profiler/rlimit"
	"go.opentelemetry.io/ebpf-profiler/support"
	"go.opentelemetry.io/ebpf-profiler/tracer/types"
)

type (
	ebpfLoader struct {
		coll *cebpf.CollectionSpec

		tails   map[string]progLoaderHelper
		progOpt cebpf.ProgramOptions

		maps  map[string]*cebpf.Map
		progs map[string]*cebpf.Program
	}
)

func newEbpfLoader(coll *cebpf.CollectionSpec, tracers types.IncludedTracers, lvl uint32) *ebpfLoader {
	return &ebpfLoader{
		maps:    make(map[string]*cebpf.Map),
		progs:   make(map[string]*cebpf.Program),
		coll:    coll,
		progOpt: cebpf.ProgramOptions{LogLevel: cebpf.LogLevel(lvl)},
		tails: map[string]progLoaderHelper{
			"unwind_stop":    {progID: uint32(support.ProgUnwindStop), enable: true},
			"unwind_native":  {progID: uint32(support.ProgUnwindNative), enable: true},
			"unwind_hotspot": {progID: uint32(support.ProgUnwindHotspot), enable: tracers.Has(types.HotspotTracer)},
			"unwind_perl":    {progID: uint32(support.ProgUnwindPerl), enable: tracers.Has(types.PerlTracer)},
			"unwind_php":     {progID: uint32(support.ProgUnwindPHP), enable: tracers.Has(types.PHPTracer)},
			"unwind_python":  {progID: uint32(support.ProgUnwindPython), enable: tracers.Has(types.PythonTracer)},
			"unwind_ruby":    {progID: uint32(support.ProgUnwindRuby), enable: tracers.Has(types.RubyTracer)},
			"unwind_v8":      {progID: uint32(support.ProgUnwindV8), enable: tracers.Has(types.V8Tracer)},
			"unwind_dotnet":  {progID: uint32(support.ProgUnwindDotnet), enable: tracers.Has(types.DotnetTracer)},
		},
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
	ignore := map[string]bool{
		// 不需要加载的unwinder
		`tracepoint_integration__sched_switch`: true,
		`dummy`:                                true,
		`usdt_dummy_probe`:                     true,
		`uprobe_dummy_probe`:                   true,
		`read_task_struct`:                     true,
		`read_kernel_memory`:                   true,
	}
	for _, spec := range e.coll.Programs {
		if ignore[spec.Name] {
			continue
		}
		split := strings.SplitN(spec.SectionName, "/", 2)
		section, name := split[0], split[1] // 如果SectionName格式不对则直接panic
		mapReplace := make(map[string]string)
		var tailCallMap = e.maps[`perf_progs`]
		switch section {
		case `kprobe`: // off-cpu profiling
			tailCallMap = e.maps[`kprobe_progs`]
			mapReplace[`perf_progs`] = `kprobe_progs`
			// FIXME: On-CPU和OFF-CPU不会出现数据竞争，不需要单独的per_cpu_records
			//mapReplace[`per_cpu_records`] = `kprobe_per_cpu_records`
		case `uprobe`, `uretprobe`: // 内存 profiling
			tailCallMap = e.maps[`uprobe_progs`]
			mapReplace[`perf_progs`] = `uprobe_progs`
			mapReplace[`per_cpu_records`] = `uprobe_per_cpu_records`
			spec.AttachTo = ""
		case "usdt":
			tailCallMap = e.maps[`usdt_progs`]
			mapReplace[`perf_progs`] = `usdt_progs`
			mapReplace[`per_cpu_records`] = `usdt_per_cpu_records`
		}
		for origin, cur := range mapReplace {
			if err := e.replaceMap(spec, origin, cur); err != nil {
				return err
			}
		}
		unwinder, err := cebpf.NewProgramWithOptions(spec, e.progOpt)
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
		if tail, ok := e.tails[name]; ok && tail.enable {
			fd := unwinder.FD()
			if err = tailCallMap.Update(unsafe.Pointer(&tail.progID), unsafe.Pointer(&fd), cebpf.UpdateAny); err != nil {
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

func (e *ebpfLoader) replaceMap(spec *cebpf.ProgramSpec, from, to string) error {
	iter := spec.Instructions.Iterate()
	for iter.Next() {
		if iter.Ins.OpCode.Class() != asm.LdClass {
			continue
		}
		m := iter.Ins.Map()
		if m == nil {
			continue
		}
		if e.maps[from].FD() == m.FD() {
			if err := iter.Ins.AssociateMap(e.maps[to]); err != nil {
				return fmt.Errorf("failed to rewrite map ptr: %v", err)
			}
		}
	}
	return nil
}
