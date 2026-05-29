package gpu

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/parca-dev/usdt"
	log "github.com/sirupsen/logrus"

	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/support"
	"go.opentelemetry.io/ebpf-profiler/util"
)

type (
	gpuTracer struct {
		specId   atomic.Uint32
		usdtSpec *cebpf.Map
		traps    map[usdtTrap]*cebpf.Program
		event    *eventTracer
		flag     atomic.Uint32

		gpuPids   *cebpf.Map
		mu        sync.Mutex
		linked    map[util.OnDiskFileIdentifier]*probeEntry
		pids      map[uint32]bool
		threshold uint32
	}

	probeEntry struct {
		*usdt.ProbeLinks
		refs   int
		path   string
		probes map[usdtTrap]usdt.Probe
	}
)

// thresholdAll is the sampling threshold meaning "sample every launch"
// (per-mille, 0~1000). It is the startup default on both the Go agent and the
// C++ library; keeping them equal means a never-written threshold file leaves
// the library sampling everything, as intended.
const thresholdAll uint32 = 1000

var GPU = &gpuTracer{threshold: thresholdAll}

var _ interpreter.Loader = (*gpuTracer)(nil).Loader

func (g *gpuTracer) Setup(ctx context.Context, progs map[string]*cebpf.Program, maps map[string]*cebpf.Map, rpt Reporter) error {
	gpuTimingEvents := maps["cuda_timing_events"]
	eventReader, err := perf.NewReader(gpuTimingEvents, 1024*1024)
	if err != nil {
		return fmt.Errorf("failed new reader for %s: %v", gpuTimingEvents, err)
	}
	gpuErrorEvents := maps["cuda_error_events"]
	errorReader, err := perf.NewReader(gpuErrorEvents, 1024*16)
	if err != nil {
		_ = eventReader.Close()
		return fmt.Errorf("failed new reader for %s: %v", gpuErrorEvents, err)
	}
	g.usdtSpec = maps["__bpf_usdt_specs"]

	g.gpuPids = maps["gpu_target_pids"]
	if g.gpuPids == nil {
		log.Warnf("[gpu] gpu_target_pids map not found, pid filtering disabled")
	} else {
		// Default to sampling every process until Switch() narrows it down.
		allKey := uint32(0)
		var one uint8 = 1
		if err := g.gpuPids.Update(unsafe.Pointer(&allKey), unsafe.Pointer(&one), cebpf.UpdateAny); err != nil {
			log.Warnf("[gpu] failed to set all-pids sentinel: %s", err)
		}
	}

	g.linked = make(map[util.OnDiskFileIdentifier]*probeEntry)
	traps := []usdtTrap{apiCorrelation, hostTiming, kernelTiming, apiSynchronize, errorTrap}
	g.traps = make(map[usdtTrap]*cebpf.Program)
	for _, trap := range traps {
		prog, ok := progs[trap.String()]
		if !ok {
			_ = eventReader.Close()
			_ = errorReader.Close()
			return fmt.Errorf("program %q not found", trap)
		}
		g.traps[trap] = prog
	}
	g.event = newEventTracer(rpt)
	go g.watchTimeline(ctx, eventReader)
	go g.watchError(ctx, errorReader)
	return nil
}
func (g *gpuTracer) ReportTrace(trace *libpf.Trace, meta *samples.TraceEventMeta) {
	if g.event != nil {
		g.event.ReportTrace(trace, meta)
	}
}

func (g *gpuTracer) Loader(_ interpreter.EbpfHandler, info *interpreter.LoaderInfo) (interpreter.Data, error) {
	if len(g.traps) == 0 {
		return nil, nil
	}
	ef, err := info.GetELF()
	if err != nil {
		return nil, err
	}

	// We use the existence of the .note.stapsdt section to determine if this is a
	// process that has libparcagpucupti.so loaded.
	probes, err := ef.ParseUSDTProbes()
	if err != nil {
		return nil, err
	}
	probes = slices.DeleteFunc(probes, func(probe usdt.Probe) bool { return probe.Provider != "colagpu" })
	if len(probes) == 0 {
		return nil, nil
	}
	d := &data{
		g:      g,
		path:   info.FileName(),
		probes: make(map[usdtTrap]usdt.Probe),
	}
	for _, trap := range []usdtTrap{apiCorrelation, hostTiming, kernelTiming, apiSynchronize, errorTrap} {
		if idx := slices.IndexFunc(probes, func(probe usdt.Probe) bool { return probe.Name == trap.String() }); idx == -1 {
			log.Warnf("[gpu] USDT probes in %s missing kernel probe (need %s): %v",
				info.FileName(), trap, probes)
			return nil, nil
		} else {
			d.probes[trap] = probes[idx]
		}
	}

	log.Debugf("[gpu] Found USDT probes in %s: %v", info.FileName(), d.probes)
	return d, nil
}

const (
	hostApiFlag uint32 = 1 << iota
	kernelFlag
)

func (g *gpuTracer) Switch(host, kernel bool, threshold uint32, pids map[uint32]bool) (switched bool) {
	var flag uint32
	if host {
		flag |= hostApiFlag
	}
	if kernel {
		flag |= kernelFlag
	}
	threshold = min(threshold, thresholdAll)
	g.mu.Lock()
	defer g.mu.Unlock()

	pidChanged := !maps.Equal(g.pids, pids)
	g.updatePidsLocked(pids)

	switched = threshold != g.threshold
	if switched || pidChanged {
		for pid := range g.pids {
			if err := writeThreshold(pid, threshold); err != nil {
				log.Errorf("[gpu] error writing threshold for pid %d: %v", pid, err)
			}
		}
		g.threshold = threshold
	}
	if g.flag.Swap(flag) == flag {
		return
	}
	switched = true
	for odfi, le := range g.linked {
		if le.ProbeLinks != nil {
			if err := le.Unload(); err != nil {
				log.Errorf("[gpu] error unloading usdt link for %s: %s", le.path, err)
			}
			le.ProbeLinks = nil
		}
		nl, err := g.attach(le.path, le.probes)
		if err != nil {
			log.Errorf("[gpu] error re-attaching usdt probes for %s: %s", le.path, err)
			continue
		}
		nl.refs = le.refs
		g.linked[odfi] = nl
	}
	return
}

// writeThreshold propagates the sampling threshold to one target CUDA process
// by writing through /proc/<pid>/root/tmp, which lands in that process's own
// /tmp filesystem (the agent runs with hostPID). A temp file + rename keeps the
// update atomic so the C++ reader never observes a torn value.
func writeThreshold(pid, value uint32) error {
	dir := fmt.Sprintf("/proc/%d/root/tmp", pid)
	tmp, err := os.CreateTemp(dir, ".parcagpu.threshold.*")
	if err != nil {
		return fmt.Errorf("create temp threshold file: %w", err)
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err = tmp.WriteString(fmt.Sprintf("%d\n", value)); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write threshold: %w", err)
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("close threshold file: %w", err)
	}

	// thresholdFileName is the filename the C++ library polls inside its own /tmp
	// (mirrors kThresholdPath in vendoring/parcagpu/src/cupti.cpp).
	const thresholdFileName = "parcagpu.threshold"
	if err = os.Rename(name, filepath.Join(dir, thresholdFileName)); err != nil {
		return fmt.Errorf("rename threshold file: %w", err)
	}
	return nil
}

func (g *gpuTracer) updatePidsLocked(pids map[uint32]bool) {
	if g.gpuPids == nil || maps.Equal(g.pids, pids) {
		return
	}

	var one uint8 = 1
	allKey := uint32(0)

	// Remove tgids that were selected before but are no longer.
	for pid := range g.pids {
		if !pids[pid] {
			if err := g.gpuPids.Delete(unsafe.Pointer(&pid)); err != nil && !errors.Is(err, cebpf.ErrKeyNotExist) {
				log.Errorf("[gpu] error removing pid %d: %s", pid, err)
			}
		}
	}
	// Add newly selected tgids.
	for pid := range pids {
		if !g.pids[pid] {
			if err := g.gpuPids.Update(unsafe.Pointer(&pid), unsafe.Pointer(&one), cebpf.UpdateAny); err != nil {
				log.Errorf("[gpu] error adding pid %d: %s", pid, err)
			}
		}
	}

	// Maintain the "all pids" sentinel: empty selection means sample everything.
	if len(pids) == 0 {
		if err := g.gpuPids.Update(unsafe.Pointer(&allKey), unsafe.Pointer(&one), cebpf.UpdateAny); err != nil {
			log.Errorf("[gpu] error setting all-pids sentinel: %s", err)
		}
	} else if err := g.gpuPids.Delete(unsafe.Pointer(&allKey)); err != nil && !errors.Is(err, cebpf.ErrKeyNotExist) {
		log.Errorf("[gpu] error removing all-pids sentinel: %s", err)
	}

	g.pids = maps.Clone(pids)
}

func (g *gpuTracer) MonitorPids(keys *[]uint32, known func(uint32) bool) {
	g.mu.Lock()
	pids := maps.Clone(g.pids)
	g.mu.Unlock()
	for pid := range pids {
		if !known(pid) {
			*keys = append(*keys, pid)
		}
	}
}

func (g *gpuTracer) EnableKernel() bool  { return g.flag.Load()&kernelFlag > 0 }
func (g *gpuTracer) EnableHostAPI() bool { return g.flag.Load()&hostApiFlag > 0 }

// activeTraps returns the traps to attach for the current host-api/kernel
// switches. correlation is attached when either switch is on; host_timing +
// api_synchronize follow the host-api switch; kernel_timing + error follow the
// kernel switch.
func (g *gpuTracer) activeTraps() []usdtTrap {
	host := g.EnableHostAPI()
	kernel := g.EnableKernel()
	traps := make([]usdtTrap, 0, 5)
	if host || kernel {
		traps = append(traps, apiCorrelation)
	}
	if host {
		traps = append(traps, hostTiming, apiSynchronize)
	}
	if kernel {
		traps = append(traps, kernelTiming, errorTrap)
	}
	return traps
}

func (g *gpuTracer) attach(path string, probes map[usdtTrap]usdt.Probe) (*probeEntry, error) {
	// Build the trap/prog/spec slices from the currently active switches. When
	// both switches are off no probe is attached (zero overhead).
	var traps []usdtTrap
	var probeSlice []usdt.Probe
	for _, trap := range g.activeTraps() {
		probe, ok := probes[trap]
		if !ok {
			continue
		}
		traps = append(traps, trap)
		probeSlice = append(probeSlice, probe)
	}

	entry := &probeEntry{path: path, probes: probes}
	if len(probeSlice) == 0 {
		return entry, nil
	}

	exe, err := link.OpenExecutable(path)
	if err != nil {
		log.Warnf("[gpu] failed to open executable in AttachUSDTProbes %v", err)
		return nil, err
	}
	startSpecID := g.specId.Add(uint32(len(probeSlice))) - uint32(len(probeSlice))
	specIDs, err := usdt.PopulateSpecMap(g.usdtSpec, probeSlice, startSpecID)
	if err != nil {
		return nil, fmt.Errorf("[gpu] failed to populate USDT spec maps: %w", err)
	}
	progs := make([]*cebpf.Program, 0, len(traps))
	cookies := make([]uint64, 0, len(traps))
	for _, trap := range traps {
		prog := g.traps[trap]
		progs = append(progs, prog)
		cookies = append(cookies, trap.Cookie())
	}

	finalCookies := usdt.MergeCookies(specIDs, cookies)
	pl, err := usdt.AttachUprobes(exe, g.usdtSpec, probeSlice, progs, finalCookies)
	if err != nil {
		return nil, err
	}

	log.Infof("[gpu] Attached %d individual probes to %s", len(probeSlice), path)
	entry.ProbeLinks = pl
	return entry, nil
}

func (g *gpuTracer) watchTimeline(ctx context.Context, reader *perf.Reader) {
	defer reader.Close()
	defer g.event.Expire(true)

	record := new(perf.Record)
	cleanTicker := time.Tick(time.Second * 5)
	for {
		reader.SetDeadline(time.Now().Add(time.Second))
		err := reader.ReadInto(record)
		select {
		case <-ctx.Done():
			return
		case <-cleanTicker:
			g.event.Expire(false)
		default:
			if err != nil || len(record.RawSample) == 0 {
				continue
			}
			recv := (*support.Timeline)(unsafe.Pointer(&record.RawSample[0]))
			timing := new(support.Timeline)
			*timing = *recv // copy
			g.event.ReportTiming(timing)
		}
	}
}

func (g *gpuTracer) watchError(ctx context.Context, reader *perf.Reader) {
	defer reader.Close()

	record := new(perf.Record)
	for {
		reader.SetDeadline(time.Now().Add(time.Second))
		err := reader.ReadInto(record)
		select {
		case <-ctx.Done():
			return
		default:
			if err != nil || len(record.RawSample) == 0 {
				continue
			}
			recv := (*support.ErrorEvent)(unsafe.Pointer(&record.RawSample[0]))
			evt := new(support.ErrorEvent)
			*evt = *recv // copy
			g.event.ReportError(evt)
		}
	}
}
