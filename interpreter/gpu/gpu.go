package gpu

import (
	"context"
	"fmt"
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

		mu     sync.Mutex
		linked map[util.OnDiskFileIdentifier]*probeEntry
	}

	probeEntry struct {
		*usdt.ProbeLinks
		refs   int
		path   string
		probes map[usdtTrap]usdt.Probe
	}
)

var GPU = new(gpuTracer)

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

func (g *gpuTracer) Switch(host, kernel bool) (switched bool) {
	var flag uint32
	if host {
		flag |= hostApiFlag
	}
	if kernel {
		flag |= kernelFlag
	}
	if switched = g.flag.Swap(flag) != flag; !switched {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
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
