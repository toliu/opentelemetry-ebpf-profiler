package colasoft

import (
	"context"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"

	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/times"
	"go.opentelemetry.io/ebpf-profiler/tracehandler"
	"go.opentelemetry.io/ebpf-profiler/tracer"
	tracertypes "go.opentelemetry.io/ebpf-profiler/tracer/types"
)

type profiling struct {
	ctrl     Controller
	reporter *colaSoftReporter
}

func Setup(ctx context.Context, ctrl Controller) {
	p := &profiling{
		ctrl:     ctrl,
		reporter: newColaSoftReporter(ctx, ctrl),
	}
	go p.Start(ctx)
}

func (p *profiling) Start(ctx context.Context) {
	times.StartRealtimeSync(ctx, time.Minute*3)
	var interval = time.Second
	for {
		if err := p.start(ctx); err != nil {
			log.Warnf("failed to start profiling: %v", err)
			interval = min(interval*2, time.Second*30)
		} else {
			interval = time.Second
		}
		time.Sleep(interval)
	}
}

func (p *profiling) start(parent context.Context) error {
	if !p.ctrl.State().Enable() {
		return nil
	}
	if err := tracer.ProbeBPFSyscall(); err != nil {
		return fmt.Errorf("failed to probe eBPF syscall: %w", err)
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	_ = p.reporter.Start(ctx)
	defer p.reporter.Stop()
	defer p.reporter.SetOnCPUFreq(0)
	intervals := times.New(p.reporter.Interval(), time.Second*5, 0)
	trc, err := tracer.NewTracer(ctx, &tracer.Config{
		Reporter:          p.reporter,
		Intervals:         intervals,
		IncludeTracers:    tracertypes.AllTracers(),
		FilterErrorFrames: true,
		DebugTracer:       false,
	})
	if err != nil {
		return fmt.Errorf("failed to new tracer: %v", err)
	}
	defer trc.Close()
	trc.StartPIDEventProcessor(ctx)
	if err = trc.AttachSchedMonitor(); err != nil {
		return fmt.Errorf("failed to attach scheduler monitor: %w", err)
	}

	// Spawn monitors for the various result maps
	traceCh := make(chan *host.Trace)
	if err = trc.StartMapMonitors(ctx, traceCh); err != nil {
		return fmt.Errorf("failed to start map monitors: %v", err)
	}

	if _, err = tracehandler.Start(ctx, p.reporter, trc.TraceProcessor(), traceCh, intervals, 65536); err != nil {
		return err
	}
	var state = State{} // start with empty
	for {
		select {
		case <-time.After(time.Second):
		case <-ctx.Done():
			return nil
		}
		cur := p.ctrl.State()
		if !cur.Enable() {
			return nil
		}
		p.reporter.SetInterval(state.Interval)
		if cur.CPU.OffThreshold != state.CPU.OffThreshold {
			if err = trc.StartOffCPUProfiling(uint32(cur.CPU.OffThreshold)); err != nil {
				return fmt.Errorf("failed to start off-cpu profiling: %v", err)
			}
			log.Infof("switch off-cpu profiling threshold %d to %d", state.CPU.OffThreshold, cur.CPU.OffThreshold)
		}

		if cur.CPU.OnFrequency != state.CPU.OnFrequency {
			p.reporter.SetOnCPUFreq(cur.CPU.OnFrequency)
			if err = trc.StartOnCpuProfiling(cur.CPU.OnFrequency); err != nil {
				return fmt.Errorf("failed to start on-cpu profiling: %v", err)
			}
			log.Infof("switch on-cpu profiling frequency %d to %d", state.CPU.OnFrequency, cur.CPU.OnFrequency)
		}
		if cur.Memory.Block != state.Memory.Block {
			if err = trc.StartMemProfiling(cur.Memory.Block); err != nil {
				return err
			}
			log.Infof("switch mem profiling block %d to %d", state.Memory.Block, cur.Memory.Block)
		}

		add, remove := state.CPU.PIDs.Compare(cur.CPU.PIDs)
		if err = trc.UpdateTargetPIDs(add, remove); err != nil {
			log.Warnf("failed to update target pids: %v", err)
		}
		add, remove = state.Memory.PIDs.Compare(cur.Memory.PIDs)
		trc.UpdateMemTargetPIDs(add, remove)
		state = cur
	}
}
