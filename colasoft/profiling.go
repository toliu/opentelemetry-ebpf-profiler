package colasoft

import (
	"context"
	"fmt"
	"maps"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/exp/constraints"

	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/interpreter/gpu"
	"go.opentelemetry.io/ebpf-profiler/times"
	"go.opentelemetry.io/ebpf-profiler/tracehandler"
	"go.opentelemetry.io/ebpf-profiler/tracer"
	tracertypes "go.opentelemetry.io/ebpf-profiler/tracer/types"
	"go.opentelemetry.io/ebpf-profiler/util"
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
	if !p.ctrl.GetProfilingStat(nil).Enable() {
		return nil
	}
	defer p.ctrl.GetProfilingStat(nil)

	if err := tracer.ProbeBPFSyscall(); err != nil {
		return fmt.Errorf("failed to probe eBPF syscall: %w", err)
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	_ = p.reporter.Start(ctx)
	defer p.reporter.Stop()
	defer p.reporter.SetOnCPUFreq(0)
	intervals := times.New(p.reporter.Interval(), time.Second*5, 0)
	tracers := tracertypes.AllTracers()
	if !util.HasBpfGetAttachCookie() {
		tracers.Disable(tracertypes.CUDATracer) // USDT support requires cookies
	}
	trc, err := tracer.NewTracer(ctx, &tracer.Config{
		Reporter:          p.reporter,
		Intervals:         intervals,
		IncludeTracers:    tracers,
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
	if tracers.Has(tracertypes.CUDATracer) {
		if err = trc.StartGPUProfiling(ctx, p.reporter); err != nil {
			return fmt.Errorf("faield start gpu profiling: %v", err)
		}
	}
	var state = new(State) // start with empty
	enter := time.Now()
	for {
		select {
		case <-time.After(time.Second):
		case <-ctx.Done():
			return nil
		}
		cur := p.ctrl.GetProfilingStat(state)
		if !cur.Enable() {
			log.Infof("profiling stopped,duration of this run: %s", time.Since(enter))
			return nil
		}
		p.reporter.SetInterval(cur.interval)
		var logMessages []string
		if cur.interval != state.interval {
			logMessages = append(logMessages, fmt.Sprintf("report-interval(%s->%s)", state.interval, cur.interval))
		}
		if cur.cpu.OffThreshold != state.cpu.OffThreshold {
			if err = trc.StartOffCPUProfiling(uint32(cur.cpu.OffThreshold)); err != nil {
				return fmt.Errorf("failed to start off-cpu profiling: %v", err)
			}
			msg := fmt.Sprintf("off-cpu(%.2f%%->%.2f%%)%s",
				float32(state.cpu.OffThreshold)/10, float32(cur.cpu.OffThreshold)/10,
				actionSymbol(state.cpu.OffThreshold, cur.cpu.OffThreshold),
			)
			logMessages = append(logMessages, msg)
		}

		if cur.cpu.OnFrequency != state.cpu.OnFrequency {
			p.reporter.SetOnCPUFreq(cur.cpu.OnFrequency)
			if err = trc.StartOnCpuProfiling(cur.cpu.OnFrequency); err != nil {
				return fmt.Errorf("failed to start on-cpu profiling: %v", err)
			}
			msg := fmt.Sprintf("on-cpu(%dHz->%dHz)%s",
				state.cpu.OnFrequency, cur.cpu.OnFrequency, actionSymbol(state.cpu.OnFrequency, cur.cpu.OnFrequency))
			logMessages = append(logMessages, msg)
		}
		if cur.memory.Block != state.memory.Block {
			if err = trc.StartMemProfiling(cur.memory.Block); err != nil {
				return err
			}
			msg := fmt.Sprintf("heap-block(%dB->%dB)%s",
				state.memory.Block, cur.memory.Block, actionSymbol(state.memory.Block, cur.memory.Block))
			logMessages = append(logMessages, msg)
		}
		if gpu.GPU.Switch(cur.gpu.HostAPI, cur.gpu.Kernel) {
			msg := fmt.Sprintf("gpu-switch(host-api=%t->%t, kernel=%t->%t)",
				state.gpu.HostAPI, cur.gpu.HostAPI, state.gpu.Kernel, cur.gpu.Kernel)
			logMessages = append(logMessages, msg)
		}
		add, remove := state.cpu.PIDs.Compare(cur.cpu.PIDs)
		if err = trc.UpdateTargetPIDs(add, remove); err != nil {
			cur.cpu.PIDs = state.cpu.PIDs // reset to prev
			log.Warnf("failed to update target pids: %v", err)
		} else if len(add) > 0 || len(remove) > 0 {
			logMessages = append(logMessages, fmt.Sprintf("cpu-PID(%s)", state.cpu.PIDs.diff(cur.cpu.PIDs)))
		}
		add, remove = state.memory.PIDs.Compare(cur.memory.PIDs)
		trc.UpdateMemTargetPIDs(cur.memory.Disable, add, remove)
		if len(add) > 0 || len(remove) > 0 {
			logMessages = append(logMessages, fmt.Sprintf("memory-PID(%s)", state.memory.PIDs.diff(cur.memory.PIDs)))
		}
		if !maps.Equal(state.memory.Disable, cur.memory.Disable) {
			logMessages = append(logMessages, fmt.Sprintf("disable-memory-interpreter(%v)", cur.memory.Disable))
		}

		if len(logMessages) > 0 {
			log.Infof("switch profiling state: %s", strings.Join(logMessages, ", "))
		}
		state = cur
	}
}

func actionSymbol[T constraints.Integer](from, to T) string {
	switch {
	case from == 0 && to > 0:
		return "+"
	case from > 0 && to == 0:
		return "-"
	case from < to:
		return "↑"
	case from > to:
		return "↓"
	default:
		return ""
	}
}
