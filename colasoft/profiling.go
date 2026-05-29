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
	actual   *State
}

func Setup(ctx context.Context, ctrl Controller) {
	p := &profiling{
		ctrl:     ctrl,
		reporter: newColaSoftReporter(ctx, ctrl),
		actual:   new(State),
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
			p.actual.Error = err
		} else {
			interval = time.Second
		}
		time.Sleep(interval)
	}
}

func (p *profiling) start(parent context.Context) error {
	if !p.ctrl.GetProfilingStat(p.actual).Enable() {
		return nil
	}
	defer p.actual.reset()

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
			return fmt.Errorf("faield start Accelerator profiling: %v", err)
		}
	}
	p.actual.reset()
	enter := time.Now()
	for {
		select {
		case <-time.After(time.Second):
		case <-ctx.Done():
			return nil
		}
		cur := p.ctrl.GetProfilingStat(p.actual)
		if !cur.Enable() {
			log.Infof("profiling stopped,duration of this run: %s", time.Since(enter))
			return nil
		}
		p.reporter.SetInterval(cur.interval)
		var logMessages []string
		if cur.interval != p.actual.interval {
			logMessages = append(logMessages, fmt.Sprintf("report-interval(%s->%s)", p.actual.interval, cur.interval))
		}
		if cur.CPU.OffThreshold != p.actual.CPU.OffThreshold {
			if err = trc.StartOffCPUProfiling(uint32(cur.CPU.OffThreshold)); err != nil {
				return fmt.Errorf("failed to start off-cpu profiling: %v", err)
			}
			msg := fmt.Sprintf("off-cpu(%.2f%%->%.2f%%)%s",
				float32(p.actual.CPU.OffThreshold)/10, float32(cur.CPU.OffThreshold)/10,
				actionSymbol(p.actual.CPU.OffThreshold, cur.CPU.OffThreshold),
			)
			logMessages = append(logMessages, msg)
		}

		if cur.CPU.OnFrequency != p.actual.CPU.OnFrequency {
			p.reporter.SetOnCPUFreq(cur.CPU.OnFrequency)
			if err = trc.StartOnCpuProfiling(cur.CPU.OnFrequency); err != nil {
				return fmt.Errorf("failed to start on-cpu profiling: %v", err)
			}
			msg := fmt.Sprintf("on-cpu(%dHz->%dHz)%s",
				p.actual.CPU.OnFrequency, cur.CPU.OnFrequency, actionSymbol(p.actual.CPU.OnFrequency, cur.CPU.OnFrequency))
			logMessages = append(logMessages, msg)
		}
		if cur.Memory.Block != p.actual.Memory.Block {
			if err = trc.StartMemProfiling(cur.Memory.Block); err != nil {
				return err
			}
			msg := fmt.Sprintf("heap-block(%dB->%dB)%s",
				p.actual.Memory.Block, cur.Memory.Block, actionSymbol(p.actual.Memory.Block, cur.Memory.Block))
			logMessages = append(logMessages, msg)
		}
		if gpu.GPU.Switch(cur.Accelerator.HostAPI, cur.Accelerator.Kernel, cur.Accelerator.Threshold, cur.Accelerator.PIDs) {
			msg := fmt.Sprintf("accelerator(host=%t->%t, kernel=%t->%t, threshold=%.1f%%->%.1f%%)",
				p.actual.Accelerator.HostAPI,
				cur.Accelerator.HostAPI,
				p.actual.Accelerator.Kernel,
				cur.Accelerator.Kernel,
				float32(p.actual.Accelerator.Threshold)/10,
				float32(cur.Accelerator.Threshold)/10,
			)
			logMessages = append(logMessages, msg)
		}
		add, remove := p.actual.Accelerator.PIDs.Compare(cur.Accelerator.PIDs)
		if len(add) > 0 || len(remove) > 0 {
			logMessages = append(logMessages, fmt.Sprintf("Accelerator-PID(%s)", p.actual.Accelerator.PIDs.diff(cur.Accelerator.PIDs)))
		}
		add, remove = p.actual.CPU.PIDs.Compare(cur.CPU.PIDs)
		if err = trc.UpdateTargetPIDs(add, remove); err != nil {
			cur.CPU.PIDs = p.actual.CPU.PIDs // reset to prev
			log.Warnf("failed to update target pids: %v", err)
		} else if len(add) > 0 || len(remove) > 0 {
			logMessages = append(logMessages, fmt.Sprintf("cpu-PID(%s)", p.actual.CPU.PIDs.diff(cur.CPU.PIDs)))
		}
		add, remove = p.actual.Memory.PIDs.Compare(cur.Memory.PIDs)
		trc.UpdateMemTargetPIDs(cur.Memory.Disable, add, remove)
		if len(add) > 0 || len(remove) > 0 {
			logMessages = append(logMessages, fmt.Sprintf("memory-PID(%s)", p.actual.Memory.PIDs.diff(cur.Memory.PIDs)))
		}
		if !maps.Equal(p.actual.Memory.Disable, cur.Memory.Disable) {
			logMessages = append(logMessages, fmt.Sprintf("disable-memory-interpreter(%v)", cur.Memory.Disable))
		}

		if len(logMessages) > 0 {
			log.Infof("switch profiling state: %s", strings.Join(logMessages, ", "))
		}
		p.actual = cur
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
