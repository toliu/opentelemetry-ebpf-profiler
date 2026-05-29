package colasoft

import (
	"cmp"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"go.opentelemetry.io/collector/pdata/pprofile"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/support"
)

type (
	PIDState map[uint32]bool
	CPUState struct {
		OnFrequency, OffThreshold int64
		PIDs                      PIDState
	}
	MemoryState struct {
		Block   uint64
		Disable map[libpf.InterpreterType]bool
		PIDs    PIDState
	}
	AcceleratorState struct {
		HostAPI   bool
		Kernel    bool
		Threshold uint32
		PIDs      PIDState
	}
	State struct {
		running     bool
		interval    time.Duration
		CPU         CPUState
		Memory      MemoryState
		Accelerator AcceleratorState
	}
	Controller interface {
		samples.SampleAttrProducer
		ExecutableKnown(fileID libpf.FileID) bool
		ExecutableMetadata(args *reporter.ExecutableMetadataArgs)

		GetProfilingStat(prev *State) (expect *State)
		Demangle(string) string // 用于给CUDA的kernel函数解码
		TimeOffset() time.Duration
		ConsumeProfiles(tds map[uint32]pprofile.Profiles)
		ConsumeTimeEvent(timeline *support.Timeline)
		ConsumeErrorEvent(evt *support.ErrorEvent)
		Symbolization(map[libpf.FrameID]*samples.SourceInfo)
	}
)

func NewState(running bool, interval time.Duration) *State {
	interval = max(cmp.Or(interval, time.Minute), time.Second) // 确保Interval有个默认值
	return &State{running: running, interval: interval}
}

func (s *State) WithCPUState(on, off int64, pids PIDState) *State {
	s.CPU.OnFrequency = on
	s.CPU.OffThreshold = off
	if s.CPU.Enable() {
		s.CPU.PIDs = maps.Clone(pids)
	}
	return s
}
func (s *State) WithMemoryState(block uint64, disable map[libpf.InterpreterType]bool, pids PIDState) *State {
	s.Memory.Block = block
	s.Memory.Disable = disable
	if s.Memory.Enable() {
		s.Memory.PIDs = maps.Clone(pids)
	}
	return s
}
func (s *State) WithAcceleratorState(hostAPI, kernel bool, threshold uint32, pids PIDState) *State {
	s.Accelerator.HostAPI = hostAPI
	s.Accelerator.Kernel = kernel
	s.Accelerator.Threshold = min(max(0, threshold), 1000) // 0~1000
	if s.Accelerator.Enable() {
		s.Accelerator.PIDs = maps.Clone(pids)
	}
	return s
}

func (s *State) Enable() bool {
	return s.running && cmp.Or(s.CPU.Enable(), s.Memory.Enable(), s.Accelerator.Enable())
}

func (c CPUState) Enable() bool         { return c.OnFrequency > 0 || c.OffThreshold > 0 }
func (m MemoryState) Enable() bool      { return m.Block > 0 }
func (g AcceleratorState) Enable() bool { return g.HostAPI || g.Kernel }

func (p PIDState) Compare(o PIDState) (add, remove []uint32) {
	for pid := range p {
		if _, ok := o[pid]; !ok {
			remove = append(remove, pid)
		}
	}
	for pid := range o {
		if _, ok := p[pid]; !ok {
			add = append(add, pid)
		}
	}
	return
}

func (p PIDState) String() string {
	return fmt.Sprintf("%v", slices.Sorted(maps.Keys(p)))
}

func (p PIDState) diff(o PIDState) string {
	pids := make(map[uint32]bool)
	for pid := range p {
		pids[pid] = true
	}
	for pid := range o {
		pids[pid] = true
	}
	var desc []string
	for _, pid := range slices.Sorted(maps.Keys(pids)) {
		var symbol string
		if p[pid] && !o[pid] {
			symbol = "-"
		} else if !p[pid] && o[pid] {
			symbol = "+"
		}
		desc = append(desc, fmt.Sprintf("%s%d", symbol, pid))
	}

	return strings.Join(desc, ",")
}
