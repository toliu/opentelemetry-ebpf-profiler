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
	GPUState struct {
		HostAPI bool
		Kernel  bool
	}
	State struct {
		running  bool
		interval time.Duration
		cpu      CPUState
		memory   MemoryState
		gpu      GPUState
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
	s.cpu.OnFrequency = on
	s.cpu.OffThreshold = off
	if s.cpu.Enable() {
		s.cpu.PIDs = maps.Clone(pids)
	}
	return s
}
func (s *State) WithMemoryState(block uint64, disable map[libpf.InterpreterType]bool, pids PIDState) *State {
	s.memory.Block = block
	s.memory.Disable = disable
	if s.memory.Enable() {
		s.memory.PIDs = maps.Clone(pids)
	}
	return s
}
func (s *State) WithGPUState(hostAPI, kernel bool) *State {
	s.gpu.HostAPI = hostAPI
	s.gpu.Kernel = kernel
	return s
}

func (s *State) Enable() bool { return s.running && (s.cpu.Enable() || s.memory.Enable()) }

func (c CPUState) Enable() bool    { return c.OnFrequency > 0 || c.OffThreshold > 0 }
func (m MemoryState) Enable() bool { return m.Block > 0 }
func (g GPUState) Enable() bool    { return g.HostAPI || g.Kernel }

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
