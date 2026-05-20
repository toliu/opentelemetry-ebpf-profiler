package colasoft

import (
	"time"

	"go.opentelemetry.io/collector/pdata/pprofile"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
)

type (
	PIDState map[uint32]bool
	State    struct {
		Overload bool
		Interval time.Duration
		CPU      struct {
			OnFrequency, OffThreshold int64
			PIDs                      PIDState
		}
		Memory struct {
			Block uint64
			PIDs  PIDState
		}
	}
	Controller interface {
		samples.SampleAttrProducer
		ExecutableKnown(fileID libpf.FileID) bool
		ExecutableMetadata(args *reporter.ExecutableMetadataArgs)

		State() State
		TimeOffset() time.Duration
		ConsumeProfiles(tds map[uint32]pprofile.Profiles)
		Symbolization(map[libpf.FrameID]*samples.SourceInfo)
	}
)

func (s State) Enable() bool {
	enable := s.CPU.OnFrequency > 0 || s.CPU.OffThreshold > 0 || s.Memory.Block > 0
	return !s.Overload && enable
}

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
