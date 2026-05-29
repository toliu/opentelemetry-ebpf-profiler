// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package samples // import "go.opentelemetry.io/ebpf-profiler/reporter/samples"

import (
	"go.opentelemetry.io/ebpf-profiler/libpf"
)

type (
	metaValue     interface{ isMetaValue() }
	MetaValueHeap struct {
		Addr, Bytes, Count int64
	}
	MetaValueAI struct {
		Stream, Device, Graph, CorrelationID uint32
		GraphNodeID                          uint64
		Host, Kernel                         struct {
			End, Duration int64
		}
	}
	MetaValueSynchronize struct {
		metaValue
		Duration int64
	}
	MetaValueOffCPU struct {
		OffTime int64
	}
)

var _ metaValue = (*MetaValueHeap)(nil)
var _ metaValue = (*MetaValueAI)(nil)
var _ metaValue = (*MetaValueOffCPU)(nil)
var _ metaValue = (*MetaValueSynchronize)(nil)

func (m *MetaValueHeap) isMetaValue() {}
func (m *MetaValueHeap) IsFree() bool { return m.Count == 0 }

func (m *MetaValueAI) isMetaValue()     {}
func (m *MetaValueOffCPU) isMetaValue() {}

type TraceEventMeta struct {
	Timestamp      libpf.UnixTime64
	Comm           string
	ProcessName    string
	ExecutablePath string
	APMServiceName string
	PID, TID       libpf.PID
	CPU            int
	Origin         libpf.Origin
	Value          metaValue
	//OffTime        int64
}

// AISeries holds one of the two independently-collected AI observation series.
// The host-api switch produces ai-launch, the kernel switch produces
// ai-execution; keeping them apart lets the generation layer emit one column per
// active switch and drop the other when a switch is off.
type AISeries struct {
	Timestamps []uint64
	Durations  []int64
}

// TraceEvents holds known information about a trace.
type TraceEvents struct {
	Files              []libpf.FileID
	Linenos            []libpf.AddressOrLineno
	FrameTypes         []libpf.FrameType
	MappingStarts      []libpf.Address
	MappingEnds        []libpf.Address
	MappingFileOffsets []uint64
	Timestamps         []uint64 // in nanoseconds
	Values             []int64  // 不同Origin对应不同的value

	// AI (TraceOriginCuda) series, stored apart from Timestamps/Values because
	// the two GPU switches are toggled independently.
	AIHost   AISeries // ai-launch
	AIKernel AISeries // ai-execution

	//OffTimes []int64 // in nanoseconds
	//MemAlloc []int64
}

// TraceAndMetaKey is the deduplication key for samples. This **must always**
// contain all trace fields that aren't already part of the trace hash to ensure
// that we don't accidentally merge traces with different fields.
type TraceAndMetaKey struct {
	Hash libpf.TraceHash
	// comm and apmServiceName are provided by the eBPF programs
	Comm           string
	ApmServiceName string
	// containerID is annotated based on PID information
	ContainerID string
	Pid         int64
	// Process name is retrieved from /proc/PID/comm
	ProcessName string
	// Executable path is retrieved from /proc/PID/exe
	ExecutablePath string
	// ExtraMeta stores extra meta info that may have been produced by a
	// `SampleAttrProducer` instance. May be nil.
	ExtraMeta any
}

// KeyToEventMapping supports temporary mapping traces to additional information.
type KeyToEventMapping map[TraceAndMetaKey]*TraceEvents

// AttrKeyValue is a helper to populate Profile.attribute_table.
type AttrKeyValue[T string | int64] struct {
	Key string
	// Set to true for OTel SemConv attributes with requirement level: Required
	Required bool
	Value    T
}

// ExecInfo enriches an executable with additional metadata.
type ExecInfo struct {
	FileName   string
	GnuBuildID string
}

// SourceInfo allows mapping a frame to its source origin.
type SourceInfo struct {
	LineNumber     libpf.SourceLineno
	FunctionOffset uint32
	FunctionName   string
	FilePath       string
}

// FuncInfo is a helper to construct profile.Function messages.
type FuncInfo struct {
	Name     string
	FileName string
}
