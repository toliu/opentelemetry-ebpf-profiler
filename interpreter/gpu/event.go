package gpu

import (
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/support"
)

type (
	traceEvent struct {
		cudaFrameIndex int
		correlationID  uint32
		trace          *libpf.Trace
		meta           *samples.TraceEventMeta
	}
	launchState struct {
		host    *support.Timeline
		kernels []*support.Timeline
	}
)
