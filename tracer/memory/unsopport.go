package memory

import "go.opentelemetry.io/ebpf-profiler/libpf"

type unsupportedInterpreter struct{}

var _ memoryInterpreter = (*unsupportedInterpreter)(nil)

func newUnsupportedInterpreter() memoryInterpreter { return new(unsupportedInterpreter) }

func (u *unsupportedInterpreter) Close() error                { return nil }
func (u *unsupportedInterpreter) Type() libpf.InterpreterType { return libpf.UnknownInterp }
