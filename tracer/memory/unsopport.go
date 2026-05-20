package memory

type unsupportedInterpreter struct{}

var _ memoryInterpreter = (*unsupportedInterpreter)(nil)

func newUnsupportedInterpreter() memoryInterpreter { return new(unsupportedInterpreter) }

func (u *unsupportedInterpreter) Close() error { return nil }
