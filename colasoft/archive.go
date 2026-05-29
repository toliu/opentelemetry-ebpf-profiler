package colasoft

import (
	"io/fs"

	"go.opentelemetry.io/ebpf-profiler/vendoring"
)

type archiveType string

const CUPTI archiveType = "libcolacupti.so"
const MSPTI archiveType = "libcolamspti.so"

func Archive(typ archiveType) (fs.File, error) { return vendoring.Open(string(typ)) }
