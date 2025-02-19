package colasoft

import (
	"context"
	"github.com/toliu/opentelemetry-ebpf-profiler/libpf"
	"github.com/toliu/opentelemetry-ebpf-profiler/reporter"
	"github.com/toliu/opentelemetry-ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/collector/pdata/pprofile"
)

type (
	SymbolReporter interface {
		samples.SampleAttrProducer

		ExecutableKnown(fileID libpf.FileID) bool
		ExecutableMetadata(args *reporter.ExecutableMetadataArgs)

		ConsumeProfilesFunc(ctx context.Context, td pprofile.Profiles) error
	}

	noFrameOpSymbolReporter struct{ SymbolReporter }
)

var _ reporter.SymbolReporter = (*noFrameOpSymbolReporter)(nil)

func (n noFrameOpSymbolReporter) FrameKnown(libpf.FrameID) bool             { return false }
func (n noFrameOpSymbolReporter) FrameMetadata(*reporter.FrameMetadataArgs) {}
