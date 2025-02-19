package reporter

import (
	"github.com/toliu/opentelemetry-ebpf-profiler/libpf"
	"github.com/toliu/opentelemetry-ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/collector/consumer/xconsumer"
	"time"
)

type (
	ColaSoft struct {
		*CollectorReporter
		sr SymbolReporter
	}
)

var _ Reporter = (*ColaSoft)(nil)

func NewColaSoft(
	freq int, interval time.Duration,
	extra samples.SampleAttrProducer,
	f xconsumer.ConsumeProfilesFunc,
	sr SymbolReporter,
) (*ColaSoft, error) {
	consumer, err := xconsumer.NewProfiles(f)
	if err != nil {
		return nil, err
	}

	cfg := &Config{
		ExecutablesCacheElements: 16384,
		FramesCacheElements:      65536,
		CGroupCacheElements:      1024,
		SamplesPerSecond:         freq,
		ReportInterval:           interval,
		ExtraSampleAttrProd:      extra,
	}

	r, err := NewCollector(cfg, consumer)
	if err != nil {
		return nil, err
	}
	return &ColaSoft{CollectorReporter: r, sr: sr}, nil
}

func (c *ColaSoft) ExecutableKnown(fileID libpf.FileID) bool {
	return c.CollectorReporter.ExecutableKnown(fileID) || c.sr.ExecutableKnown(fileID)
}
func (c *ColaSoft) ExecutableMetadata(args *ExecutableMetadataArgs) {
	if args.Interp == libpf.Native {
		c.sr.ExecutableMetadata(args)
	}
	c.CollectorReporter.ExecutableMetadata(args)
}
