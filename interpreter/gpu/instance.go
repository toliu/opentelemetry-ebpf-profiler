package gpu

import (
	log "github.com/sirupsen/logrus"

	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/util"
)

type (
	// instance is the CUDA interpreter instance
	instance struct {
		interpreter.InstanceStubs
		d    *data
		odfi util.OnDiskFileIdentifier
	}
)

var _ interpreter.Instance = (*instance)(nil)

func (i *instance) Detach(_ interpreter.EbpfHandler, _ libpf.PID) error {
	g := i.d.g
	g.mu.Lock()
	defer g.mu.Unlock()
	if le := g.linked[i.odfi]; le != nil {
		le.refs--
		if le.refs <= 0 {
			log.Debugf("[gpu] last ref for %s (dev=%d ino=%d), unloading probes", i.d.path, i.odfi.DeviceID, i.odfi.InodeNum)
			if le.ProbeLinks != nil {
				if err := le.Unload(); err != nil {
					log.Errorf("[gpu] error closing usdt link: %s", err)
				}
			}
			delete(g.linked, i.odfi)
		}
	}
	return nil
}
