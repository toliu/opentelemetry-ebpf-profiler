package gpu

import (
	"errors"
	"unsafe"

	cebpf "github.com/cilium/ebpf"
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
		pid  libpf.PID
	}
)

var _ interpreter.Instance = (*instance)(nil)

func (i *instance) Detach(_ interpreter.EbpfHandler, _ libpf.PID) error {
	g := i.d.g
	g.mu.Lock()
	defer g.mu.Unlock()

	// Remove this pid's spec entries from __bpf_usdt_specs (keyed by
	// pid<<32|spec_id). Deleting an entry no other process reloaded is harmless
	// and self-heals when that pid attaches again.
	for trap := range i.d.probes {
		key := uint64(i.pid)<<32 | uint64(trap.specID())
		if err := g.usdtSpec.Delete(unsafe.Pointer(&key)); err != nil && !errors.Is(err, cebpf.ErrKeyNotExist) {
			log.Errorf("[gpu] error deleting spec for pid %d trap %s: %s", i.pid, trap, err)
		}
	}

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