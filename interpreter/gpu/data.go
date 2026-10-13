package gpu

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"github.com/parca-dev/usdt"
	log "github.com/sirupsen/logrus"

	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
	"go.opentelemetry.io/ebpf-profiler/util"
)

type (
	data struct {
		g      *gpuTracer
		path   string
		probes map[usdtTrap]usdt.Probe
	}
)

var _ interpreter.Data = (*data)(nil)

func (d *data) Attach(_ interpreter.EbpfHandler, pid libpf.PID, _ libpf.Address, _ remotememory.RemoteMemory) (interpreter.Instance, error) {
	// Stat the path to get the current inode. Uprobe attachments are
	// inode-based, so we need a separate attachment per inode.
	path := fmt.Sprintf("/proc/%d/root/%s", pid, d.path)
	st, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("[gpu] stat %s: %w", path, err)
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok || sys == nil {
		return nil, fmt.Errorf("[gpu] failed to get stat_t for %s", path)
	}
	key := util.OnDiskFileIdentifier{DeviceID: sys.Dev, InodeNum: sys.Ino}

	g := d.g
	g.mu.Lock()
	defer g.mu.Unlock()
	le := g.linked[key]
	if le == nil {
		if le, err = g.attach(path, d.probes); err != nil {
			return nil, err
		}
		g.linked[key] = le
		log.Debugf("[gpu] USDT probes attached for %s (dev=%d ino=%d)", d.path, key.DeviceID, key.InodeNum)
	}
	le.refs++
	if err := d.writeSpecs(uint32(pid)); err != nil {
		return nil, err
	}
	return &instance{d: d, odfi: key, pid: pid}, nil
}

// writeSpecs parses each probe's USDT arguments and stores the resulting spec
// in __bpf_usdt_specs under key pid<<32|spec_id. It is called for every Attach
// (not just the first per inode) because the uprobe fires host-wide: each pid
// that shares the .so inode still needs its own spec entries to resolve
// arguments keyed by its tgid.
func (d *data) writeSpecs(pid uint32) error {
	for trap, probe := range d.probes {
		spec, err := usdt.ParseUSDTArguments(probe.Arguments)
		if err != nil {
			return fmt.Errorf("[gpu] parse USDT args for %s: %w", trap, err)
		}
		key := uint64(pid)<<32 | uint64(trap.specID())
		if err := d.g.usdtSpec.Put(unsafe.Pointer(&key), usdt.SpecToBytes(spec)); err != nil {
			return fmt.Errorf("[gpu] store spec for %s: %w", trap, err)
		}
	}
	return nil
}
