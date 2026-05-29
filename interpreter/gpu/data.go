package gpu

import (
	"fmt"
	"os"
	"syscall"

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
	return &instance{d: d, odfi: key}, nil
}
