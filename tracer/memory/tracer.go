package memory

import (
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync/atomic"

	cebpf "github.com/cilium/ebpf"
	log "github.com/sirupsen/logrus"

	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/xsync"
	pm "go.opentelemetry.io/ebpf-profiler/processmanager"
	"go.opentelemetry.io/ebpf-profiler/reporter"
)

type (
	memoryInterpreter interface {
		io.Closer
	}

	Tracer struct {
		progs map[string]*cebpf.Program

		pm       *pm.ProcessManager
		reporter reporter.SymbolReporter
		traceOut chan<- *host.Trace

		block *atomic.Uint64
		pids  xsync.RWMutex[map[uint32]memoryInterpreter]
	}
)

func NewMemoryTracer(mgr *pm.ProcessManager, rpt reporter.SymbolReporter, progs map[string]*cebpf.Program) *Tracer {
	return &Tracer{
		pm:       mgr,
		reporter: rpt,
		pids:     xsync.NewRWMutex(make(map[uint32]memoryInterpreter)),
		progs:    progs,
		block:    new(atomic.Uint64),
	}
}

func (t *Tracer) SetTraceOut(out chan<- *host.Trace) { t.traceOut = out }
func (t *Tracer) SetBlock(block uint64)              { t.block.Store(block) }

func (t *Tracer) UpdateTargetPID(add, remove []uint32) {
	pids := t.pids.WLock()
	defer t.pids.WUnlock(&pids)
	for _, pid := range add {
		if _, ok := (*pids)[pid]; !ok {
			(*pids)[pid] = nil
		}
	}

	for _, pid := range remove {
		if mi, ok := (*pids)[pid]; ok {
			if mi != nil {
				_ = mi.Close()
			}
			delete(*pids, pid)
		}
	}
}

func (t *Tracer) MonitorMemProfilePids(keys *[]uint32) {
	if t.block.Load() == 0 {
		return
	}
	pids := t.pids.WLock()
	defer t.pids.WUnlock(&pids)
	var trigger []uint32
	for pid, mi := range *pids {
		if mi != nil {
			continue
		}
		minfo := t.pm.GetMemProfileInfo(libpf.PID(pid))
		if minfo == nil {
			trigger = append(trigger, pid)
			continue
		}
		mi = newUnsupportedInterpreter()
		var err error
		switch minfo.Lang {
		case libpf.Python:
			if minfo.LibPythonPath == "" {
				continue
			}
			mi, err = newPythonInterpreter(minfo.LibPythonPath, pid, t.progs)
		case libpf.Golang:
			if minfo.ExecAbsPath == "" {
				continue
			}
			mi, err = newGolangInterpreter(minfo.ExecAbsPath, pid, t.progs)
		case libpf.PHP, libpf.PHPJIT, libpf.Kernel, libpf.Ruby, libpf.Perl, libpf.V8, libpf.Dotnet:
			mi = newUnsupportedInterpreter()
		case libpf.HotSpot:
			if t.traceOut != nil {
				if minfo.MajorVersion == 0 {
					if lanV := strings.Split(fmt.Sprintf("%s", minfo.ItData), " "); len(lanV) > 1 {
						for _, s := range lanV[1:] {
							if ver := strings.Split(s, "."); len(ver) > 1 {
								minfo.MajorVersion, _ = strconv.Atoi(ver[0])
								minfo.MinorVersion, _ = strconv.Atoi(ver[1])
								break
							}
						}
					}
				}
				// 需要java 11及以上才支持
				if minfo.MajorVersion < 1 && minfo.MinorVersion < 11 {
					log.Infof("unsupported hotspot-memprofile for pid(%d): jdk-%d.%d", pid, minfo.MajorVersion, minfo.MinorVersion)
					mi = newUnsupportedInterpreter()
				} else {
					mi, err = newHotspotInterpreter(pid, t.block, t.reporter, t.traceOut)
				}
			} else {
				err = fmt.Errorf("no trace channel for jvm pid(%d)", pid)
			}
		default:
			if minfo.LibcPath == "" {
				continue
			}
			mi, err = newCLikeInterpreter(minfo.LibcPath, pid, t.progs)
		}
		if err != nil {
			log.Warnf("failed to new interpreter for pid(%d): %v", pid, err)
			continue
		}

		(*pids)[pid] = mi
	}
	if len(trigger) > 0 {
		log.Infof("apply mem profiling target pids: %v", trigger)
		*keys = append(*keys, trigger...)
	}
}

func (t *Tracer) Close() error {
	pids := t.pids.WLock()
	defer t.pids.WUnlock(&pids)
	var errs []error
	for _, mi := range *pids {
		if mi == nil {
			continue
		}
		errs = append(errs, mi.Close())
	}
	*pids = make(map[uint32]memoryInterpreter)
	return errors.Join(errs...)
}
