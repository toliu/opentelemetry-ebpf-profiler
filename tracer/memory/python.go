package memory

import (
	"errors"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"go.opentelemetry.io/ebpf-profiler/libpf"
)

type pythonInterpreter struct {
	links []link.Link
}

var _ memoryInterpreter = (*pythonInterpreter)(nil)

func newPythonInterpreter(filename string, pid uint32, progs map[string]*cebpf.Program) (memoryInterpreter, error) {
	exe, err := link.OpenExecutable(filename)
	if err != nil {
		return nil, err
	}
	attach := map[string][2]string{
		`PyObject_Malloc`:  {`PyObject_Malloc_enter`, `PyObject_Malloc_exit`},
		`PyObject_Calloc`:  {`PyObject_Calloc_enter`, `PyObject_Calloc_exit`},
		`PyObject_Realloc`: {`PyObject_Realloc_enter`, `PyObject_Realloc_exit`},
		`PyObject_Free`:    {`PyObject_Free_enter`, ``},
	}
	opt := &link.UprobeOptions{PID: int(pid)}
	pi := &pythonInterpreter{}
	defer func() {
		if err != nil {
			_ = pi.Close()
		}
	}()
	for symbol, pname := range attach {
		var uprobe, uretprobe link.Link
		if uprobe, err = exe.Uprobe(symbol, progs[pname[0]], opt); err != nil {
			return nil, err
		}
		pi.links = append(pi.links, uprobe)
		if len(pname[1]) == 0 {
			continue
		}
		if uretprobe, err = exe.Uretprobe(symbol, progs[pname[1]], opt); err != nil {
			return nil, err
		}
		pi.links = append(pi.links, uretprobe)
	}
	return pi, nil
}

func (p *pythonInterpreter) Close() error {
	var errs []error
	for _, lnk := range p.links {
		errs = append(errs, lnk.Close())
	}
	return errors.Join(errs...)
}

func (p *pythonInterpreter) Type() libpf.InterpreterType { return libpf.Python }
