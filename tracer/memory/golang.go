package memory

import (
	"debug/buildinfo"
	"runtime"
	"strconv"
	"strings"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type golangInterpreter struct {
	link link.Link
}

var _ memoryInterpreter = (*golangInterpreter)(nil)

func newGolangInterpreter(filename string, pid uint32, progs map[string]*cebpf.Program) (memoryInterpreter, error) {
	bi, err := buildinfo.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	ver := strings.TrimPrefix(bi.GoVersion, `Go cmd/compile`)
	var major, minor int
	if strings.HasPrefix(ver, "go") {
		v := strings.SplitN(ver[2:], ".", 3)
		major, err = strconv.Atoi(v[0])
		if err != nil {
			return nil, err
		}

		if len(v) >= 2 {
			minor, err = strconv.Atoi(v[1])
			if err != nil {
				return nil, err
			}
		}
	}
	if major == 0 && minor == 0 {
		return newUnsupportedInterpreter(), nil // go version miss
	}
	exe, err := link.OpenExecutable(filename)
	if err != nil {
		return nil, err
	}

	prog := "mallocgc_register_enter"
	if (runtime.GOARCH == "amd64" && minor < 17) || (runtime.GOARCH == "arm64" && minor < 18) {
		prog = "mallocgc_stack_enter"
	}
	opt := &link.UprobeOptions{PID: int(pid)}
	lnk, err := exe.Uprobe(`runtime.mallocgc`, progs[prog], opt)
	if err != nil {
		return nil, err
	}
	return &golangInterpreter{link: lnk}, nil
}

func (g *golangInterpreter) Close() error { return g.link.Close() }
