package memory

import (
	"errors"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type cLikeInterpreter struct {
	links []link.Link
}

var _ memoryInterpreter = (*cLikeInterpreter)(nil)

func newCLikeInterpreter(filename string, pid uint32, progs map[string]*cebpf.Program) (memoryInterpreter, error) {
	type entrypoint struct {
		symbol      string
		enter, exit string
		mayFail     bool
	}
	var entries = []entrypoint{
		{"malloc", "malloc_enter", "malloc_exit", false},
		{"calloc", "calloc_enter", "calloc_exit", false},
		{"realloc", "realloc_enter", "realloc_exit", false},
		{"mmap", "mmap_enter", "mmap_exit", true},
		{"posix_memalign", "posix_memalign_enter", "posix_memalign_exit", false},
		{"valloc", "valloc_enter", "valloc_exit", true},
		{"memalign", "memalign_enter", "memalign_exit", false},
		/* pvalloc在arm64上不存在,不需要挂载 */
		{"pvalloc", "pvalloc_enter", "pvalloc_exit", true},
		{"aligned_alloc", "aligned_alloc_enter", "aligned_alloc_exit", true},
		{"free", "free_enter", "", false},
		{"munmap", "munmap_enter", "", true},
	}
	exe, err := link.OpenExecutable(filename)
	if err != nil {
		return nil, err
	}
	clink := &cLikeInterpreter{}
	defer func() {
		if err != nil {
			_ = clink.Close()
		}
	}()
	opt := &link.UprobeOptions{PID: int(pid)}
	for _, entry := range entries {
		var enter, exit link.Link
		if enter, err = exe.Uprobe(entry.symbol, progs[entry.enter], opt); err != nil {
			if !entry.mayFail {
				return nil, err
			}
			err = nil
		}
		if enter != nil {
			clink.links = append(clink.links, enter)
		}
		if entry.exit == "" {
			continue
		}
		if exit, err = exe.Uretprobe(entry.symbol, progs[entry.exit], opt); err != nil {
			if !entry.mayFail {
				return nil, err
			}
			err = nil
		}
		if exit != nil {
			clink.links = append(clink.links, exit)
		}
	}
	return clink, nil
}

func (c *cLikeInterpreter) Close() error {
	var errs []error
	for _, lnk := range c.links {
		errs = append(errs, lnk.Close())
	}
	return errors.Join(errs...)
}
