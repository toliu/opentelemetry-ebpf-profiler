package memory

import "C"
import (
	"bufio"
	"bytes"
	"context"
	"embed"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/zeebo/xxh3"
	profilesv1 "go.opentelemetry.io/proto/otlp/profiles/v1development"
	"google.golang.org/protobuf/proto"

	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/support"
	"go.opentelemetry.io/ebpf-profiler/times"
)

type hotspotInterpreter struct {
	cancel          context.CancelFunc
	pid, nspid      int
	tmpdir, library string
	block           *atomic.Uint64
	out             chan<- *host.Trace
	reporter        reporter.SymbolReporter
}

//go:embed hotspot_profiler_linux_arm64.so hotspot_profiler_linux_amd64.so
var hotspotProfilerLibrary embed.FS

var _ memoryInterpreter = (*hotspotInterpreter)(nil)

func newHotspotInterpreter(pid uint32, block *atomic.Uint64, rpt reporter.SymbolReporter, out chan<- *host.Trace) (memoryInterpreter, error) {
	hi := &hotspotInterpreter{
		pid:      int(pid),
		nspid:    int(pid),
		block:    block,
		out:      out,
		tmpdir:   os.TempDir(),
		reporter: rpt,
	}
	pidProcDir := filepath.Join("/proc", fmt.Sprint(pid))
	// 获取该进程在容器内的PID
	if file, err := os.Open(filepath.Join(pidProcDir, "status")); err != nil {
		return nil, err
	} else {
		defer file.Close()
		reader := bufio.NewReader(file)
		var line []byte
		for {
			if line, _, err = reader.ReadLine(); err != nil {
				break
			}
			if !bytes.HasPrefix(line, []byte("NStgid:")) {
				continue
			}
			fields := bytes.Fields(line)
			if len(fields) < 2 {
				break
			}
			if hi.nspid, err = strconv.Atoi(string(fields[len(fields)-1])); err != nil {
				return nil, err
			}
			break
		}
	}
	tmpdir := filepath.Join(pidProcDir, "root", "tmp") // 如果是容器内tmp
	if _, err := os.Stat(tmpdir); err == nil {
		hi.tmpdir = tmpdir
	}
	libraryName := fmt.Sprintf("hotspot_profiler_linux_%s.so", runtime.GOARCH)
	hi.library = filepath.Join(hi.tmpdir, libraryName)
	if file, err := hotspotProfilerLibrary.Open(libraryName); err != nil {
		return nil, err
	} else {
		defer file.Close()
		var rewrite bool
		if stat, serr := os.Stat(hi.library); serr != nil {
			rewrite = true
		} else if fstat, ferr := file.Stat(); ferr == nil {
			rewrite = fstat.Size() != stat.Size()
		}
		if rewrite {
			dest, cerr := os.OpenFile(hi.library, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0777)
			if cerr != nil {
				return nil, cerr
			}
			defer dest.Close()
			if _, err = io.Copy(dest, file); err != nil {
				return nil, err
			}
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	hi.cancel = cancel
	go hi.start(ctx)
	return hi, nil
}

func (h *hotspotInterpreter) Close() error {
	h.cancel()
	return nil
}

func (h *hotspotInterpreter) Type() libpf.InterpreterType { return libpf.HotSpot }

func (h *hotspotInterpreter) start(ctx context.Context) {
	var interval = time.Second
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
		if err := h.tick(ctx); err != nil {
			log.Warnf("failed to start hotspot profiling with pid(%d): %v", h.pid, err)
			interval = min(interval*2, time.Second*40)
		} else {
			interval = time.Second
		}
	}
}

func (h *hotspotInterpreter) tick(ctx context.Context) error {
	block := h.block.Load()
	if block == 0 {
		return nil // stop memory profiling
	}
	start := fmt.Sprintf("start,event=alloc,alloc=%d", block)
	// 不需要手动停止，过一分钟后会自动退出
	if err := h.loadAgent(start); err != nil {
		return fmt.Errorf("failed to start profiling: %w", err)
	} else {
		log.Debugf("start hotspot mem profiling for pid(%d) with command: %s", h.pid, start)
	}
	for {
		select {
		case <-ctx.Done():
			log.Tracef("Context cancelled, stopping hotspot mem profiling")
			return nil
		case <-time.After(time.Second * 5):
			if err := h.dump(ctx); err != nil {
				return err
			}
			if block != h.block.Load() { // changed
				return nil // restart
			}
		}
	}
}

func (h *hotspotInterpreter) dump(ctx context.Context) error {
	pbFilename := fmt.Sprintf("asprof.%d.%d.pb", os.Getpid(), h.pid)
	logFilename := fmt.Sprintf("asprof-log.%d.%d.txt", os.Getpid(), h.pid)
	dump := fmt.Sprintf("dump,file=/tmp/%s,otlp,log=/tmp/%s", pbFilename, logFilename)
	// 执行 dump 命令
	if err := h.loadAgent(dump); err != nil {
		return fmt.Errorf("failed to dump hotspot profile with cmd %s: %v", dump, err)
	}
	// 等待文件写入完成, 动态库会把数据写入文件，然后我们读出来解析.
	// 时先这样最简单，如果要通过其他方式得改动态库代码。
	time.Sleep(200 * time.Millisecond)
	root, err := os.OpenRoot(h.tmpdir)
	if err != nil {
		return fmt.Errorf("failed to open hotspot profiling directory %s: %v", h.tmpdir, err)
	}
	defer root.Close()
	defer root.Remove(pbFilename)
	defer root.Remove(logFilename)

	data := new(profilesv1.ProfilesData)
	if content, rerr := root.ReadFile(pbFilename); rerr != nil {
		logData, _ := os.ReadFile(logFilename)
		log.Errorf("failed to read hotspot mem profiling dump data %v: %s", rerr, string(logData))
		return nil
	} else if err = proto.Unmarshal(content, data); err != nil { // 解析通用OTLP protobuf数据
		log.Errorf("Failed to unmarshal OTLP data: %v", err)
		return nil
	}
	dictionary := data.GetDictionary()
	locationTab := dictionary.GetLocationTable()
	functionTab := dictionary.GetFunctionTable()
	stringTab := dictionary.GetStringTable()
	for _, rp := range data.GetResourceProfiles() {
		for _, sp := range rp.GetScopeProfiles() {
			for _, prof := range sp.GetProfiles() {
				locationIndices := prof.GetLocationIndices()
				for _, sample := range prof.GetSample() {
					values := sample.GetValue()
					trace := &host.Trace{
						Comm:     "java",
						PID:      libpf.PID(h.pid),
						Origin:   support.TraceOriginHeap,
						OffTime:  values[0], // 内存申请次数
						MemAlloc: uint64(values[1]),
						//MemAddr:  uint64(ptr.mem_addr),
						KTime:  times.KTime(prof.GetTimeNanos()),
						CPU:    0,
						Frames: make([]host.Frame, sample.GetLocationsLength()),
					}
					startIndex := int(sample.GetLocationsStartIndex())
					hash := xxh3.New()
					_, _ = hash.WriteString(fmt.Sprint(h.pid))
					for i := range trace.Frames {
						locIndex := locationIndices[startIndex+i]
						loc := locationTab[locIndex]
						var filename, name string
						if len(loc.GetLine()) > 0 {
							line := loc.GetLine()[0]
							function := functionTab[line.GetFunctionIndex()]
							filename = stringTab[function.GetFilenameStrindex()]
							name = stringTab[function.GetNameStrindex()]
						}
						_, _ = hash.WriteString(filename)
						_, _ = hash.WriteString(name)
						fileId := libpf.FileIDFromKernelBuildID(filename)
						hostFileId := host.FileIDFromLibpf(fileId)
						//为了和后续的Symbol保持一致，截取64位作为fileId: processmanager/manager.go:284
						fileId = libpf.NewFileID(uint64(hostFileId), 0)
						frm := host.Frame{
							File:          hostFileId,
							Lineno:        libpf.AddressOrLineno(loc.GetAddress()), // always zero?
							Type:          libpf.HotSpotFrame,
							ReturnAddress: false,
						}
						if frm.Lineno == 0 { // 构造一个假的lineno，用于后续hash唯一索引
							frm.Lineno = libpf.AddressOrLineno(libpf.FileIDFromKernelBuildID(name).Hi())
						}
						frameId := libpf.NewFrameID(fileId, frm.Lineno)
						if !h.reporter.FrameKnown(frameId) {
							h.reporter.FrameMetadata(&reporter.FrameMetadataArgs{
								FrameID:      frameId,
								FunctionName: name,
								SourceFile:   filename,
							})
						}
						trace.Frames[i] = frm
					}
					trace.Hash = host.TraceHash(hash.Sum64())
					if !h.outputTrace(ctx, trace) {
						return nil
					}
				}
			}
		}
	}

	return nil
}

func (h *hotspotInterpreter) loadAgent(cmd string) error {
	newConn := func() (net.Conn, error) {
		unixSocketFilename := filepath.Join(h.tmpdir, fmt.Sprintf(".java_pid%d", h.nspid))
		return net.Dial("unix", unixSocketFilename)
	}
	conn, err := newConn()
	if err != nil {
		// 尝试在 /proc/pid/cwd 创建
		signFile := fmt.Sprintf("/proc/%d/cwd/.attach_pid%d", h.pid, h.nspid)
		if os.WriteFile(signFile, []byte(``), 0660) != nil {
			signFile = filepath.Join(h.tmpdir, fmt.Sprintf(".attach_pid%d", h.nspid))
			if err = os.WriteFile(signFile, []byte(``), 0660); err != nil {
				return err
			}
		}
		/*
			JVM 有一个内置的 Attach Listener 机制，但默认情况下这个监听线程可能没有启动。当 JVM 收到 SIGQUIT 信号时，它会：
			检查是否存在 .attach_pid<pid> 文件
			如果存在该文件，JVM 会启动 Attach Listener 线程
			Attach Listener 线程会创建一个 Unix Domain Socket（.java_pid<pid>）用于接收外部命令

			为什么是 SIGQUIT？
			SIGQUIT 在 JVM 中有特殊含义，通常用于触发线程 dump
			JVM 的 Signal Dispatcher 线程会捕获这个信号
			当检测到 .attach_pid 文件存在时，JVM 不会执行线程 dump，而是启动 Attach Listener
			这是 JVM 官方设计的 Attach 机制的一部分

			SIGQUIT 是安全的，JVM 专门处理了这个信号用于诊断和 attach 机制，不会导致进程退出。
			这也是为什么 async-profiler、jstack、jmap 等工具都使用这个信号来连接 JVM。
		*/
		var process *os.Process
		if process, err = os.FindProcess(h.pid); err != nil {
			return fmt.Errorf("failed to find process: %w", err)
		} else if err = process.Signal(syscall.SIGQUIT); err != nil { // 发送 SIGQUIT 信号给 JVM
			return fmt.Errorf("failed to send SIGQUIT: %w", err)
		}
		for try := 0; ; try++ {
			time.Sleep(time.Second)
			if conn, err = newConn(); err == nil && conn != nil {
				break
			}
			if try == 5 {
				return fmt.Errorf("failed to connect to socket: %w", err)
			}
		}
	}
	defer conn.Close()

	args := []string{
		"1", //协议版本
		"load",
		h.library,
		"true", // instrument = true
		cmd,
	}
	wr := bufio.NewWriter(conn)
	for _, arg := range args {
		if _, err = wr.WriteString(arg); err != nil {
			return err
		} else if err = wr.WriteByte(0); err != nil {
			return err
		}
	}
	if err = wr.Flush(); err != nil {
		return err
	}
	result := bytes.NewBuffer(nil)
	reader := bufio.NewReader(conn)
	for {
		var n int64
		if n, err = reader.WriteTo(result); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return err
		} else if n == 0 {
			break
		}
	}
	lines := strings.Split(result.String(), "\n")
	if len(lines) == 0 {
		return fmt.Errorf("invalid response: %s", lines)
	}
	// 第一行是返回码
	returnCode := strings.TrimSpace(lines[0])
	if returnCode != "0" {
		// 检查是否有 "return code:" 行
		const prefix = "return code:"
		for i, line := range lines {
			if !strings.HasPrefix(line, prefix) {
				continue
			}
			code := strings.TrimSpace(strings.TrimPrefix(line, prefix))
			if code != "0" {
				errorMsg := ""
				if i+1 < len(lines) {
					errorMsg = strings.Join(lines[i+1:], "\n")
				}
				return fmt.Errorf("agent returned error code %s: %s", code, errorMsg)
			}
			break
		}
	}
	return nil
}

func (h *hotspotInterpreter) outputTrace(ctx context.Context, trace *host.Trace) (ok bool) {
	// 退出profiling时，out channel会被其它协程关闭，捕获并直接退出即可
	defer func() { _ = recover() }()
	select {
	case <-ctx.Done():
	case h.out <- trace:
		ok = true
	}
	return
}
