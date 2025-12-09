package main

import (
	"context"
	"fmt"
	hp "github.com/toliu/opentelemetry-ebpf-profiler/reporter/hotspotmem"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	if len(os.Args) >= 2 {
		fmt.Println("Usage: go run . <java_pid>")
		fmt.Println("Example: go run . 12345")
		fmt.Println("")
		fmt.Println("This program will:")
		fmt.Println("  1. Start memory allocation profiling on the Java process")
		fmt.Println("  2. Dump OTLP format profile data every 2 seconds")
		fmt.Println("  3. Convert OTLP data to collapsed format")
		fmt.Println("  4. Save both formats to /tmp/asprof-otlp/")
		fmt.Println("")
		fmt.Println("Press Ctrl+C to stop profiling")
		return
	}

	pid := 172847

	// 创建上下文，支持 Ctrl+C 取消
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 监听中断信号
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		log.Printf("\n[INFO] Received interrupt signal, stopping profiling...")
		cancel()
	}()

	// 配置
	config := &hp.OTLPProfilerConfig{
		PID:           pid,
		AllocInterval: 10 * 1024, // 降低到 10KB，更容易触发采样
		DumpInterval:  2 * time.Second,
		LibAsyncPath:  "/root/zzp/async-profiler-4.1-linux-x64/lib/libasyncProfiler.so",
	}

	log.Printf("=== OTLP Profiler ===")
	log.Printf("Target PID: %d", config.PID)
	log.Printf("Alloc interval: %s", config.AllocInterval)
	log.Printf("Dump interval: %s", config.DumpInterval)
	log.Printf("")

	// 启动 profiling
	dataChan, err := hp.StartMemAllocProfilingOTLP(ctx, config)
	if err != nil {
		log.Fatalf("Failed to start profiling: %v", err)
	}

	// 接收数据
	dumpCount := 0
	for data := range dataChan {
		dumpCount++
		log.Printf("\n=== Dump #%d at %s ===", dumpCount, data.Timestamp.Format("15:04:05"))
		if dumpCount == 1 {
			// 只在第一次 dump 时打印详细信息
		}
	}

	log.Printf("\n=== Profiling Completed ===")
	log.Printf("Total dumps: %d", dumpCount)
	log.Printf("\nTo generate flamegraph:")
	log.Printf("  git clone https://github.com/brendangregg/FlameGraph.git")
	log.Printf("  cd FlameGraph")
}
