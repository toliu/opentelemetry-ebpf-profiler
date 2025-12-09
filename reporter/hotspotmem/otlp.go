package hotspotmem

import (
	"context"
	"crypto/rand"
	"fmt"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pprofile"
	"os"
	"slices"
	"time"

	profilesv1 "go.opentelemetry.io/proto/otlp/profiles/v1development"
	"google.golang.org/protobuf/proto"
)

// OTLPProfilerConfig OTLP profiler 配置
type OTLPProfilerConfig struct {
	PID           int           // Java 进程 PID
	AllocInterval uint64        // 内存分配采样间隔，以字节为单位
	DumpInterval  time.Duration // dump 间隔
	LibAsyncPath  string        // libasyncProfiler.so 路径
}

// OTLPProfileData OTLP profile 数据
type OTLPProfileData struct {
	Timestamp    time.Time
	ProfilesData *profilesv1.ProfilesData
}

// StartMemAllocProfilingOTLP 启动内存分配 profiling（OTLP 格式）
func StartMemAllocProfilingOTLP(ctx context.Context, config *OTLPProfilerConfig, cha chan map[uint32]pprofile.Profiles) error {
	// 设置默认值
	if config.AllocInterval == 0 {
		config.AllocInterval = 512 * 1024
	}
	if config.DumpInterval == 0 {
		config.DumpInterval = 5 * time.Second
	}
	if config.LibAsyncPath == "" {
		return fmt.Errorf("empty hotspot memprofile lib")
	}

	// 创建 JVM attacher
	attacher, err := NewJVMAttacher(config.PID)
	if err != nil {
		return fmt.Errorf("failed to create JVM attacher: %w", err)
	}

	// 启动 profiling
	startCmd := fmt.Sprintf("start,event=alloc,alloc=%d", config.AllocInterval)
	log.Debugf("Starting hotspot mem profiling with command: %s", startCmd)

	stopCmd := "stop"
	_, _ = attacher.loadAgent(config.LibAsyncPath, stopCmd)

	response, err := attacher.loadAgent(config.LibAsyncPath, startCmd)
	if err != nil {
		return fmt.Errorf("failed to start profiling: %w", err)
	}
	log.Debugf("start hot spot mem profiling: %s", response)

	// 启动 dump 协程
	go func() {
		//defer close(dataChan)
		defer func() {
			// 停止 profiling
			log.Debugf("Stopping profiling...")
			_, _ = attacher.loadAgent(config.LibAsyncPath, stopCmd)
		}()

		ticker := time.NewTicker(config.DumpInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				log.Debugf("Context cancelled, stopping hotspot mem profiling")
				return

			case <-ticker.C:
				// Dump profile data
				timestamp := time.Now()
				var data OTLPProfileData
				data.Timestamp = timestamp

				// 使用临时目录（跨平台兼容）
				tmpDir := os.TempDir()
				tmpFile := fmt.Sprintf("%s/asprof.%d.%d.pb", tmpDir, os.Getpid(), config.PID)
				tmpLog := fmt.Sprintf("%s/asprof-log.%d.%d.txt", tmpDir, os.Getpid(), config.PID)

				// 构建 dump 命令（OTLP 格式）
				dumpCmd := fmt.Sprintf("dump,file=%s,otlp,log=%s", tmpFile, tmpLog)
				log.Debugf("Sending hotspot mem profiling dump command: %s", dumpCmd)
				// 执行 dump 命令
				_, err := attacher.loadAgent(config.LibAsyncPath, dumpCmd)
				if err != nil {
					log.Errorf(" Failed to dump hotspot profile: %v", err)
					return
				}
				// 等待文件写入完成, 动态库会把数据写入文件，然后我们读出来解析，
				// 暂时先这样最简单，
				// 如果要通过其他方式得改动态库代码。
				time.Sleep(200 * time.Millisecond)

				// 检查文件是否存在
				if _, err := os.Stat(tmpFile); os.IsNotExist(err) {
					log.Errorf("unable to read hotspot mem profiling dump data, data file does not exist: %s", tmpFile)
					// 检查日志文件
					if logData, err := os.ReadFile(tmpLog); err == nil {
						log.Errorf("hotspot mem profiling lib: %s", string(logData))
					}
					_ = os.Remove(tmpLog)
					continue
				}

				// 读取临时文件
				fileData, dumpErr := os.ReadFile(tmpFile)
				if dumpErr != nil {
					// 尝试容器场景：通过 /proc/PID/root 访问
					containerPath := fmt.Sprintf("/proc/%d/root%s", config.PID, tmpFile)
					fileData, dumpErr = os.ReadFile(containerPath)
					if dumpErr != nil {
						log.Errorf("Failed to read hotspot mem profiling dump file: %v", err)
						_ = os.Remove(tmpFile)
						_ = os.Remove(tmpLog)
						continue
					}
				}
				_ = os.Remove(tmpFile)
				_ = os.Remove(tmpLog)
				// 解析 通用 OTLP protobuf 数据
				profilesData := &profilesv1.ProfilesData{}
				if err := proto.Unmarshal(fileData, profilesData); err != nil {
					log.Errorf("Failed to unmarshal OTLP data: %v", err)
					continue
				}
				data.ProfilesData = profilesData
				tds := ConvertOtlpData(data, uint32(config.PID))

				select {
				case cha <- tds:
				case <-ctx.Done():
					return
				default:
					log.Warnf("drop hot spot mem profiling data, cause channel overflow...")
				}
			}
		}
	}()
	return nil
}

// mkProfileID 从generate.go直接copy过来的
func mkProfileID() []byte {
	profileID := make([]byte, 16)
	_, err := rand.Read(profileID)
	if err != nil {
		return []byte("opentelemetry-ebpf-profiler")
	}
	return profileID
}

func ConvertOtlpData(data OTLPProfileData, pid uint32) map[uint32]pprofile.Profiles {
	tds := make(map[uint32]pprofile.Profiles)
	profiles := pprofile.NewProfiles()

	rp := profiles.ResourceProfiles().AppendEmpty()
	sp := rp.ScopeProfiles().AppendEmpty()
	profile := sp.Profiles().AppendEmpty()
	profile.SetProfileID(pprofile.ProfileID(mkProfileID()))
	var typeStrIndex, unitStrIndex int32
	t := []uint64{uint64(data.Timestamp.UnixNano())}
	slices.DeleteFunc(data.ProfilesData.GetResourceProfiles(), func(profiles *profilesv1.ResourceProfiles) bool {
		slices.DeleteFunc(profiles.GetScopeProfiles(), func(profiles *profilesv1.ScopeProfiles) bool {
			slices.DeleteFunc(profiles.GetProfiles(), func(p *profilesv1.Profile) bool {
				st := profile.SampleType().AppendEmpty()
				if len(p.GetSampleType()) > 0 {
					typeStrIndex = p.GetSampleType()[0].GetTypeStrindex()
					unitStrIndex = p.GetSampleType()[0].GetUnitStrindex()
					st.SetTypeStrindex(typeStrIndex)
					st.SetUnitStrindex(unitStrIndex)
				}
				slices.DeleteFunc(p.GetSample(), func(sample *profilesv1.Sample) bool {
					s := profile.Sample().AppendEmpty()
					s.SetLocationsStartIndex(sample.LocationsStartIndex)
					s.SetLocationsLength(sample.LocationsLength)
					s.TimestampsUnixNano().Append(t...)
					s.Value().Append([]int64{sample.Value[1], sample.Value[0], -1}...)
					return false
				})
				profile.LocationIndices().Append(p.GetLocationIndices()...)
				profile.SetPeriod(p.GetPeriod())
				profile.PeriodType().SetTypeStrindex(p.PeriodType.GetTypeStrindex())
				profile.PeriodType().SetUnitStrindex(p.PeriodType.GetUnitStrindex())
				return false
			})
			return false
		})
		return false
	})
	for _, mapping := range data.ProfilesData.Dictionary.GetMappingTable() {
		m := profile.MappingTable().AppendEmpty()
		m.AttributeIndices().Append(mapping.GetAttributeIndices()...)
	}

	for _, l := range data.ProfilesData.Dictionary.GetLocationTable() {
		_l := profile.LocationTable().AppendEmpty()
		_l.SetMappingIndex(l.GetMappingIndex())
		_l.SetAddress(l.Address)
		_l.AttributeIndices().Append(l.GetAttributeIndices()...)
		for _, line := range l.GetLine() {
			_line := _l.Line().AppendEmpty()
			_line.SetFunctionIndex(line.GetFunctionIndex())
			_line.SetLine(line.GetLine())
		}
	}

	for _, f := range data.ProfilesData.Dictionary.FunctionTable {
		_f := profile.FunctionTable().AppendEmpty()
		_f.SetNameStrindex(f.GetNameStrindex())
		_f.SetFilenameStrindex(f.GetFilenameStrindex())
	}
	sb := data.ProfilesData.Dictionary.GetStringTable()
	sb[typeStrIndex] = "heap"
	sb[unitStrIndex] = "bytes"
	profile.StringTable().Append(data.ProfilesData.Dictionary.StringTable...)
	profile.SetTime(pcommon.Timestamp(t[0]))
	profile.PeriodType().SetTypeStrindex(typeStrIndex)
	profile.PeriodType().SetUnitStrindex(unitStrIndex)

	tds[pid] = profiles
	return tds
}
