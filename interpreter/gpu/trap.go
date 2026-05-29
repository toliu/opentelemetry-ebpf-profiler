package gpu

import "math"

type usdtTrap string

const apiCorrelation usdtTrap = "api_correlation"

// host_timing carries HOST-API timing events (ai-launch); attached when the
// host-api switch is on.
const hostTiming usdtTrap = "host_timing"

// kernel_timing carries KERNEL + MEMCPY timing events (ai-execution + timeline);
// attached when the kernel switch is on.
const kernelTiming usdtTrap = "kernel_timing"
const apiSynchronize usdtTrap = "api_synchronize"
const errorTrap usdtTrap = "error"

// Cookie fixme(liushi):根据cookie来动态选择入口的逻辑已从bpf中移除
func (u usdtTrap) Cookie() uint64 {
	switch u {
	case apiCorrelation:
		return 0
	case hostTiming:
		return 1
	case kernelTiming:
		return 2
	default:
		return math.MaxUint64
	}
}
func (u usdtTrap) String() string { return string(u) }
