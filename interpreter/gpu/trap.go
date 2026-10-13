package gpu

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

// specID is the fixed per-probe id forming the low 32 bits of the
// __bpf_usdt_specs map key (u64 pid<<32|spec_id). It must match the SPEC_ID_*
// constants in cuda.ebpf.c and must be non-zero (0 means "no spec" in BPF).
func (u usdtTrap) specID() uint32 {
	switch u {
	case apiCorrelation:
		return 1
	case apiSynchronize:
		return 2
	case hostTiming:
		return 3
	case kernelTiming:
		return 4
	case errorTrap:
		return 5
	default:
		return 0
	}
}

func (u usdtTrap) String() string { return string(u) }