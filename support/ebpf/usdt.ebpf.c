#include "bpfdefs.h"
#include "tracemgmt.h"

#include "types.h"
#include "usdt_defs.h"

#ifndef BPF_USDT_MAX_SPEC_CNT
  #define BPF_USDT_MAX_SPEC_CNT 256
#endif

bpf_map_def SEC("maps") __bpf_usdt_specs = {
  .type        = BPF_MAP_TYPE_HASH,
  .key_size    = sizeof(u32),
  .value_size  = sizeof(struct bpf_usdt_spec),
  .max_entries = BPF_USDT_MAX_SPEC_CNT,
};

// Per-CPU record of the stack being built and meta-data on the building process
bpf_map_def SEC("maps") usdt_per_cpu_records = {
  .type        = BPF_MAP_TYPE_PERCPU_ARRAY,
  .key_size    = sizeof(int),
  .value_size  = sizeof(PerCPURecord),
  .max_entries = 1,
};

// usdt_progs maps from a program ID to a usdt eBPF program
bpf_map_def SEC("maps") usdt_progs = {
  .type        = BPF_MAP_TYPE_PROG_ARRAY,
  .key_size    = sizeof(u32),
  .value_size  = sizeof(u32),
  .max_entries = NUM_TRACER_PROGS,
};

// Dummy probe to reference USDT maps so they're not considered unreferenced during loading.
// This ensures the maps are available for actual USDT probe programs to use.
// This function is never actually attached, it just ensures the maps are loaded.
SEC("usdt/usdt_dummy_probe")
int usdt_dummy_probe(UNUSED struct pt_regs *ctx)
{
  u32 key0 = 0;
  bpf_tail_call(ctx, &usdt_progs, key0);
  struct bpf_usdt_spec *spec = bpf_map_lookup_elem(&__bpf_usdt_specs, &key0);
  (void)spec; // Reference the spec to avoid unused variable warning
  PerCPURecord *record = bpf_map_lookup_elem(&usdt_per_cpu_records, &key0);
  (void)record;
  return 0;
}
