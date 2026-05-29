#include "bpfdefs.h"
#include "cupti_activity_bpf.h"
#include "tracemgmt.h"
#include "types.h"
#include "usdt_args.h"

// cuda_correlation reads the correlation ID from the USDT probe and records a trace.
SEC("usdt/colasoft/gpu/api_correlation")
int BPF_USDT(api_correlation, u32 correlation_id, s32 cbid)
{
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid      = pid_tgid >> 32;
  u32 tid      = pid_tgid & 0xFFFFFFFF;

  if (pid == 0 || tid == 0)
    return 0;
  DEBUG_PRINT("api_correlation_probe: correlation_id=%u, cbid=%u", correlation_id, cbid);

  u64 ts      = bpf_ktime_get_ns();
  // Cast cbid to s32 first to get sign extension, then to u64
  u64 cuda_id = correlation_id + ((u64)cbid << 32);
  return collect_trace(ctx, TRACE_CUDA_LAUNCH, pid, tid, ts, 0, 0, 0, cuda_id);
}

// probe api_synchronize(u64 start, u64 end, u32 syncKind);
SEC("usdt/colasoft/gpu/api_synchronize")
int BPF_USDT(api_synchronize, u64 start, u64 end, u32 syncKind)
{
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid      = pid_tgid >> 32;
  u32 tid      = pid_tgid & 0xFFFFFFFF;

  if (pid == 0 || tid == 0)
    return 0;
  DEBUG_PRINT("api_synchronize_probe: start=%u, end=%u, syncKind=%u", start, end, syncKind);
  // syncKind is an enumerated CUDA driver synchronize API id (see the .so side).
  // Passing it as cuda_id makes collect_trace push a leaf frame whose addr_or_line
  // carries the kind, resolved back to a function name in user space.
  return collect_trace(ctx, TRACE_CUDA_SYNCHRONIZE, pid, tid, end, end - start, 0, 0, syncKind);
}

bpf_map_def SEC("maps") cuda_error_events = {
  .type        = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
  .key_size    = sizeof(u32),
  .value_size  = sizeof(u32),
  .max_entries = 0,
};

// probe error(s32 code, const char *message, const char *component);
// Reports error events to user-space via perf_event when component starts with "api-".
SEC("usdt/colasoft/gpu/error")
int BPF_USDT(error, s32 code, const char *message, const char *component)
{
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid      = pid_tgid >> 32;
  u32 tid      = pid_tgid & 0xFFFFFFFF;

  if (pid == 0 || tid == 0)
    return 0;

  // Check if component starts with "api-"
  char comp[5];
  if (bpf_probe_read_user_str(comp, sizeof(comp), component) < 4) {
    return 0;
  }
  if (comp[0] != 'a' || comp[1] != 'p' || comp[2] != 'i' || comp[3] != '-') {
    return 0;
  }

  struct error_event evt = {};
  evt.pid                = pid;
  evt.tid                = tid;
  evt.code               = code;
  bpf_probe_read_user_str(evt.message, sizeof(evt.message), message);
  bpf_probe_read_user_str(evt.component, sizeof(evt.component), component + 4);

  DEBUG_PRINT("error: pid=%u code=%d component=%s", pid, code, comp);

  bpf_perf_event_output(ctx, &cuda_error_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
  return 0;
}

// Per-CPU scratch space for large structs that exceed the BPF 512-byte stack limit.
// Used by cuda_host_timing and cuda_kernel_timing (mutually exclusive on same CPU).
#define MAX_BATCH_SIZE 128
#define PTR_BATCH      16
struct cuda_scratch {
  timeline timing;
  struct activity_event rec;
  // Pre-parsed activity_batch USDT args, set by cuda_probe before tail call.
  // bpf_get_attach_cookie does not return the correct cookie after bpf_tail_call,
  // so we parse args in cuda_probe and pass them via scratch.
  u64 ab_ptrs_base;
  u32 ab_num_activities;
};

bpf_map_def SEC("maps") cuda_scratch_heap = {
  .type        = BPF_MAP_TYPE_PERCPU_ARRAY,
  .key_size    = sizeof(u32),
  .value_size  = sizeof(struct cuda_scratch),
  .max_entries = 1,
};

bpf_map_def SEC("maps") cuda_timing_events = {
  .type        = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
  .key_size    = sizeof(u32),
  .value_size  = sizeof(u32),
  .max_entries = 0,
};

// SEC("usdt/colasoft/gpu/cuda_kernel")
// int BPF_USDT(
//   cuda_kernel_exec,
//   u64 start,
//   u64 end,
//   u32 correlation_id,
//   u32 device_id,
//   u32 stream_id,
//   u32 graph_id,
//   u64 graph_node_id,
//   u64 name_ptr)
// {
//   u64 pid_tgid = bpf_get_current_pid_tgid();
//   u32 pid      = pid_tgid >> 32;
//   if (!should_trace_pid(pid))
//     return 0;
//   const char *name = (const char *)name_ptr;
//
//   u32 zero                     = 0;
//   struct cuda_scratch *scratch = bpf_map_lookup_elem(&cuda_scratch_heap, &zero);
//   if (!scratch) {
//     return 0;
//   }
//   struct timeline *timing = &scratch->timing;
//
//   timing->pid            = pid;
//   timing->correlation_id = correlation_id;
//   timing->start          = start;
//   timing->end            = end;
//   timing->graph_node_id  = graph_node_id;
//   timing->device_id      = device_id;
//   timing->stream_id      = stream_id;
//   timing->graph_id       = graph_id;
//
//   int chars =
//     bpf_probe_read_user_str((char *)&timing->kernel_name, sizeof(timing->kernel_name), name);
//   if (chars <= 0) {
//     timing->kernel_name[0] = 'e';
//     timing->kernel_name[1] = 'r';
//     timing->kernel_name[2] = 'r';
//     timing->kernel_name[3] = '\0';
//   }
//
//   DEBUG_PRINT("cuda_kernel_exec: pid=%u corr_id=%u dev=%u", pid, correlation_id, device_id);
//
//   bpf_perf_event_output(ctx, &cuda_timing_events, BPF_F_CURRENT_CPU, timing, sizeof(*timing));
//
//   return 0;
// }

SEC("usdt/colasoft/gpu/host_timing")
int BPF_USDT(host_timing, u64 ptrs_base, u32 num_activities)
{
  u64 pid_tgid                 = bpf_get_current_pid_tgid();
  u32 pid                      = pid_tgid >> 32;
  u32 zero                     = 0;
  struct cuda_scratch *scratch = bpf_map_lookup_elem(&cuda_scratch_heap, &zero);
  if (!scratch) {
    return 0;
  }
  timeline *timing      = &scratch->timing;
  struct activity_event *rec = &scratch->rec;

  DEBUG_PRINT("cuda_host_timing: pid=%u num=%u", pid, (u32)num_activities);

  if (num_activities > MAX_BATCH_SIZE) {
    num_activities = MAX_BATCH_SIZE;
  }

  // Stack-local pointer batch — small enough for the BPF stack.
  u64 ptrs[PTR_BATCH] = {};

  // Nested loop: outer iterates over batches of PTR_BATCH pointers,
  // inner processes each pointer in the batch.  This keeps the verifier's
  // jump-sequence count well under BPF_COMPLEXITY_LIMIT_JMP_SEQ (8192).
  for (u32 batch = 0; batch < MAX_BATCH_SIZE / PTR_BATCH; batch++) {
    u32 base = batch * PTR_BATCH;
    if (base >= num_activities) {
      break;
    }

    if (bpf_probe_read_user(ptrs, sizeof(ptrs), (void *)(ptrs_base + base * sizeof(u64))) != 0) {
      break;
    }

    for (u32 j = 0; j < PTR_BATCH; j++) {
      if (base + j >= num_activities) {
        break;
      }

      u64 rec_ptr = ptrs[j];

      // Read the full activity record and filter by kind. The host_timing
      // batch only ever contains HOST-API records (ai-launch).
      if (bpf_probe_read_user(rec, sizeof(*rec), (void *)rec_ptr) != 0) {
        continue;
      }
      if (rec->kind != ACTIVITY_KIND_HOST_API) {
        continue;
      }

      timing->pid           = pid;
      timing->kind          = rec->kind;
      timing->correlationId = rec->correlationId;
      timing->start         = rec->start;
      timing->end           = rec->end;
      timing->graphNodeId   = rec->graphNodeId;
      timing->deviceId      = rec->deviceId;
      timing->streamId      = rec->streamId;
      timing->graphId       = rec->graphId;

      timing->tid      = rec->tid;
      timing->bytes    = rec->bytes;
      timing->copyKind = rec->copyKind;
      timing->sync     = rec->sync;

      const char *name = (const char *)rec->name;
      int chars =
        bpf_probe_read_user_str((char *)&timing->kernel_name, sizeof(timing->kernel_name), name);
      if (chars <= 0) {
        timing->kernel_name[0] = 'e';
        timing->kernel_name[1] = 'r';
        timing->kernel_name[2] = 'r';
        timing->kernel_name[3] = '\0';
      }

      DEBUG_PRINT(
        "cuda_host_timing: corr_id=%u kind=%u dev=%u",
        rec->correlation_id,
        rec->kind,
        rec->device_id);

      bpf_perf_event_output(ctx, &cuda_timing_events, BPF_F_CURRENT_CPU, timing, sizeof(*timing));
    }
  }

  return 0;
}

SEC("usdt/colasoft/gpu/kernel_timing")
int BPF_USDT(kernel_timing, u64 ptrs_base, u32 num_activities)
{
  u64 pid_tgid                 = bpf_get_current_pid_tgid();
  u32 pid                      = pid_tgid >> 32;
  u32 zero                     = 0;
  struct cuda_scratch *scratch = bpf_map_lookup_elem(&cuda_scratch_heap, &zero);
  if (!scratch) {
    return 0;
  }
  timeline *timing      = &scratch->timing;
  struct activity_event *rec = &scratch->rec;

  DEBUG_PRINT("cuda_kernel_timing: pid=%u num=%u", pid, (u32)num_activities);

  if (num_activities > MAX_BATCH_SIZE) {
    num_activities = MAX_BATCH_SIZE;
  }

  // Stack-local pointer batch — small enough for the BPF stack.
  u64 ptrs[PTR_BATCH] = {};

  for (u32 batch = 0; batch < MAX_BATCH_SIZE / PTR_BATCH; batch++) {
    u32 base = batch * PTR_BATCH;
    if (base >= num_activities) {
      break;
    }

    if (bpf_probe_read_user(ptrs, sizeof(ptrs), (void *)(ptrs_base + base * sizeof(u64))) != 0) {
      break;
    }

    for (u32 j = 0; j < PTR_BATCH; j++) {
      if (base + j >= num_activities) {
        break;
      }

      u64 rec_ptr = ptrs[j];

      // Read the full activity record and filter by kind. The kernel_timing
      // batch only ever contains KERNEL + MEMCPY records (ai-execution +
      // memcpy/kernel timeline).
      if (bpf_probe_read_user(rec, sizeof(*rec), (void *)rec_ptr) != 0) {
        continue;
      }
      if (rec->kind != ACTIVITY_KIND_KERNEL && rec->kind != ACTIVITY_KIND_MEMCPY) {
        continue;
      }

      timing->pid           = pid;
      timing->kind          = rec->kind;
      timing->correlationId = rec->correlationId;
      timing->start         = rec->start;
      timing->end           = rec->end;
      timing->graphNodeId   = rec->graphNodeId;
      timing->deviceId      = rec->deviceId;
      timing->streamId      = rec->streamId;
      timing->graphId       = rec->graphId;

      timing->tid      = rec->tid;
      timing->bytes    = rec->bytes;
      timing->copyKind = rec->copyKind;
      timing->sync     = rec->sync;

      const char *name = (const char *)rec->name;
      int chars =
        bpf_probe_read_user_str((char *)&timing->kernel_name, sizeof(timing->kernel_name), name);
      if (chars <= 0) {
        timing->kernel_name[0] = 'e';
        timing->kernel_name[1] = 'r';
        timing->kernel_name[2] = 'r';
        timing->kernel_name[3] = '\0';
      }

      DEBUG_PRINT(
        "cuda_kernel_timing: corr_id=%u kind=%u dev=%u",
        rec->correlation_id,
        rec->kind,
        rec->device_id);

      bpf_perf_event_output(ctx, &cuda_timing_events, BPF_F_CURRENT_CPU, timing, sizeof(*timing));
    }
  }

  return 0;
}

// FIXME(liushi): multiple挂载+cookie区分的模式对内核版本有要求，暂时注释这种方案，避免加载失败
// // Tail-call entry point for cuda_activity_batch.  Reads pre-parsed USDT args
// // from the scratch map (set by cuda_probe before bpf_tail_call) and forwards
// // them to the inline body generated by BPF_USDT.
// SEC("usdt/cuda_activity_batch_tail")
// int cuda_activity_batch_tail(struct pt_regs *ctx)
// {
//   u32 zero                     = 0;
//   struct cuda_scratch *scratch = bpf_map_lookup_elem(&cuda_scratch_heap, &zero);
//   if (!scratch) {
//     return 0;
//   }
//   return ____cuda_activity_batch(ctx, scratch->ab_ptrs_base, scratch->ab_num_activities);
// }

// // Cookie values for the cuda_probe multi-probe dispatcher.
// // Must match the cookie values set in cuda.go.
// #define CUDA_PROG_CORRELATION    0
// #define CUDA_PROG_KERNEL_EXEC    1
// #define CUDA_PROG_ACTIVITY_BATCH 2

// // Tail-call prog array for cuda_probe.  Contains a single entry at key 0
// // for cuda_activity_batch_tail, whose batch loop pushes past the BPF verifier's
// // BPF_COMPLEXITY_LIMIT_JMP_SEQ (8192) limit.  cuda_correlation and
// // cuda_kernel_exec are inlined directly in cuda_probe.
// bpf_map_def SEC("maps") cuda_progs = {
//   .type        = BPF_MAP_TYPE_PROG_ARRAY,
//   .key_size    = sizeof(u32),
//   .value_size  = sizeof(u32),
//   .max_entries = 1,
// };

// SEC("usdt/cuda_probe")
// int cuda_probe(struct pt_regs *ctx)
// {
//   u64 full_cookie = bpf_get_attach_cookie(ctx);
//   u32 cookie      = (u32)(full_cookie & 0xFFFFFFFF);

//   switch (cookie) {
//   case CUDA_PROG_CORRELATION: return BPF_USDT_CALL(cuda_correlation, correlation_id, cbid);
//   case CUDA_PROG_KERNEL_EXEC:
//     return BPF_USDT_CALL(
//       cuda_kernel_exec,
//       start,
//       end,
//       correlation_id,
//       device_id,
//       stream_id,
//       graph_id,
//       graph_node_id,
//       name);
//   case CUDA_PROG_ACTIVITY_BATCH: {
//     // Parse USDT args before the tail call — bpf_get_attach_cookie does not
//     // return the correct cookie after bpf_tail_call.
//     u32 zero                     = 0;
//     struct cuda_scratch *scratch = bpf_map_lookup_elem(&cuda_scratch_heap, &zero);
//     if (!scratch) {
//       break;
//     }
//     scratch->ab_ptrs_base      = (u64)bpf_usdt_arg0(ctx);
//     scratch->ab_num_activities = (u32)bpf_usdt_arg1(ctx);
//     bpf_tail_call(ctx, &cuda_progs, 0);
//     break;
//   }
//   default: DEBUG_PRINT("cuda_probe: unknown cookie %u", cookie); break;
//   }
//   return 0;
// }
