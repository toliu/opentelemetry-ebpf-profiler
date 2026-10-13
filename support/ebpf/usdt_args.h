// Derived from github.com/parca-dev/usdt (ebpf/usdt_args.h), Apache License 2.0.
//
// Self-contained USDT argument parser for the GPU probes. Unlike the parca
// version this does NOT depend on bpf_get_attach_cookie (kernel 5.15+): the
// spec-map key is a single u64 = (u64)pid << 32 | spec_id, where pid is the
// current tgid and spec_id is the per-probe compile-time constant passed into
// BPF_USDT_ID. Register-offset logic is lifted from parca verbatim.
//
// This header is deliberately not self-contained: include bpfdefs.h first.

#ifndef COLA_GPU_USDT_ARGS_H
#define COLA_GPU_USDT_ARGS_H

#include "usdt_defs.h"

// Defined in usdt.ebpf.c as a BPF map (bpf_map_def). Redeclared here as an
// opaque type so we can take its address for bpf_map_lookup_elem without
// pulling in the legacy map-declaration macro.
extern struct usdt_specs_t __bpf_usdt_specs;

// __bpf_usdt_get_reg_off maps a register ID to its byte offset inside
// struct pt_regs for the compiled architecture.
static EBPF_INLINE int __bpf_usdt_get_reg_off(u8 reg_id)
{
  switch (reg_id) {
#if defined(__x86_64__)
  case BPF_USDT_REG_RAX: return __builtin_offsetof(struct pt_regs, ax);
  case BPF_USDT_REG_RBX: return __builtin_offsetof(struct pt_regs, bx);
  case BPF_USDT_REG_RCX: return __builtin_offsetof(struct pt_regs, cx);
  case BPF_USDT_REG_RDX: return __builtin_offsetof(struct pt_regs, dx);
  case BPF_USDT_REG_RSI: return __builtin_offsetof(struct pt_regs, si);
  case BPF_USDT_REG_RDI: return __builtin_offsetof(struct pt_regs, di);
  case BPF_USDT_REG_RBP: return __builtin_offsetof(struct pt_regs, bp);
  case BPF_USDT_REG_RSP: return __builtin_offsetof(struct pt_regs, sp);
  case BPF_USDT_REG_R8:  return __builtin_offsetof(struct pt_regs, r8);
  case BPF_USDT_REG_R9:  return __builtin_offsetof(struct pt_regs, r9);
  case BPF_USDT_REG_R10: return __builtin_offsetof(struct pt_regs, r10);
  case BPF_USDT_REG_R11: return __builtin_offsetof(struct pt_regs, r11);
  case BPF_USDT_REG_R12: return __builtin_offsetof(struct pt_regs, r12);
  case BPF_USDT_REG_R13: return __builtin_offsetof(struct pt_regs, r13);
  case BPF_USDT_REG_R14: return __builtin_offsetof(struct pt_regs, r14);
  case BPF_USDT_REG_R15: return __builtin_offsetof(struct pt_regs, r15);
  case BPF_USDT_REG_RIP: return __builtin_offsetof(struct pt_regs, ip);
#elif defined(__aarch64__)
  case BPF_USDT_REG_X0:  return __builtin_offsetof(struct pt_regs, regs[0]);
  case BPF_USDT_REG_X1:  return __builtin_offsetof(struct pt_regs, regs[1]);
  case BPF_USDT_REG_X2:  return __builtin_offsetof(struct pt_regs, regs[2]);
  case BPF_USDT_REG_X3:  return __builtin_offsetof(struct pt_regs, regs[3]);
  case BPF_USDT_REG_X4:  return __builtin_offsetof(struct pt_regs, regs[4]);
  case BPF_USDT_REG_X5:  return __builtin_offsetof(struct pt_regs, regs[5]);
  case BPF_USDT_REG_X6:  return __builtin_offsetof(struct pt_regs, regs[6]);
  case BPF_USDT_REG_X7:  return __builtin_offsetof(struct pt_regs, regs[7]);
  case BPF_USDT_REG_X8:  return __builtin_offsetof(struct pt_regs, regs[8]);
  case BPF_USDT_REG_X9:  return __builtin_offsetof(struct pt_regs, regs[9]);
  case BPF_USDT_REG_X10: return __builtin_offsetof(struct pt_regs, regs[10]);
  case BPF_USDT_REG_X11: return __builtin_offsetof(struct pt_regs, regs[11]);
  case BPF_USDT_REG_X12: return __builtin_offsetof(struct pt_regs, regs[12]);
  case BPF_USDT_REG_X13: return __builtin_offsetof(struct pt_regs, regs[13]);
  case BPF_USDT_REG_X14: return __builtin_offsetof(struct pt_regs, regs[14]);
  case BPF_USDT_REG_X15: return __builtin_offsetof(struct pt_regs, regs[15]);
  case BPF_USDT_REG_X16: return __builtin_offsetof(struct pt_regs, regs[16]);
  case BPF_USDT_REG_X17: return __builtin_offsetof(struct pt_regs, regs[17]);
  case BPF_USDT_REG_X18: return __builtin_offsetof(struct pt_regs, regs[18]);
  case BPF_USDT_REG_X19: return __builtin_offsetof(struct pt_regs, regs[19]);
  case BPF_USDT_REG_X20: return __builtin_offsetof(struct pt_regs, regs[20]);
  case BPF_USDT_REG_X21: return __builtin_offsetof(struct pt_regs, regs[21]);
  case BPF_USDT_REG_X22: return __builtin_offsetof(struct pt_regs, regs[22]);
  case BPF_USDT_REG_X23: return __builtin_offsetof(struct pt_regs, regs[23]);
  case BPF_USDT_REG_X24: return __builtin_offsetof(struct pt_regs, regs[24]);
  case BPF_USDT_REG_X25: return __builtin_offsetof(struct pt_regs, regs[25]);
  case BPF_USDT_REG_X26: return __builtin_offsetof(struct pt_regs, regs[26]);
  case BPF_USDT_REG_X27: return __builtin_offsetof(struct pt_regs, regs[27]);
  case BPF_USDT_REG_X28: return __builtin_offsetof(struct pt_regs, regs[28]);
  case BPF_USDT_REG_X29: return __builtin_offsetof(struct pt_regs, regs[29]); // FP
  case BPF_USDT_REG_X30: return __builtin_offsetof(struct pt_regs, regs[30]); // LR
  case BPF_USDT_REG_SP:  return __builtin_offsetof(struct pt_regs, sp);
  case BPF_USDT_REG_PC:  return __builtin_offsetof(struct pt_regs, pc);
#endif
  default: return -1;
  }
}

static EBPF_INLINE int __bpf_usdt_get_reg_val(struct pt_regs *ctx, u8 reg_id, unsigned long *val)
{
  int reg_off = __bpf_usdt_get_reg_off(reg_id);
  if (reg_off < 0)
    return -1;
  return bpf_probe_read_kernel(val, sizeof(*val), (void *)ctx + reg_off);
}

// bpf_usdt_arg resolves one USDT argument (0-based arg_num) of the probe
// identified by spec_id for the current task. The result is written to *res.
//
// Unlike parca's bpf_usdt_arg, there is no spec_id lookup via attach cookie:
// the caller passes the per-probe constant spec_id directly. The lookup key is
// (u64)pid << 32 | spec_id, matching the key Go writes in data.go.
static EBPF_INLINE UNUSED int bpf_usdt_arg(struct pt_regs *ctx, u32 spec_id, u64 arg_num, long *res)
{
  struct bpf_usdt_spec *spec;
  struct bpf_usdt_arg_spec *arg_spec;
  unsigned long val;
  int err;
  u64 key;

  *res = 0;

  key = ((u64)(bpf_get_current_pid_tgid() >> 32) << 32) | spec_id;
  spec = bpf_map_lookup_elem(&__bpf_usdt_specs, &key);
  if (!spec)
    return -1;

  if (arg_num >= BPF_USDT_MAX_ARG_CNT || arg_num >= spec->arg_cnt)
    return -1;

  arg_spec = &spec->args[arg_num];

  u32 arg_type    = arg_spec->arg_type;
  u64 val_off     = arg_spec->val_off;
  u8 reg_id       = arg_spec->reg_id;
  bool arg_signed = arg_spec->arg_signed;
  s8 arg_bitshift = arg_spec->arg_bitshift;

  switch (arg_type) {
  case BPF_USDT_ARG_CONST:
    val = val_off;
    break;
  case BPF_USDT_ARG_REG:
    err = __bpf_usdt_get_reg_val(ctx, reg_id, &val);
    if (err) return err;
    break;
  case BPF_USDT_ARG_REG_DEREF:
    err = __bpf_usdt_get_reg_val(ctx, reg_id, &val);
    if (err) return err;
    err = bpf_probe_read_user(&val, sizeof(val), (void *)val + val_off);
    if (err) return err;
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    val >>= arg_bitshift;
#endif
    break;
  default: return -1;
  }

  val <<= arg_bitshift;
  if (arg_signed)
    val = ((long)val) >> arg_bitshift;
  else
    val = val >> arg_bitshift;
  *res = val;
  return 0;
}

// ---- Variadic argument-list generation (thread spec_id through) ----

#ifndef ___bpf_nth
#define ___bpf_nth(_, _1, _2, _3, _4, _5, _6, _7, _8, _9, _a, _b, _c, N, ...) N
#endif
#ifndef ___bpf_narg
#define ___bpf_narg(...) \
	___bpf_nth(_, ##__VA_ARGS__, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0)
#endif

#define ___cu_usdt_args0(spec_id) ctx
#define ___cu_usdt_args1(spec_id, x) ___cu_usdt_args0(spec_id), ({ long _arg; bpf_usdt_arg(ctx, spec_id, 0, &_arg); _arg; })
#define ___cu_usdt_args2(spec_id, x, args...) ___cu_usdt_args1(spec_id, args), ({ long _arg; bpf_usdt_arg(ctx, spec_id, 1, &_arg); _arg; })
#define ___cu_usdt_args3(spec_id, x, args...) ___cu_usdt_args2(spec_id, args), ({ long _arg; bpf_usdt_arg(ctx, spec_id, 2, &_arg); _arg; })
#define ___cu_usdt_args4(spec_id, x, args...) ___cu_usdt_args3(spec_id, args), ({ long _arg; bpf_usdt_arg(ctx, spec_id, 3, &_arg); _arg; })
#define ___cu_usdt_args5(spec_id, x, args...) ___cu_usdt_args4(spec_id, args), ({ long _arg; bpf_usdt_arg(ctx, spec_id, 4, &_arg); _arg; })
#define ___cu_usdt_args6(spec_id, x, args...) ___cu_usdt_args5(spec_id, args), ({ long _arg; bpf_usdt_arg(ctx, spec_id, 5, &_arg); _arg; })
#define ___cu_usdt_args7(spec_id, x, args...) ___cu_usdt_args6(spec_id, args), ({ long _arg; bpf_usdt_arg(ctx, spec_id, 6, &_arg); _arg; })
#define ___cu_usdt_args8(spec_id, x, args...) ___cu_usdt_args7(spec_id, args), ({ long _arg; bpf_usdt_arg(ctx, spec_id, 7, &_arg); _arg; })
#define ___cu_usdt_args9(spec_id, x, args...) ___cu_usdt_args8(spec_id, args), ({ long _arg; bpf_usdt_arg(ctx, spec_id, 8, &_arg); _arg; })
#define ___cu_usdt_args10(spec_id, x, args...) ___cu_usdt_args9(spec_id, args), ({ long _arg; bpf_usdt_arg(ctx, spec_id, 9, &_arg); _arg; })
#define ___cu_usdt_args11(spec_id, x, args...) ___cu_usdt_args10(spec_id, args), ({ long _arg; bpf_usdt_arg(ctx, spec_id, 10, &_arg); _arg; })
#define ___cu_usdt_args12(spec_id, x, args...) ___cu_usdt_args11(spec_id, args), ({ long _arg; bpf_usdt_arg(ctx, spec_id, 11, &_arg); _arg; })

#define ___cu_concat(a, b) a##b
#define ___cu_apply(fn, n) ___cu_concat(fn, n)
#define ___cu_usdt_args(spec_id, args...) ___cu_apply(___cu_usdt_args, ___bpf_narg(args))(spec_id, args)

// BPF_USDT_ID(name, spec_id, args...) declares a USDT uprobe entry point
// `name(struct pt_regs *ctx)` whose typed parameters are extracted from the
// current task's USDT spec (keyed by pid<<32|spec_id). The body continues as a
// static inline ____name(ctx, <typed args>) defined immediately after the
// macro.
#define BPF_USDT_ID(name, spec_id, args...) \
  name(struct pt_regs *ctx); \
  static EBPF_INLINE typeof(name(0)) ____##name(UNUSED struct pt_regs *ctx, ##args); \
  typeof(name(0)) name(struct pt_regs *ctx) { \
    _Pragma("GCC diagnostic push") \
    _Pragma("GCC diagnostic ignored \"-Wint-conversion\"") \
    return ____##name(___cu_usdt_args(spec_id, args)); \
    _Pragma("GCC diagnostic pop") \
  } \
  static EBPF_INLINE typeof(name(0)) ____##name(UNUSED struct pt_regs *ctx, ##args)

#endif // COLA_GPU_USDT_ARGS_H