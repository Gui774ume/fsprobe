#include <linux/kconfig.h>
#include <linux/version.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Waddress-of-packed-member"
#pragma clang diagnostic ignored "-Warray-bounds"
#pragma clang diagnostic ignored "-Wunused-label"

/* In Linux 5.4 asm_inline was introduced, but it's not supported by clang.
 * Redefine it to just asm to enable successful compilation.
 */
#ifdef asm_inline
#undef asm_inline
#define asm_inline asm
#endif
/* Before bpf_helpers.h is included, uapi bpf.h has been
 * included, which references linux/types.h. This may bring
 * in asm_volatile_goto definition if permitted based on
 * compiler setup and kernel configs.
 *
 * clang does not support "asm volatile goto" yet.
 * So redefine asm_volatile_goto to some invalid asm code.
 * If asm_volatile_goto is actually used by the bpf program,
 * a compilation error will appear.
 */
#ifdef asm_volatile_goto
#undef asm_volatile_goto
#endif
#define asm_volatile_goto(x...) asm volatile("invalid use of asm_volatile_goto")

#include <linux/ptrace.h>
#include <linux/tty.h>
#pragma clang diagnostic pop

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-variable-sized-type-not-at-end"
#include <uapi/linux/limits.h>
#include <linux/sched.h>
#include <linux/fs_struct.h>
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/types.h>
#include <linux/fs_pin.h>
#include <linux/mount.h>
#include <linux/sched/signal.h>

#include <linux/nsproxy.h>
#include <linux/pid_namespace.h>
#include <linux/ns_common.h>
#pragma clang diagnostic pop

// Custom eBPF includes
#include "bpf/bpf.h"
#include "bpf/bpf_map.h"
#include "bpf/bpf_helpers.h"
#include "process.h"
#include "structs.h"
#include "filter.h"
#include "const.h"
#include "dentry.h"
#include "events/events.h"
