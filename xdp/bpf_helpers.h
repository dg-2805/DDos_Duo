/* Minimal bpf_helpers.h to build BPF programs without kernel source tree */
#ifndef __BPF_HELPERS_MINI_H__
#define __BPF_HELPERS_MINI_H__

#include <linux/types.h>

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

#ifndef __maybe_unused
#define __maybe_unused __attribute__((unused))
#endif

#define SEC(NAME) __attribute__((section(NAME), used))

struct bpf_map_def {
	__u32 type;
	__u32 key_size;
	__u32 value_size;
	__u32 max_entries;
	__u32 map_flags;
};

/* Helper function prototypes */
static void *(*bpf_map_lookup_elem)(const void *map, const void *key) = (void *)1;
static int (*bpf_map_update_elem)(const void *map, const void *key, const void *value, __u64 flags) = (void *)2;
static int (*bpf_map_delete_elem)(const void *map, const void *key) = (void *)3;
static int (*bpf_get_prandom_u32)(void) = (void *)7;
static int (*bpf_trace_printk)(const char *fmt, __u32 fmt_size, ...) = (void *)6;
static __u64 (*bpf_csum_diff)(__be32 *from, __u32 from_size, __be32 *to, __u32 to_size, __u64 seed) = (void *)28;

#endif /* __BPF_HELPERS_MINI_H__ */


