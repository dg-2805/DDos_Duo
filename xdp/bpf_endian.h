// Minimal endian helpers for BPF
#ifndef __BPF_ENDIAN_MINI_H__
#define __BPF_ENDIAN_MINI_H__

#include <linux/types.h>

#ifndef __BYTE_ORDER__
#define __BYTE_ORDER__ __ORDER_LITTLE_ENDIAN__
#endif

static __always_inline __u16 __bswap16(__u16 x) { return __builtin_bswap16(x); }
static __always_inline __u32 __bswap32(__u32 x) { return __builtin_bswap32(x); }

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define bpf_htons(x) (__bswap16((__u16)(x)))
#define bpf_ntohs(x) (__bswap16((__u16)(x)))
#define bpf_htonl(x) (__bswap32((__u32)(x)))
#define bpf_ntohl(x) (__bswap32((__u32)(x)))
#else
#define bpf_htons(x) (x)
#define bpf_ntohs(x) (x)
#define bpf_htonl(x) (x)
#define bpf_ntohl(x) (x)
#endif

#endif /* __BPF_ENDIAN_MINI_H__ */


