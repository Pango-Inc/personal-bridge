#ifndef CHECKSUM_H
#define CHECKSUM_H

#include "headers.h"

static __always_inline __u16 calc_csum(void *data_start, __u16 *data_end) {
    __u32 csum = 0;
    for (__u16 *it = data_start; it < data_end; ++it) {
        csum += *it;
    }
    return ~((csum & 0xFFFF) + (csum >> 16));
}

static __always_inline __u16 calc_ip_checksum(struct iphdr *iph) {
  __u32 csum = 0;
  __u16 *v = (__u16 *)iph;
  int i;
  for (i = 0; i < sizeof(struct iphdr) >> 1; i++) {
    csum += *v++;
  }
  return ~((csum & 0xFFFF) + (csum >> 16));
}

static __always_inline __u16 recalc_csum(__u16 curr, __u32 prev, __u32 next) {
    __u32 csum;
    prev = ~bpf_ntohl(prev);
    next = bpf_ntohl(next);
    curr = ~bpf_ntohs(curr);
    csum = (__u32)curr + (prev>>16) + (prev&0xffff) + (next>>16) + (next&0xffff);
    return bpf_htons(~((csum & 0xFFFF) + (csum >> 16)));
}

static __always_inline __u16 recalc_csum_ipv6(__u16 sum, __u32* pprev, __u32* pnext) {
    __u32 subsum = 0;
    __u32 prev = bpf_ntohl(*pprev);
    subsum += (prev>>16) + (prev&0xffff);
    prev = bpf_ntohl(*(pprev+1));
    subsum += (prev>>16) + (prev&0xffff);
    prev = bpf_ntohl(*(pprev+2));
    subsum += (prev>>16) + (prev&0xffff);
    prev = bpf_ntohl(*(pprev+3));
    subsum += (prev>>16) + (prev&0xffff);

    __u32 addsum = 0;
    __u32 next = bpf_ntohl(*pnext);
    addsum += (next>>16) + (next&0xffff);
    next = bpf_ntohl(*(pnext+1));
    addsum += (next>>16) + (next&0xffff);
    next = bpf_ntohl(*(pnext+2));
    addsum += (next>>16) + (next&0xffff);
    next = bpf_ntohl(*(pnext+3));
    addsum += (next>>16) + (next&0xffff);

    sum= ~bpf_ntohs(sum);
    sum -= (subsum >> 16) + (subsum & 0xffff);
    sum += (addsum >> 16) + (addsum & 0xffff);

    return bpf_htons(~sum);
}

#endif // CHECKSUM_H
