#ifndef __EBPF_TYPES_H
#define __EBPF_TYPES_H

struct ip_address {
  __u16 family;
  __u16 pad1;
  union {
    __u32 v6[4];
    __u32 v4;
  } addr;
};

struct rule {
  struct ip_address replace;
  __u32 ifindex;

  __u64 counter_packets;
  __u64 counter_bytes;
};

#endif