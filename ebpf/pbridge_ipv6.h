#include "headers.h"
#include "types.h"
#include "maps.h"
#include "checksum.h"

static __always_inline int handle_ipv6(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  struct ipv6hdr *iph = data;
  struct tcphdr *tcph;
  struct udphdr *udph;

  if ((void *)(iph + 1) > data_end) {
    return XDP_DROP;
  }

  __u32 match = 0;
  __u32 prev_ip[4] = {0};
  __u32 next_ip[4] = {0};
  __u32 ifindex = 0;

//  bpf_printk("packet %pI6 -> %pI6\n", &iph->saddr, &iph->daddr);

  // check and use src rule
  struct ip_address src_ip;
  __builtin_memset(&src_ip, 0, sizeof(struct ip_address));
  src_ip.family = AF_INET6;
  __builtin_memcpy(&src_ip.addr.v6, &iph->saddr, sizeof(struct in6_addr));
  struct rule *src_rule = bpf_map_lookup_elem(&src_rules, &src_ip);
  if (src_rule) {
//    bpf_printk("src match\n");
    __builtin_memcpy(prev_ip, &iph->saddr, sizeof(struct in6_addr));
    __builtin_memcpy(next_ip, &src_rule->replace.addr.v6, sizeof(struct in6_addr));
    ifindex = src_rule->ifindex;

    __builtin_memcpy(&iph->saddr, next_ip, sizeof(struct in6_addr));
    match = 1;

    src_rule->counter_packets++;
    src_rule->counter_bytes += (ctx->data_end - ctx->data);
  }

  // check and use dst rule
  struct ip_address dst_ip;
  __builtin_memset(&dst_ip, 0, sizeof(struct ip_address));
  dst_ip.family = AF_INET6;
  __builtin_memcpy(&dst_ip.addr.v6, &iph->daddr, sizeof(struct in6_addr));
  struct rule *dst_rule = bpf_map_lookup_elem(&dst_rules, &dst_ip);
  if (dst_rule) {
//    bpf_printk("dst match\n");
    __builtin_memcpy(prev_ip, &iph->daddr, sizeof(struct in6_addr));
    __builtin_memcpy(next_ip, &dst_rule->replace.addr.v6, sizeof(struct in6_addr));
    ifindex = dst_rule->ifindex;

    __builtin_memcpy(&iph->daddr, next_ip, sizeof(struct in6_addr));
    match = 1;

    dst_rule->counter_packets++;
    dst_rule->counter_bytes += (ctx->data_end - ctx->data);
  }


  // update IP checksum and redirect
  if (match) {
    // update TCP/UDP checksum
    if (iph->nexthdr == IPPROTO_TCP) {
      tcph = data + sizeof(struct ipv6hdr);
      if ((void *)(tcph + 1) > data_end) {
        return XDP_DROP;
      }
      tcph->check = recalc_csum_ipv6(tcph->check, prev_ip, next_ip);
    } else if (iph->nexthdr == IPPROTO_UDP) {
      udph = data + sizeof(struct ipv6hdr);
      if ((void *)(udph + 1) > data_end) {
        return XDP_DROP;
      }
      udph->check = recalc_csum_ipv6(udph->check, prev_ip, next_ip);
    }

    return bpf_redirect(ifindex, 0);
  }

  return XDP_DROP;
}

