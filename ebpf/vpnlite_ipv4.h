#include "headers.h"
#include "types.h"
#include "maps.h"
#include "checksum.h"

static __always_inline int handle_ipv4(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  struct iphdr *iph = data;
  struct tcphdr *tcph;
  struct udphdr *udph;

  if ((void *)(iph + 1) > data_end) {
    return XDP_DROP;
  }

  __u32 prev_ip = 0;
  __u32 next_ip = 0;
  __u32 ifindex = 0;

//    bpf_printk("SRC IP: %u.%u", (iph->saddr) & 0xFF, (iph->saddr >> 8) & 0xFF);
//    bpf_printk(".%u.%u\n", (iph->saddr >> 16) & 0xFF, (iph->saddr >> 24) & 0xFF);
//
//    // Log destination IP
//    bpf_printk("DST IP: %u.%u", (iph->daddr) & 0xFF, (iph->daddr >> 8) & 0xFF);
//    bpf_printk(".%u.%u\n", (iph->daddr >> 16) & 0xFF, (iph->daddr >> 24) & 0xFF);


  // check and use src rule
  struct ip_address src_ip;
  __builtin_memset(&src_ip, 0, sizeof(struct ip_address));
  src_ip.family = AF_INET;
  src_ip.addr.v4 = iph->saddr;
  struct rule *src_rule = bpf_map_lookup_elem(&src_rules, &src_ip);
  if (src_rule) {
//    bpf_printk("src match\n");
    prev_ip = iph->saddr;
    next_ip = src_rule->replace.addr.v4;
    ifindex = src_rule->ifindex;
    iph->saddr = next_ip;

    src_rule->counter_packets++;
    src_rule->counter_bytes += (ctx->data_end - ctx->data);
  }

  // check and use dst rule
  struct ip_address dst_ip;
  __builtin_memset(&dst_ip, 0, sizeof(struct ip_address));
  dst_ip.family = AF_INET;
  dst_ip.addr.v4 = iph->daddr;
  struct rule *dst_rule = bpf_map_lookup_elem(&dst_rules, &dst_ip);
  if (dst_rule) {
    //bpf_printk("dst match\n");
    prev_ip = iph->daddr;
    next_ip = dst_rule->replace.addr.v4;
    ifindex = dst_rule->ifindex;
    iph->daddr = next_ip;

    dst_rule->counter_packets++;
    dst_rule->counter_bytes += (ctx->data_end - ctx->data);
  }


  // update IP checksum and redirect
  if (next_ip) {
    iph->check = recalc_csum(iph->check, prev_ip, next_ip);

    // update TCP/UDP checksum
    if (iph->protocol == IPPROTO_TCP) {
      tcph = data + sizeof(struct iphdr);
      if ((void *)(tcph + 1) > data_end) {
        return XDP_DROP;
      }
      tcph->check = recalc_csum(tcph->check, prev_ip, next_ip);
    } else if (iph->protocol == IPPROTO_UDP) {
      udph = data + sizeof(struct iphdr);
      if ((void *)(udph + 1) > data_end) {
        return XDP_DROP;
      }
      udph->check = recalc_csum(udph->check, prev_ip, next_ip);
    }

    return bpf_redirect(ifindex, 0);
  }

  return XDP_DROP;
}

