#include "headers.h"
#include "checksum.h"

#define WG_PORT 51820
#define PING_SIG_BE 0x676e6970  //ping
#define PONG_SIG_BE 0x676e6f70  //pong

#define IP_DF 0x4000 /* dont fragment flag */

static __always_inline int is_wg_ping_request(__u8* payload, void *data_end) {
  // Wireguard data packet structure
  // https://www.wireguard.com/protocol/#subsequent-messages-exchange-of-data-packets
  //
  // msg = packet_data {
  //     u8 message_type
  //     u8 reserved_zero[3]
  //     u32 receiver_index
  //     u64 counter
  //     u8 encrypted_encapsulated_packet[]
  // }

  // Check message_type = 0x04 (transport data packet)
  //
  // Check first 4 bytes of encrypted_encapsulated_packet against 
  // p(0x70)
  // i(0x69)
  // n(0x6e)
  // g(0x67) 

  // Check message_type is transport data packet (0x4)
  if (*payload != 0x4) {
    return XDP_PASS;
  }

  __u32* ping = (__u32*)(payload + 16);
  if ((void *)(ping + 1) > data_end) {
    return XDP_DROP;
  }
  if (*ping != PING_SIG_BE) {
    return XDP_PASS;
  }

  return XDP_TX; // Indicating we need to send back the PONG packet
}

static __always_inline int wg_pong_ping_packet_if_any_ipv4(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  struct iphdr *iph;
  struct udphdr *udph;

  iph = data + sizeof(struct ethhdr);
  if ((void *)(iph + 1) > data_end) {
    return XDP_DROP;
  }

  // ignore non-UDP packet
  if (iph->protocol != IPPROTO_UDP) {
    return XDP_PASS;
  }

  // ignore non-DF packet
  if ((bpf_ntohs(iph->frag_off) & IP_DF) != IP_DF) {
    return XDP_PASS;
  }

  udph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
  if ((void *)(udph + 1) > data_end) {
    return XDP_DROP;
  }

  // ignore non-51820 (wireguard) port
  if (bpf_ntohs(udph->dest) != WG_PORT) {
    return XDP_PASS;
  }

  // Check message type
  __u8* payload = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);
  if ((void *)(payload + 20) > data_end) {
    return XDP_DROP;
  }

  int ret = is_wg_ping_request(payload, data_end);
  if (ret != XDP_TX) {
    return ret;
  }

  // Swap dest and src
  __u32 daddr = iph->daddr;
  iph->daddr = iph->saddr;
  iph->saddr = daddr;

  // Swap ports
  __u16 dest_port = udph->dest;
  udph->dest = udph->source;
  udph->source = dest_port;

  // ping -> pong
  __u8* pong = payload + 17;
  *pong = 'o';
  // fix check sum
  if (udph->check != 0) {
    udph->check = recalc_csum(udph->check, PING_SIG_BE, PONG_SIG_BE);
  }

  // Swap mac addresses
  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end) {
    return XDP_DROP;
  }
  __u8 h_dest[ETH_ALEN];
  __builtin_memcpy(h_dest, eth->h_dest, ETH_ALEN);
  __builtin_memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
  __builtin_memcpy(eth->h_source, h_dest, ETH_ALEN);

  return XDP_TX;
}

static __always_inline int wg_pong_ping_packet_if_any_ipv6(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  struct ipv6hdr *iph6;
  struct udphdr *udph;

  iph6 = data + sizeof(struct ethhdr);
  if ((void *)(iph6 + 1) > data_end) {
    return XDP_DROP;
  }

  // ignore non-UDP packet and also this ignores all fragmented header (44) i.e. non-DF packet
  if (iph6->nexthdr != IPPROTO_UDP) {
    return XDP_PASS;
  }

  udph = data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr);
  if ((void *)(udph + 1) > data_end) {
    return XDP_DROP;
  }

  // ignore non-51820 (wireguard) port
  if (bpf_ntohs(udph->dest) != WG_PORT) {
    return XDP_PASS;
  }

  // Check message type
  __u8* payload = data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + sizeof(struct udphdr);
  if ((void *)(payload + 20) > data_end) {
    return XDP_DROP;
  }

  int ret = is_wg_ping_request(payload, data_end);
  if (ret != XDP_TX) {
    return ret;
  }

  // Swap daddr and saddr
  struct in6_addr daddr;
  __builtin_memcpy(daddr.in6_u.u6_addr32, iph6->saddr.in6_u.u6_addr32, sizeof(struct in6_addr));
  __builtin_memcpy(iph6->daddr.in6_u.u6_addr32, iph6->saddr.in6_u.u6_addr32, sizeof(struct in6_addr));
  __builtin_memcpy(iph6->saddr.in6_u.u6_addr32, daddr.in6_u.u6_addr32, sizeof(struct in6_addr));

  // Swap ports
  __u16 dest_port = udph->dest;
  udph->dest = udph->source;
  udph->source = dest_port;

  // ping -> pong
  __u8* pong = payload + 17;
  *pong = 'o';
  // fix check sum
  if (udph->check != 0) {
    udph->check = recalc_csum(udph->check, PING_SIG_BE, PONG_SIG_BE);
  }

  // Swap mac addresses
  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end) {
    return XDP_DROP;
  }
  __u8 h_dest[ETH_ALEN];
  __builtin_memcpy(h_dest, eth->h_dest, ETH_ALEN);
  __builtin_memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
  __builtin_memcpy(eth->h_source, h_dest, ETH_ALEN);

  return XDP_TX;
}

static __always_inline int wg_pong_ping_packet_if_any(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  struct ethhdr *eth = data;
  __u16 h_proto;

  if ((void *)(eth + 1) > data_end) {
    return XDP_DROP;
  }

  h_proto = bpf_ntohs(eth->h_proto);

  if (h_proto == ETH_P_IP) {
    return wg_pong_ping_packet_if_any_ipv4(ctx);
  }
  if (h_proto == ETH_P_IPV6) {
    return wg_pong_ping_packet_if_any_ipv6(ctx);
  }
  return XDP_PASS;
}
