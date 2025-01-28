#include "headers.h"
#include "types.h"
#include "maps.h"
#include "pbridge_ipv4.h"
#include "pbridge_ipv6.h"

SEC("xdp_pbridge")
int xdp_pbridge_prog(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  if (data + 8 > data_end) {
    // check if the packet is empty
    return XDP_DROP;
  }

  switch (*(__u8*)data >> 4) {
    case 4:
      return handle_ipv4(ctx);
    case 6:
      return handle_ipv6(ctx);
    default:
      return XDP_PASS;
  }
}

char _license[] SEC("license") = "MIT";
