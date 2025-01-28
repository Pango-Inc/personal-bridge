#include "wg.h"

SEC("xdp_wg")
int xdp_wg_prog(struct xdp_md *ctx) {
  // pong to test wireguard ping packet if any
  int ret = wg_pong_ping_packet_if_any(ctx);
  if (ret != XDP_PASS) {
    return ret;
  }

  return XDP_PASS;
}
