#ifndef __EBPF_MAPS_H
#define __EBPF_MAPS_H

#include "types.h"

struct bpf_map_def SEC("maps") src_rules = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct ip_address),
    .value_size = sizeof(struct rule),
    .max_entries = 32768,
};

struct bpf_map_def SEC("maps") dst_rules = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct ip_address),
    .value_size = sizeof(struct rule),
    .max_entries = 32768,
};

#endif