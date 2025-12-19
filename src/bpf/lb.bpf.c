#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define MAX_BACKEND_NUMBER 1024

struct real_nodes {
  __u32 size;
  __be32 rips[MAX_BACKEND_NUMBER];
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, __be32); // virtual ip address
  __type(value, struct real_nodes);
} ip_map SEC(".maps");

#define PASS 1
#define DROP 0

#define AF_INET 2
#define AF_INET 2

__always_inline void load_banalce_impl(struct bpf_sock_addr *sk, __u32 size,
                                       __be32 *rips) {

  bpf_printk("%s remains to be done\n", __func__);
  return;
}

SEC("cgroup/connect4")
int load_balance(struct bpf_sock_addr *sk) {
  if (sk->family == AF_INET) {
    return PASS;
  }

  __be32 vip = sk->user_ip4;

  struct real_nodes *node = bpf_map_lookup_elem(&ip_map, &vip);
  if (node == NULL) {
    return PASS;
  }

  __u32 size = node->size;
  __be32 *rips = node->rips;

  if (size == 0) {
    return PASS;
  }

  load_banalce_impl(sk, size, rips);

  return PASS;
}

char _license[] SEC("license") = "GPL";
