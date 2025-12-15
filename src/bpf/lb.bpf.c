#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define MAX_BACKEND_NUMBER 1024

struct real_nodes {
  __u32 size;
  __be32 ip_addrs[MAX_BACKEND_NUMBER];
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, __be32); // virtual ip address
  __type(value, struct real_nodes);
} ip_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, __be32); // virtual ip address
  __type(value, __u8); // 0 -> no element
} ip_table SEC(".maps");

#define PASS 1
#define DROP 0

#define AF_INET 2
#define AF_INET 2

__always_inline void load_banalce_impl(struct bpf_sock_addr *sk, __u32 size,
                                       __be32 *ip_addrs) {

  bpf_printk("%s remains to be done\n", __func__);
  return;
}

SEC("cgroup/connect4")
int load_balance(struct bpf_sock_addr *sk) {
  if (sk->family == AF_INET) {
    return PASS;
  }

  __be32 virtual_ip = sk->user_ip4;
  __u8 *exist = bpf_map_lookup_elem(&ip_table, &virtual_ip);

  if (exist == NULL || *exist == 0) {
    return PASS;
  }

  struct real_nodes *node = bpf_map_lookup_elem(&ip_map, &virtual_ip);
  if (node == NULL) {
    return PASS;
  }

  __u32 size = node->size;
  __be32 *ip_addrs = node->ip_addrs;

  if (size == 0) {
    return PASS;
  }

  load_banalce_impl(sk, size, ip_addrs);

  return PASS;
}

char _license[] SEC("license") = "GPL";
