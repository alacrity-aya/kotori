#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define MAX_BACKEND_NUMBER 512

struct endpoint {
  __u32 rip;
  __u32 ports;
};

struct backends {
  __u32 size;
  struct endpoint endpoints[MAX_BACKEND_NUMBER];
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, __be32); // virtual ip address
  __type(value, struct backends);
} ip_map SEC(".maps");

#define PASS 1
#define DROP 0

#define AF_INET 2

static __always_inline __u32 get_bucket_index(__u32 size) {
  __u32 random = bpf_get_prandom_u32();

  if (size == 1)
    return 0;

  // Lemire's Fast Modulo
  return ((__u64)random * (__u64)size) >> 32;
}

SEC("cgroup/connect4")
int load_balance(struct bpf_sock_addr *sk) {

  if (sk->family != AF_INET) {
    return PASS;
  }

  __be32 vip = sk->user_ip4;

  // bpf_printk("vip = %pI4, port = %u", &vip, bpf_ntohl(sk->user_port));

  struct backends *node = bpf_map_lookup_elem(&ip_map, &vip);
  if (node == NULL) {
    return PASS;
  }

  __u32 size = node->size;
  struct endpoint *endpoints = node->endpoints;

  // virtual ip exists but no real ip, reject this.
  if (size == 0) [[clang::unlikely]] {
    return DROP;
  }

  if (size > MAX_BACKEND_NUMBER) {
    size = MAX_BACKEND_NUMBER;
  }

  __u32 index = get_bucket_index(size);
  if (index >= MAX_BACKEND_NUMBER) [[clang::unlikely]] {
    index = 0; // this should be unreachable
  }

  __u32 target_ip = endpoints[index].rip;
  __u32 target_port = endpoints[index].ports;

  sk->user_ip4 = target_ip;
  sk->user_port = target_port;

  return PASS;
}

char _license[] SEC("license") = "GPL";
