#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define MAX_BACKEND_NUMBER 1024

struct backends {
  __u32 size;
  __be32 rips[MAX_BACKEND_NUMBER];
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

#define barrier_var(var) asm volatile("" : "+r"(var))

__always_inline void load_banalce_impl(struct bpf_sock_addr *sk, __u32 size,
                                       __be32 *rips) {
  __u32 random_index = bpf_get_prandom_u32();
  random_index %= size;
  barrier_var(random_index); // make verifier happy
  random_index &= (MAX_BACKEND_NUMBER - 1);

  __u32 target_ip = rips[random_index];
  sk->user_ip4 = target_ip;
  bpf_printk("LB: Selected index %u, IP: %pI4", random_index, &target_ip);
}

SEC("cgroup/connect4")
int load_balance(struct bpf_sock_addr *sk) {

  if (sk->family != AF_INET) {
    return PASS;
  }

  __be32 vip = sk->user_ip4;

  bpf_printk("vip = %pI4", &vip);

  struct backends *node = bpf_map_lookup_elem(&ip_map, &vip);
  if (node == NULL) {
    bpf_printk("node == NULL, pass");
    return PASS;
  }

  __u32 size = node->size;
  __be32 *rips = node->rips;

  // virtual ip exists, but no real ip, reject this.
  if (size == 0) [[clang::unlikely]] {
    return DROP;
  }

  if (size > MAX_BACKEND_NUMBER) {
    size = MAX_BACKEND_NUMBER;
  }

  load_banalce_impl(sk, size, rips);

  return PASS;
}

char _license[] SEC("license") = "GPL";
