#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define MAXN 128

SEC("cgroup/connect4")
int load_balance(struct bpf_sock_addr *sk) {
  bpf_printk("receive a packet");
  return 1;
}

char _license[] SEC("license") = "GPL";
