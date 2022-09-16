# Do some research on ebpf

## Install packages on Ubuntu 22.04

```sh
sudo apt-get update
sudo apt-get install golang-go
sudo apt-get install make clang llvm
```

## Generate vmlinux.h

```sh
bpftool btf dump file /sys/kernel/btf/vmlinux format c > ebpf/headers/vmlinux.h
```

[Intro vmlinux.h](https://www.ebpf.top/post/intro_vmlinux_h/)

[BPF and CO-RE](https://www.ebpf.top/post/bpf_core/)

[BTF with Linux Distribution](https://github.com/aquasecurity/btfhub/blob/main/docs/supported-distros.md)

[BTF Hub Archive](https://github.com/aquasecurity/btfhub-archive)

## Run

```sh
make
```

## Run in container

```sh
docker run -d \
  --name=mbpf \
  --net=host \
  --privileged \
  -v /sys/kernel/debug:/sys/kernel/debug \
  jamesyyang/mbpf:0.0.6
```

## Reference

[深入理解 iptables 和 netfilter 架构](http://arthurchiao.art/blog/deep-dive-into-iptables-and-netfilter-arch-zh/)

[Cilium：BPF 和 XDP 参考指南](https://arthurchiao.art/blog/cilium-bpf-xdp-reference-guide-zh/)

[BPF 程序（BPF Prog）类型详解](https://arthurchiao.art/blog/bpf-advanced-notes-1-zh/)

[eBPF观测HTTP](https://mp.weixin.qq.com/s/2ncM-PvN06lSwScvc2Zueg)

[Facebook 流量路由最佳实践](http://arthurchiao.art/blog/facebook-from-xdp-to-socket-zh/)

[基于 BPF/XDP 实现 K8s Service 负载均衡](http://arthurchiao.art/blog/cilium-k8s-service-lb-zh/)

[Cracking Kubernetes Node Proxy](http://arthurchiao.art/blog/cracking-k8s-node-proxy/)

[Life of a Packet in Cilium](http://arthurchiao.art/blog/cilium-life-of-a-packet-pod-to-service-zh/)

[深入理解 Cilium 的 eBPF 收发包路径](http://arthurchiao.art/blog/understanding-ebpf-datapath-in-cilium-zh/)
