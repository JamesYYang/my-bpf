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
  jamesyyang/mbpf:0.0.4
```