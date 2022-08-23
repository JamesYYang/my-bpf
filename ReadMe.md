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
  -v /lib/modules:/lib/modules:ro \
  -v /usr/src:/usr/src:ro \
  -v /boot:/boot:ro \
  -v /sys/kernel/debug:/sys/kernel/debug \
  mbpf:0.0.1
```