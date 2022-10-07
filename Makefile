all: build-ebpf build-assets build

build-ebpf:
	mkdir -p ebpf/bin
	clang -g -O2 -c -I./ebpf/headers -target bpf -D__TARGET_ARCH_x86 -o ./ebpf/bin/sys_execve.o ./ebpf/sys_execve.c
	clang -g -O2 -c -I./ebpf/headers -target bpf -D__TARGET_ARCH_x86 -o ./ebpf/bin/sys_openat.o ./ebpf/sys_openat.c
	clang -g -O2 -c -I./ebpf/headers -target bpf -D__TARGET_ARCH_x86 -o ./ebpf/bin/tcp_connect.o ./ebpf/tcp_connect.c
	clang -g -O2 -c -I./ebpf/headers -target bpf -D__TARGET_ARCH_x86 -o ./ebpf/bin/tcp_reset.o ./ebpf/tcp_reset.c
	clang -g -O2 -c -I./ebpf/headers -target bpf -D__TARGET_ARCH_x86 -o ./ebpf/bin/tcp_retrans.o ./ebpf/tcp_retrans.c
	clang -g -O2 -c -I./ebpf/headers -target bpf -D__TARGET_ARCH_x86 -o ./ebpf/bin/tc_capture.o ./ebpf/tc_capture.c
	clang -g -O2 -c -I./ebpf/headers -target bpf -D__TARGET_ARCH_x86 -o ./ebpf/bin/udp_dns.o ./ebpf/udp_dns.c
	clang -g -O2 -c -I./ebpf/headers -target bpf -D__TARGET_ARCH_x86 -o ./ebpf/bin/udp_connect.o ./ebpf/udp_connect.c

build-assets:
	go run github.com/shuLhan/go-bindata/cmd/go-bindata -pkg assets -o "./assets/probe.go" $(wildcard ./ebpf/bin/*.o)

build:
	go build -o mbpf

run:
	./mbpf

clean:
	rm -f ebpf/bin/*.o mbpf