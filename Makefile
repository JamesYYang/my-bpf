all: build-ebpf build-assets build run

build-ebpf:
	mkdir -p ebpf/bin
	clang -g -O2 -c -I./ebpf/headers -target bpf -D__TARGET_ARCH_x86 -o ebpf/bin/kp.o ebpf/kp.c
	clang -g -O2 -c -I./ebpf/headers -target bpf -D__TARGET_ARCH_x86 -o ebpf/bin/tp.o ebpf/tp.c
	clang -g -O2 -c -I./ebpf/headers -target bpf -D__TARGET_ARCH_x86 -o ebpf/bin/tcp_connect.o ebpf/tcp_connect.c

build-assets:
	go run github.com/shuLhan/go-bindata/cmd/go-bindata -pkg assets -o "assets/probe.go" $(wildcard ebpf/bin/*.o)

build:
	go build -o mbpf

run:
	./mbpf

clean:
	rm -f ebpf/bin/*.o mbpf