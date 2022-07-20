all: build-ebpf build run

build-ebpf:
	mkdir -p ebpf/bin
	clang -g -O2 -c -I./ebpf/headers -target bpf -D__TARGET_ARCH_x86 -o ebpf/bin/probe.o ebpf/kp.c
	go run github.com/shuLhan/go-bindata/cmd/go-bindata -pkg main -prefix "ebpf/bin" -o "probe.go" "ebpf/bin/probe.o"

build:
	go build -o mbpf

run:
	./mbpf

clean:
	rm -f ebpf/bin/probe.o mbpf