FROM ubuntu:jammy

RUN apt-get update && apt-get install -y golang-go make clang llvm dumb-init

WORKDIR /dist

COPY ./assets /dist/assets

COPY ./config /dist/config

COPY ./ebpf /dist/ebpf

COPY ./modules /dist/modules

COPY ./go.mod /dist/

COPY ./go.sum /dist/

COPY ./mbpf.go /dist/

COPY ./Makefile /dist/

RUN go env -w GOPROXY=https://proxy.golang.com.cn,direct

RUN go env -w GOINSECURE=github.com

RUN go env

RUN make

ENTRYPOINT ["dumb-init", "--"]

CMD ["./mbpf"]