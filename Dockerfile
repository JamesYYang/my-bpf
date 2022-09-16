FROM ubuntu:jammy

RUN apt-get update 

RUN apt-get install -y ca-certificates

RUN apt-get install -y golang-go make clang llvm dumb-init

WORKDIR /dist

COPY ./assets /dist/assets

COPY ./config /dist/config

COPY ./ebpf /dist/ebpf

COPY ./modules /dist/modules

COPY ./k8s /dist/k8s

COPY ./go.mod /dist/

COPY ./go.sum /dist/

COPY ./mbpf.go /dist/

COPY ./Makefile /dist/

RUN go env -w GOPROXY=https://goproxy.cn,direct

RUN make

ENTRYPOINT ["dumb-init", "--"]

CMD ["./mbpf"]