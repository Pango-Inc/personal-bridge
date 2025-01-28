FROM fedora:34 AS builder

RUN dnf install -y make clang llvm gcc libbpf libbpf-devel libxdp libxdp-devel xdp-tools bpftool kernel-headers glibc-devel glibc-devel.i686 \
  iputils curl wget iproute vim

COPY . /src
WORKDIR /src
RUN clang -O2 -target bpf -c pbridge.c -o pbridge.o
RUN clang -O2 -target bpf -c wg.c -o wg.o

FROM scratch
COPY --from=builder /src/pbridge.o /pbridge.o
COPY --from=builder /src/wg.o /wg.o

