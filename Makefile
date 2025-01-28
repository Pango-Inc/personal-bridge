.PHONY: ebpf build
build: ebpf
	GOOS=linux GOARCH=amd64 go build -o vpnlite ./cmd/vpnlite

ebpf:
	$(MAKE) -C ebpf build
	mv ebpf/vpnlite.o pkg/ebpf/vpnlite.o
	mv ebpf/wg.o pkg/ebpf/wg.o
