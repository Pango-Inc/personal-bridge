.PHONY: ebpf build
build: ebpf
	GOOS=linux GOARCH=amd64 go build -o pbridge ./cmd/pbridge

ebpf:
	$(MAKE) -C ebpf build
	mv ebpf/pbridge.o pkg/ebpf/pbridge.o
	mv ebpf/wg.o pkg/ebpf/wg.o
