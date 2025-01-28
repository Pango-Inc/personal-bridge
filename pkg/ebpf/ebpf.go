package ebpf

import (
	"bytes"
	_ "embed"
	"encoding"
	"encoding/binary"
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

//go:embed pbridge.o
var PBridgeProg []byte

//go:embed wg.o
var WgProg []byte

var ErrKeyNotExist = ebpf.ErrKeyNotExist

func RemoveMemlockLimit() error {
	return unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	})
}

const (
	XDP_FLAGS_UPDATE_IF_NOEXIST = 1 < 0
	XDP_FLAGS_SKB_MODE          = 1 << 1
	XDP_FLAGS_DRV_MODE          = 1 << 2
	XDP_FLAGS_HW_MODE           = 1 << 3
	XDP_FLAGS_REPLACE           = 1 << 4
)

func InstallEbpf(linkName string) (*EbpfHandle, error) {
	link, err := netlink.LinkByName(linkName)
	if err != nil {
		return nil, fmt.Errorf("failed to get link by name: %w", err)
	}

	//if link.Attrs().Xdp != nil {
	//	err = netlink.LinkSetXdpFdWithFlags(link, -1, XDP_FLAGS_SKB_MODE)
	//	if err != nil {
	//		return nil, fmt.Errorf("failed to unload XDP spec: %w", err)
	//	}
	//	// existing maps deletes with delay, need to wait
	//	time.Sleep(5 * time.Second)
	//}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(PBridgeProg))
	if err != nil {
		return nil, fmt.Errorf("failed to load XDP spec: %w", err)
	}

	handle := &EbpfHandle{}
	err = spec.LoadAndAssign(handle, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to assign XDP spec: %w", err)
	}

	err = netlink.LinkSetXdpFdWithFlags(link, handle.PBridgeProg.FD(), XDP_FLAGS_SKB_MODE)
	if err != nil {
		return nil, fmt.Errorf("failed to attach XDP to interface %s: %w", link.Attrs().Name, err)
	}

	return handle, nil
}

type EbpfHandle struct {
	PBridgeProg *ebpf.Program `ebpf:"xdp_pbridge_prog"`
	SrcRules    *ebpf.Map     `ebpf:"src_rules"`
	DstRules    *ebpf.Map     `ebpf:"dst_rules"`
}

type EbpfWgHandle struct {
	WgProg *ebpf.Program `ebpf:"xdp_wg_prog"`
}

func (s *EbpfWgHandle) Close() {
	s.WgProg.Close()
}

func InstallEbpfWg(link netlink.Link) (*EbpfWgHandle, error) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(WgProg))
	if err != nil {
		return nil, fmt.Errorf("wg: failed to load XDP spec: %w", err)
	}

	handle := &EbpfWgHandle{}
	err = spec.LoadAndAssign(handle, nil)
	if err != nil {
		return nil, fmt.Errorf("wg: failed to assign XDP spec: %w", err)
	}

	err = netlink.LinkSetXdpFdWithFlags(link, handle.WgProg.FD(), XDP_FLAGS_SKB_MODE)
	if err != nil {
		return nil, fmt.Errorf("wg: failed to attach XDP to interface %s: %w", link.Attrs().Name, err)
	}

	return handle, nil
}

func (s *EbpfHandle) SetSrcRule(ip net.IP, replace net.IP, ifindex uint32) error {
	key := RuleKey{IP: ip}
	value := RuleValue{Replace: replace, Ifindex: ifindex}
	return s.SrcRules.Put(&key, &value)
}

func (s *EbpfHandle) SetDstRule(ip net.IP, replace net.IP, ifindex uint32) error {
	key := RuleKey{IP: ip}
	value := RuleValue{Replace: replace, Ifindex: ifindex}
	return s.DstRules.Put(&key, &value)
}

func (s *EbpfHandle) DeleteSrcRule(ip net.IP) error {
	key := RuleKey{IP: ip}
	return s.SrcRules.Delete(&key)
}

func (s *EbpfHandle) DeleteDstRule(ip net.IP) error {
	key := RuleKey{IP: ip}
	return s.DstRules.Delete(&key)
}

func (s *EbpfHandle) Close() {
	s.PBridgeProg.Close()
	// s.AccessWhitelist.Close()
	// s.AccessBlacklist.Close()
}

func marshalIP(ip net.IP, data []byte) {
	ip4 := ip.To4()
	if ip4 != nil {
		binary.LittleEndian.PutUint16(data[:2], unix.AF_INET)
		copy(data[4:8], ip4)
	} else {
		binary.LittleEndian.PutUint16(data[:2], unix.AF_INET6)
		copy(data[4:20], ip)
	}
}

func unmarshalIP(data []byte) net.IP {
	family := binary.LittleEndian.Uint16(data[:2])
	if family == unix.AF_INET {
		return net.IP(data[4:8]).To4()
	} else if family == unix.AF_INET6 {
		return net.IP(data[4:20]).To16()
	} else {
		return net.IPv4zero
	}
}

var _ encoding.BinaryMarshaler = (*RuleKey)(nil)

type RuleKey struct {
	IP net.IP
}

func (s *RuleKey) MarshalBinary() ([]byte, error) {
	data := make([]byte, 20)
	marshalIP(s.IP, data)
	return data, nil
}

func (s *RuleKey) UnmarshalBinary(data []byte) error {
	if len(data) != 20 {
		return fmt.Errorf("wrong session key length: expected %d, got %d", 20, len(data))
	}

	s.IP = unmarshalIP(data)
	return nil
}

var _ encoding.BinaryMarshaler = (*RuleValue)(nil)

type RuleValue struct {
	Replace        net.IP
	Ifindex        uint32
	CounterPackets uint64
	CounterBytes   uint64
}

func (s *RuleValue) MarshalBinary() ([]byte, error) {
	data := make([]byte, 40)
	marshalIP(s.Replace, data)
	binary.LittleEndian.PutUint32(data[20:], s.Ifindex)
	binary.LittleEndian.PutUint64(data[24:], s.CounterPackets)
	binary.LittleEndian.PutUint64(data[32:], s.CounterBytes)
	return data, nil
}

func (s *RuleValue) UnmarshalBinary(data []byte) error {
	if len(data) != 40 {
		return fmt.Errorf("wrong session value length: expected %d, got %d", 24, len(data))
	}

	s.Replace = unmarshalIP(data)
	s.Ifindex = binary.LittleEndian.Uint32(data[20:])
	s.CounterPackets = binary.LittleEndian.Uint64(data[24:])
	s.CounterBytes = binary.LittleEndian.Uint64(data[32:])
	return nil
}
