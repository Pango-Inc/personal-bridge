package wgserver

import (
	"encoding/base64"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"

	"pbridge/pkg/config"
	"pbridge/pkg/ebpf"
	"pbridge/pkg/ippool"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const defaulServerInterfacePrefix = "wgs"

type Service struct {
	cfg        *config.WireguardServerConfig
	privateKey wgtypes.Key
	publicKey  wgtypes.Key
	client     *wgctrl.Client
	link       *netlink.Wireguard
	handle     *ebpf.EbpfHandle
	handleWg   *ebpf.EbpfWgHandle
	ip4        net.IP
	ip6        net.IP
	ipPool4    *ippool.IPPool
	ipPool6    *ippool.IPPool

	lock     sync.Mutex
	profiles map[string]*ProfileHandle
}

func New(cfg *config.WireguardServerConfig) *Service {
	return &Service{
		cfg:      cfg,
		profiles: map[string]*ProfileHandle{},
	}
}

func (s *Service) getServerInterfaceName() string {
	serverInterfacePrefix := defaulServerInterfacePrefix
	if s.cfg.NicPrefix != "" {
		serverInterfacePrefix = s.cfg.NicPrefix
	}
	// wgs0
	return serverInterfacePrefix + "0"
}

func (s *Service) Init() error {
	slog.Info("server: initialization")

	err := s.initWgHandler()
	if err != nil {
		return fmt.Errorf("server: init wireguard handler: %w", err)
	}

	ip4, ip6, err := GetDefaultIPs()
	if err != nil {
		return fmt.Errorf("get default IPs: %w", err)
	}

	slog.Info("server: default IPs", slog.Any("ip4", ip4), slog.Any("ip6", ip6))

	slog.Info("server: create wireguard ip pool")
	ipPool4, err := ippool.New("wg4", s.cfg.Subnet4)
	if err != nil {
		return fmt.Errorf("create wireguard ip pool: %w", err)
	}

	var ipPool6 *ippool.IPPool
	if s.cfg.Subnet6 != "" {
		ipPool6, err = ippool.New("wg6", s.cfg.Subnet6)
		if err != nil {
			return fmt.Errorf("create wireguard ip pool: %w", err)
		}
	}

	slog.Info("server: load wireguard private key", slog.String("file", s.cfg.PrivateKeyFile))
	privateKeyData, err := os.ReadFile(s.cfg.PrivateKeyFile)
	if err != nil {
		if os.IsNotExist(err) {
			slog.Info("server: wireguard private key file not found, generating a new one")
			privateKey, err := wgtypes.GeneratePrivateKey()
			if err != nil {
				return fmt.Errorf("generate private key: %w", err)
			}
			privateKeyData = []byte(base64.StdEncoding.EncodeToString(privateKey[:]))
			if err := os.WriteFile(s.cfg.PrivateKeyFile, privateKeyData, 0o600); err != nil {
				return fmt.Errorf("write private key file: %w", err)
			}
		} else {
			return fmt.Errorf("reading wireguard private key file: %w", err)
		}
	}

	privateKey, err := wgtypes.ParseKey(string(privateKeyData))
	if err != nil {
		return fmt.Errorf("parse private key: %w", err)
	}

	slog.Info("server: wireguard private key loaded", slog.String("public_key", privateKey.PublicKey().String()))

	slog.Info("server: create wireguard netlink client")
	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("create wireguard netlink client: %w", err)
	}

	serverInterfaceName := s.getServerInterfaceName()

	if link, err := netlink.LinkByName(serverInterfaceName); err == nil {
		slog.Info("server: wireguard interface already exists, removing")
		if err := netlink.LinkDel(link); err != nil {
			return fmt.Errorf("remove wireguard interface: %w", err)
		}
	}

	slog.Info("server: creating wireguard interface", slog.String("link", serverInterfaceName))

	link := &netlink.Wireguard{
		LinkAttrs: netlink.LinkAttrs{
			Name: serverInterfaceName,
		},
	}

	err = netlink.LinkAdd(link)
	if err != nil {
		return fmt.Errorf("add wireguard interface: %w", err)
	}

	slog.Info("server: wireguard interface created", slog.String("link", serverInterfaceName))

	for _, subnet := range []string{s.cfg.Subnet4, s.cfg.Subnet6} {
		addr, err := netlink.ParseAddr(subnet)
		if err != nil {
			return fmt.Errorf("parse wireguard subnet: %w", err)
		}

		slog.Info("server: add subnet to wireguard interface", slog.String("link", serverInterfaceName), slog.String("subnet", subnet))
		err = netlink.AddrAdd(link, addr)
		if err != nil {
			return fmt.Errorf("add subnet to wireguard interface: %w", err)
		}
	}

	slog.Info("server: configure wireguard interface", slog.String("link", serverInterfaceName))
	err = client.ConfigureDevice(serverInterfaceName, wgtypes.Config{
		PrivateKey: &privateKey,
		ListenPort: &s.cfg.ListenPort,
	})
	if err != nil {
		return fmt.Errorf("configure wireguard interface: %w", err)
	}

	slog.Info("server: install ebpf filter", slog.String("link", serverInterfaceName))
	handle, err := ebpf.InstallEbpf(serverInterfaceName)
	if err != nil {
		return fmt.Errorf("install ebpf filter: %w", err)
	}

	slog.Info("server: start wireguard interface", slog.String("link", serverInterfaceName))
	err = netlink.LinkSetUp(link)
	if err != nil {
		return fmt.Errorf("failed to set up wireguard interface: %w", err)
	}

	s.client = client
	s.privateKey = privateKey
	s.publicKey = privateKey.PublicKey()
	s.link = link
	s.handle = handle
	s.ip4 = ip4
	s.ip6 = ip6
	s.ipPool4 = ipPool4
	s.ipPool6 = ipPool6
	return nil
}

func (s *Service) Add(profile *ServerProfile) (*ProfileHandle, error) {
	slog.Info("server: add peer", slog.String("public_key", profile.ClientPublicKey))

	pubKey, err := wgtypes.ParseKey(profile.ClientPublicKey)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %v", err)
	}

	ip4 := net.ParseIP(profile.InternalIP4)
	ip6 := net.ParseIP(profile.InternalIP6)

	allowedIPs := []net.IPNet{
		{IP: ip4, Mask: net.CIDRMask(32, 32)},
	}
	if ip6 != nil {
		allowedIPs = append(allowedIPs, net.IPNet{IP: ip6, Mask: net.CIDRMask(128, 128)})
	}

	keepAliveDuration := time.Duration(profile.KeepAlive) * time.Second

	wgpeer := &wgtypes.PeerConfig{
		PublicKey:                   pubKey,
		Endpoint:                    &net.UDPAddr{IP: s.ip4, Port: s.cfg.ListenPort},
		AllowedIPs:                  allowedIPs,
		PersistentKeepaliveInterval: &keepAliveDuration,
	}

	s.lock.Lock()
	defer s.lock.Unlock()

	if _, ok := s.profiles[profile.ClientPublicKey]; ok {
		s.ipPool4.Release(ip4)
		if ip6 != nil {
			s.ipPool6.Release(ip6)
		}
		return nil, fmt.Errorf("peer already exists")
	}

	peer := &ProfileHandle{
		WGPeer: wgpeer,
		IP4:    ip4,
		IP6:    ip6,
		handle: s.handle,
	}
	s.profiles[profile.ClientPublicKey] = peer

	err = s.updatePeersLocked()
	if err != nil {
		s.ipPool4.Release(ip4)
		if ip6 != nil {
			s.ipPool6.Release(ip6)
		}
		return nil, fmt.Errorf("update peers: %v", err)
	}

	return peer, nil
}

func (s *Service) Remove(handle *ProfileHandle) error {
	publicKey := handle.WGPeer.PublicKey.String()
	slog.Info("server: remove peer", slog.String("public_key", publicKey))

	s.lock.Lock()
	defer s.lock.Unlock()

	_, ok := s.profiles[publicKey]
	if !ok {
		return fmt.Errorf("peer not found")
	}

	delete(s.profiles, publicKey)
	err := s.updatePeersLocked()
	if err != nil {
		return fmt.Errorf("update peers: %v", err)
	}

	if handle.IP4 != nil {
		s.ipPool4.Release(handle.IP4)
		err = s.handle.DeleteSrcRule(handle.IP4)
		if err != nil {
			slog.Error("server: delete src rule", slog.Any("ip", handle.IP4), slog.Any("error", err))
		}
	}

	if handle.IP6 != nil {
		s.ipPool6.Release(handle.IP6)
		err = s.handle.DeleteSrcRule(handle.IP6)
		if err != nil {
			slog.Error("server: delete src rule", slog.Any("ip", handle.IP6), slog.Any("error", err))
		}
	}

	return nil
}

func (s *Service) updatePeersLocked() error {
	peers := make([]wgtypes.PeerConfig, 0, len(s.profiles)+1)
	for _, peer := range s.profiles {
		peers = append(peers, *peer.WGPeer)
	}
	serverInterfaceName := s.getServerInterfaceName()
	err := s.client.ConfigureDevice(serverInterfaceName, wgtypes.Config{
		Peers: peers,
	})
	if err != nil {
		return fmt.Errorf("configure wireguard interface: %v", err)
	}
	return nil
}

func (s *Service) GetPublicKey() string {
	return s.publicKey.String()
}

func (s *Service) GetListenPort() int {
	return s.cfg.ListenPort
}

func (s *Service) GetIPs() (net.IP, net.IP) {
	return s.ip4, s.ip6
}

func (s *Service) GetLink() uint32 {
	return uint32(s.link.Attrs().Index)
}

func (s *Service) AllocateInternalIPs() (net.IP, net.IP, error) {
	ip4 := s.ipPool4.Acquire()
	if ip4 == nil {
		return nil, nil, fmt.Errorf("no more IPv4 addresses")
	}

	var ip6 net.IP
	if s.ipPool6 != nil {
		ip6 = s.ipPool6.Acquire()
		if ip6 == nil {
			s.ipPool4.Release(ip4)
			return nil, nil, fmt.Errorf("no more IPv6 addresses")
		}
	}

	return ip4, ip6, nil
}

func (s *Service) ReserveInternalIPs(ip4, ip6 net.IP) {
	if ip4 != nil {
		s.ipPool4.SetAcquired(ip4)
	}

	if ip6 != nil {
		s.ipPool6.SetAcquired(ip6)
	}
}

func (s *Service) DumpMaps() {
	slog.Info("server: dump maps", slog.Int("ifindex", s.link.Attrs().Index))
	var k ebpf.RuleKey
	var v ebpf.RuleValue
	it := s.handle.SrcRules.Iterate()
	for it.Next(&k, &v) {
		slog.Info("server: src map entry",
			slog.String("key", k.IP.String()),
			slog.String("value_ip", v.Replace.String()),
			slog.Int("value_ifindex", int(v.Ifindex)))
	}

	it = s.handle.DstRules.Iterate()
	for it.Next(&k, &v) {
		slog.Info("server: dst map entry",
			slog.String("key", k.IP.String()),
			slog.String("value_ip", v.Replace.String()),
			slog.Int("value_ifindex", int(v.Ifindex)))
	}
}

func (s *Service) Close() {
	s.handle.Close()
	s.handleWg.Close()
}

func (s *Service) initWgHandler() error {
	externalLink, _, err := GetExternalLink(unix.AF_INET)
	if err != nil {
		return fmt.Errorf("failed to find external network interface: %w", err)
	}

	slog.Info("server: install ebpf wg filter prog", slog.String("link", externalLink.Attrs().Name))
	handleWg, err := ebpf.InstallEbpfWg(externalLink)
	if err != nil {
		return fmt.Errorf("install ebpf filter: %v", err)
	}

	s.handleWg = handleWg
	return nil
}
