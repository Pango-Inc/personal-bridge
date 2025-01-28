package wgclient

import (
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"vpnlite/pkg/config"
	"vpnlite/pkg/ebpf"
	"vpnlite/pkg/nic"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const defaulClientInterfacePrefix = "wgc"

type Service struct {
	nicPool   *nic.NICPool
	ctrl      *wgctrl.Client
	nicPrefix string

	lock           sync.Mutex
	clientsCounter uint64
	clients        map[uint64]*ProfileHandle
}

func New(cfg *config.WireguardClientConfig) *Service {
	nicPrefix := defaulClientInterfacePrefix
	if cfg.NicPrefix != "" {
		nicPrefix = cfg.NicPrefix
	}
	return &Service{
		nicPool:   nic.NewNICPool(),
		clients:   make(map[uint64]*ProfileHandle),
		nicPrefix: nicPrefix,
	}
}

func (s *Service) Init() error {
	slog.Info("client: initialization")
	err := s.cleanup()
	if err != nil {
		return fmt.Errorf("cleanup client odd wireguard network interfaces: %w", err)
	}
	ctrl, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("create wireguard netlink client: %w", err)
	}
	s.ctrl = ctrl
	return nil
}

func (s *Service) cleanup() error {
	slog.Info(fmt.Sprintf("client: start cleanup odd wireguard network interfaces %s%%d", s.nicPrefix))
	// Iterate over all nics and delete matched nics by prefix
	linkList, err := netlink.LinkList()
	if err != nil {
		return fmt.Errorf("get link list failed: %w", err)
	}
	for _, link := range linkList {
		// Check form wgc%d
		linkName := link.Attrs().Name
		after, ok := strings.CutPrefix(linkName, s.nicPrefix)
		if !ok || after == "" {
			continue
		}
		_, err := strconv.ParseUint(after, 10, 64)
		if err != nil {
			continue
		}
		if err := netlink.LinkDel(link); err != nil {
			return fmt.Errorf("delete existing wireguard interface %s: %w", linkName, err)
		}
		slog.Info(fmt.Sprintf("client: existing wireguard interface deleted: %s", linkName))
	}
	slog.Info(fmt.Sprintf("client: complete cleanup odd wireguard network interfaces %s%%d", s.nicPrefix))
	return nil
}

func (s *Service) Add(profile *Profile) (*ProfileHandle, error) {
	// validate
	if net.ParseIP(profile.ServerIP) == nil {
		return nil, fmt.Errorf("invalid server IP: %s", profile.ServerIP)
	}

	if profile.ServerPort == 0 {
		return nil, fmt.Errorf("invalid server port: %d", profile.ServerPort)
	}

	clientPrivateKey, err := wgtypes.ParseKey(profile.ClientPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("parse client private key: %w", err)
	}

	internalIP4 := net.ParseIP(profile.InternalIP4)
	if internalIP4 == nil {
		return nil, fmt.Errorf("invalid internal IP4: %s", profile.InternalIP4)
	}

	var internalIP6 net.IP
	if profile.InternalIP6 != "" {
		internalIP6 = net.ParseIP(profile.InternalIP6)
		if internalIP6 == nil {
			return nil, fmt.Errorf("invalid internal IP6: %s", profile.InternalIP6)
		}
	}

	if profile.PersistentKeepaliveInterval < 0 {
		return nil, fmt.Errorf("invalid persistent keepalive interval: %d", profile.PersistentKeepaliveInterval)
	}

	// prepare
	serverPublicKey, err := wgtypes.ParseKey(profile.ServerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("parse server public key: %w", err)
	}

	nicId, err := s.nicPool.GetNIC()
	if err != nil {
		return nil, err
	}
	// wdc0 ... wdcN
	nicName := fmt.Sprintf("%s%d", s.nicPrefix, nicId)

	persistentKeepaliveInterval := time.Duration(profile.PersistentKeepaliveInterval) * time.Second

	var allowedIPs []net.IPNet
	allowedIPs = append(allowedIPs, net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)})
	if profile.InternalIP6 != "" {
		allowedIPs = append(allowedIPs, net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)})
	}

	// Create a new Wireguard interface
	if link, err := netlink.LinkByName(nicName); err == nil {
		if err := netlink.LinkDel(link); err != nil {
			return nil, fmt.Errorf("delete existing wireguard interface %s: %w", nicName, err)
		}
	}

	err = netlink.LinkAdd(&netlink.Wireguard{
		LinkAttrs: netlink.LinkAttrs{
			Name: nicName,
			MTU:  profile.MTU,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("create wireguard interface %s: %w", nicName, err)
	}

	err = s.ctrl.ConfigureDevice(nicName, wgtypes.Config{
		PrivateKey:   &clientPrivateKey,
		ReplacePeers: true,
		Peers: []wgtypes.PeerConfig{
			{
				PublicKey:                   serverPublicKey,
				Endpoint:                    &net.UDPAddr{IP: net.ParseIP(profile.ServerIP), Port: profile.ServerPort},
				PersistentKeepaliveInterval: &persistentKeepaliveInterval,
				AllowedIPs:                  allowedIPs,
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("configure wireguard interface: %w", err)
	}

	handle, err := ebpf.InstallEbpf(nicName)
	if err != nil {
		return nil, fmt.Errorf("install ebpf filter: %w", err)
	}

	link, err := netlink.LinkByName(nicName)
	if err != nil {
		return nil, fmt.Errorf("get wireguard link: %w", err)
	}

	slog.Info("client: wireguard interface created", slog.String("name", nicName),
		slog.Int("ifindex", link.Attrs().Index))

	err = netlink.LinkSetUp(link)
	if err != nil {
		return nil, fmt.Errorf("set wireguard interface up: %w", err)
	}

	s.lock.Lock()
	defer s.lock.Unlock()

	id := s.clientsCounter
	s.clientsCounter++

	instance := &ProfileHandle{
		id:         id,
		nicId:      nicId,
		nicName:    nicName,
		privateKey: clientPrivateKey,
		handle:     handle,
		link:       link,
		ip4:        internalIP4,
		ip6:        internalIP6,
	}
	s.clients[id] = instance
	return instance, nil
}

func (s *Service) Remove(instance *ProfileHandle) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	instance, ok := s.clients[instance.id]
	if !ok {
		return fmt.Errorf("client not found: %d", instance.id)
	}

	err := netlink.LinkDel(instance.link)
	if err != nil {
		return fmt.Errorf("delete wireguard interface: %w", err)
	}

	s.nicPool.FreeNIC(instance.nicId)
	instance.handle.Close()
	delete(s.clients, instance.id)
	return nil
}
