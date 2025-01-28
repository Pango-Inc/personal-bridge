package apiserver

import (
	"time"
	"vpnlite/pkg/wgclient"
	"vpnlite/pkg/wgserver"
)

type Session struct {
	Id         string    `json:"id"`
	StartTime  time.Time `json:"start_time"`
	UpdateTime time.Time `json:"update_time"`
	ExpireTime time.Time `json:"expire_time"`

	// auth data from connect request
	Username    string `json:"username,omitempty"`
	Password    string `json:"password,omitempty"`
	AccessToken string `json:"access_token,omitempty"`

	ClientPublicKey string   `json:"client_public_key,omitempty"`
	NextHops        []string `json:"next_hops,omitempty"`

	NextHopServerPublicKey string `json:"next_hop_server_public_key,omitempty"`
	NextHopConnectIP4      string `json:"next_hop_connect_ip4,omitempty"`
	NextHopConnectIP6      string `json:"next_hop_connect_ip6,omitempty"`
	NextHopConnectPort     int    `json:"next_hop_connect_port,omitempty"`
	NextHopInternalIP4     string `json:"next_hop_internal_ip4,omitempty"`
	NextHopInternalIP6     string `json:"next_hop_internal_ip6,omitempty"`

	DNS4                        string `json:"dns4,omitempty"`
	DNS6                        string `json:"dns6,omitempty"`
	MTU                         int    `json:"mtu,omitempty"`
	PersistentKeepaliveInterval int    `json:"persistent_keepalive_interval,omitempty"`
	RXTimeout                   int    `json:"rx_timeout,omitempty"`

	// wireguard profiles
	ClientProfile *wgclient.Profile       `json:"client_profile,omitempty"`
	ServerProfile *wgserver.ServerProfile `json:"server_profile,omitempty"`

	// runtime handlers
	ServerProfileHandle *wgserver.ProfileHandle `json:"-"`
	ClientProfileHandle *wgclient.ProfileHandle `json:"-"`
}

// CloneRepresentation returns a copy of the session with raw data removed.
func (s *Session) ToOutputSession() *SessionWithStats {
	txPackets, txBytes := s.ServerProfileHandle.GetStats()
	rxPackets, rxBytes := s.ClientProfileHandle.GetStats()

	return &SessionWithStats{
		Session:   *s,
		TxPackets: txPackets,
		TxBytes:   txBytes,
		RxPackets: rxPackets,
		RxBytes:   rxBytes,
	}
}
