package wgclient

type Profile struct {
	ServerIP                    string `json:"server_ip"`
	ServerPort                  int    `json:"server_port"`
	ServerPublicKey             string `json:"server_public_key"`
	ClientPrivateKey            string `json:"client_private_key"`
	ClientPublicKey             string `json:"client_public_key"`
	InternalIP4                 string `json:"internal_ip4"`
	InternalIP6                 string `json:"internal_ip6"`
	PersistentKeepaliveInterval int    `json:"persistent_keepalive_interval"`
	MTU                         int    `json:"mtu"`
}
