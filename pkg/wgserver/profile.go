package wgserver

type ServerProfile struct {
	ClientPublicKey string `json:"client_public_key"`
	ServerPublicKey string `json:"server_public_key"`
	KeepAlive       int    `json:"keep_alive"`
	InternalIP4     string `json:"internal_ip4"`
	InternalIP6     string `json:"internal_ip6"`
}
