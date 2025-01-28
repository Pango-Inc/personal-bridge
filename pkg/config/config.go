package config

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"path"

	"github.com/ghodss/yaml"
)

type Config struct {
	Logging   LoggingConfig   `json:"logging"`
	API       APIConfig       `json:"api"`
	Wireguard WireguardConfig `json:"wireguard"`
}

type WireguardConfig struct {
	Server WireguardServerConfig `json:"server"`
	Client WireguardClientConfig `json:"client"`
}

type WireguardServerConfig struct {
	PrivateKeyFile string `json:"private_key_file"`
	ListenPort     int    `json:"listen_port"`
	Subnet4        string `json:"subnet4"`
	Subnet6        string `json:"subnet6"`
	// Use "wgs" prefix if empty or not specified
	NicPrefix string `json:"nic_prefix"`
}

type WireguardClientConfig struct {
	// Use "wgc" prefix if empty or not specified
	NicPrefix string `json:"nic_prefix"`
}

type LoggingConfig struct {
	Level  slog.Level `json:"level"`
	Format string     `json:"format"`
}

type APIConfig struct {
	ServerName     string         `json:"server_name"`
	Listen         []ListenConfig `json:"listen"`
	MaxHops        int            `json:"max_hops,omitempty"`
	Admins         []AdminRecord  `json:"admins"`
	Clients        []ClientRecord `json:"clients"`
	SessionStorage string         `json:"session_storage"`
	TrustCAFile    string         `json:"trust_ca_file"`
}

type AdminRecord struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type ClientRecord struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type ListenConfig struct {
	Addr string `json:"addr"`
	TLS  *struct {
		Static *struct {
			Crt string `json:"crt"`
			Key string `json:"key"`
		}
		Acme *struct {
			CacheDir string   `json:"cache_dir"`
			Domains  []string `json:"domains"`
		}
	}
}

func Load(configPath string) (*Config, error) {
	var cfg Config

	configData, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("error reading config file: %v", err)
	}

	switch path.Ext(configPath) {
	case ".yaml", ".yml":
		if err = yaml.Unmarshal(configData, &cfg); err != nil {
			return nil, fmt.Errorf("error unmarshalling config data: %v", err)
		}
	case ".json":
		if err = yaml.Unmarshal(configData, &cfg); err != nil {
			return nil, fmt.Errorf("error unmarshalling config data: %v", err)
		}
	default:
		return nil, fmt.Errorf("unsupported config file format: %s", path.Ext(configPath))
	}
	// Unmarshal the config data into the cfg struct

	if len(cfg.API.Admins) == 0 {
		var pwdBytes [16]byte
		_, _ = rand.Read(pwdBytes[:])
		pwd := hex.EncodeToString(pwdBytes[:])

		cfg.API.Admins = []AdminRecord{{
			Username: "admin",
			Password: pwd,
		}}
		slog.Warn("admin accounts are not configured, use random password to access dashboard",
			"password", pwd)
	}

	if len(cfg.API.Clients) == 0 {
		slog.Info("clients are not configured, server will be accessible without authentication")
	}

	return &cfg, nil
}

func (s APIConfig) GetMaxHops() int {
	if s.MaxHops == 0 {
		return 32
	}
	return s.MaxHops
}
