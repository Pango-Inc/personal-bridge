package testclient

import (
	"bytes"
	"encoding/json"
	"github.com/henvic/httpretty"
	"github.com/lmittmann/tint"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"time"
)

func Connect(username, password string, servers []string) {
	// It is a test client. Pretty print and color everything.
	slog.SetDefault(slog.New(
		tint.NewHandler(os.Stderr, &tint.Options{
			Level:      slog.LevelDebug,
			TimeFormat: time.DateTime,
		}),
	))

	httpLogger := &httpretty.Logger{
		Time:           true,
		TLS:            true,
		RequestHeader:  true,
		RequestBody:    true,
		ResponseHeader: true,
		ResponseBody:   true,
		Colors:         true, // erase line if you don't like colors
		Formatters:     []httpretty.Formatter{&httpretty.JSONFormatter{}},
	}
	client := &http.Client{
		Transport: httpLogger.RoundTripper(http.DefaultTransport),
	}

	if len(servers) == 0 {
		slog.Error("No servers provided")
		return
	}

	dockerPrepare()

	// create temporary directory
	clientDir, err := os.MkdirTemp("", "pbridge-testclient-*")
	if err != nil {
		slog.Error("Failed to create temporary directory", slog.Any("err", err))
		return
	}
	slog.Debug("Created temporary client directory", slog.Any("dir", clientDir))
	defer func() {
		slog.Debug("Remove temporary client directory", slog.Any("dir", clientDir))
		_ = os.RemoveAll(clientDir)
	}()

	slog.Info("Generate new wireguard keys...")
	clientPrivateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		slog.Error("failed to generate private key", slog.Any("err", err))
		return
	}

	slog.Debug("Client wireguard private key", slog.Any("key", clientPrivateKey.String()))
	slog.Debug("Client wireguard public key", slog.Any("key", clientPrivateKey.PublicKey().String()))

	slog.Info("Call /wireguard/connect...")

	serverUrl := servers[0]
	nextHops := servers[1:]
	request := map[string]any{
		"username":          username,
		"password":          password,
		"client_public_key": clientPrivateKey.PublicKey().String(),
	}
	if len(nextHops) > 0 {
		request["next_hops"] = nextHops
	}
	requestBytes, err := json.Marshal(request)
	if err != nil {
		slog.Error("Failed to marshal request", slog.Any("err", err))
		return
	}

	requestUrl, err := url.JoinPath(serverUrl, "/wireguard/connect")
	if err != nil {
		slog.Error("Failed to join URL", slog.Any("err", err))
		return
	}

	resp, err := client.Post(requestUrl, "application/json", bytes.NewReader(requestBytes))
	if err != nil {
		slog.Error("Failed to request connect", slog.Any("err", err))
		return
	}
	if resp.StatusCode != http.StatusOK {
		slog.Error("Failed to request connect", slog.Any("status", resp.Status))
		return
	}

	var connectResponse ConnectResponse
	err = json.NewDecoder(resp.Body).Decode(&connectResponse)
	if err != nil {
		slog.Error("Failed to decode connect response", slog.Any("err", err))
		return
	}

	prepareWireguardConfig(clientDir, clientPrivateKey.String(), connectResponse)
	dockerRunClient(clientDir)
	updateWorker(client, serverUrl, username, password, connectResponse)
}

type ConnectResponse struct {
	Result                      string `json:"result"`
	SessionID                   string `json:"session_id"`
	ServerPublicKey             string `json:"server_public_key"`
	InternalIP                  string `json:"internal_ip"`
	InternalIPLen               int    `json:"internal_ip_len"`
	InternalIP6                 string `json:"internal_ip6,omitempty"`
	InternalIP6Len              int    `json:"internal_ip6_len,omitempty"`
	ConnectIP                   string `json:"connect_ip"`
	ConnectIP6                  string `json:"connect_ip6,omitempty"`
	ConnectPort                 int    `json:"connect_port"`
	DNS                         string `json:"dns"`
	DNS6                        string `json:"dns6,omitempty"`
	MTU                         int    `json:"mtu"`
	PersistentKeepaliveInterval int    `json:"persistent_keepalive_interval"`
	RXTimeout                   int    `json:"rx_timeout"`
	TTL                         int    `json:"ttl"`
}
