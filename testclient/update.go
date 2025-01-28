package testclient

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"time"
)

func updateWorker(client *http.Client, serverUrl, username, password string, connectResponse ConnectResponse) {
	slog.Info("Starting update worker")
	lastUpdate := time.Now()
	ttl := time.Duration(connectResponse.TTL) * time.Second

	for range time.Tick(1 * time.Second) {
		// start attempts to renew the session 30 seconds before it expires
		if time.Since(lastUpdate) < ttl-30*time.Second {
			continue
		}

		// renew the session
		requestUpdate(client, serverUrl, username, password, connectResponse.SessionID)
		lastUpdate = time.Now()
	}
}

func requestUpdate(client *http.Client, serverUrl, username, password, sessionId string) time.Duration {
	request := map[string]any{
		"username":   username,
		"password":   password,
		"session_id": sessionId,
	}
	requestBytes, err := json.Marshal(request)
	if err != nil {
		slog.Error("Failed to marshal update request", slog.Any("err", err))
		os.Exit(1)
		return 0
	}

	requestUrl, err := url.JoinPath(serverUrl, "/wireguard/update")
	if err != nil {
		slog.Error("Failed to join URL", slog.Any("err", err))
		os.Exit(1)
		return 0
	}

	resp, err := client.Post(requestUrl, "application/json", bytes.NewReader(requestBytes))
	if err != nil {
		slog.Error("Failed to request update", slog.Any("err", err))
		os.Exit(1)
		return 0
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		slog.Error("Failed to request update", slog.Any("status", resp.Status))
		os.Exit(1)
		return 0
	}

	var updateResponse struct {
		Result string `json:"result"`
		TTL    int    `json:"ttl"`
	}
	err = json.NewDecoder(resp.Body).Decode(&updateResponse)
	if err != nil {
		slog.Error("Failed to decode update response", slog.Any("err", err))
		os.Exit(1)
		return 0
	}

	if updateResponse.Result != "OK" {
		slog.Error("Failed to update session", slog.String("result", updateResponse.Result))
		os.Exit(1)
		return 0
	}

	ttl := time.Duration(updateResponse.TTL) * time.Second
	if ttl <= 0 {
		slog.Error("Invalid TTL", slog.Any("ttl", updateResponse.TTL))
		os.Exit(1)
		return 0
	}

	return ttl
}
