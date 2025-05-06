package apiserver

import (
	"bytes"
	"encoding/json"
	"fmt"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"log/slog"
	"net/http"
	"net/url"
	"pbridge/pkg/wgclient"
	"pbridge/pkg/wgserver"
	"time"
)

type ConnectRequest struct {
	Username        string   `json:"username"`
	Password        string   `json:"password"`
	AccessToken     string   `json:"access_token"`
	ClientPublicKey string   `json:"client_public_key"`
	NextHops        []string `json:"next_hops"`
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

func (s *Service) handleConnect(w http.ResponseWriter, r *http.Request) {
	if err := s.authClient(r); err != nil {
		writeError(w, err)
		return
	}

	var request ConnectRequest
	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		slog.Warn("failed to decode connect request", slog.Any("err", err))
		ErrBadRequest.WithErrorMsg("Invalid json").Handle(w)
		return
	}

	if len(request.NextHops) == 0 {
		slog.Warn("no next_hops in connect request")
		ErrNotAnExitNode.WithErrorMsg("It is not an exit node").Handle(w)
		return
	}
	if len(request.NextHops) > s.cfg.GetMaxHops() {
		slog.Warn("too many hops in connect request")
		ErrTooManyHops.WithErrorMsg("Too many hops").Handle(w)
		return
	}

	for _, nextHop := range request.NextHops {
		_, err = url.Parse(nextHop)
		if err != nil {
			slog.Warn("invalid URL in next_hops", slog.String("url", nextHop), slog.Any("err", err))
			ErrBadRequest.WithErrorMsg("Invalid URL in next_hops").Handle(w)
			return
		}
	}

	nextHop := request.NextHops[0]

	slog.Info("incoming connect", slog.String("username", request.Username), slog.String("next_hop", nextHop),
		slog.String("client_public_key", request.ClientPublicKey))

	// generate new wireguard key pair
	nextHopPrivateKey, err := wgtypes.GenerateKey()
	if err != nil {
		slog.Error("failed to generate wireguard key pair", slog.Any("err", err))
		ErrInternalServerError.WithError(err).Handle(w)
		return
	}

	slog.Info("generated new wireguard key pair", slog.String("username", request.Username),
		slog.String("public_key", nextHopPrivateKey.PublicKey().String()))

	// compose request URL for the next hop
	nextHopUrl, err := url.JoinPath(nextHop, "/wireguard/connect")
	if err != nil { // this error should never happen, we have already checked the URLs in next_hops
		slog.Error("failed to join next hop URL", slog.String("url", nextHop), slog.Any("err", err))
		ErrInternalServerError.WithError(err).Handle(w)
		return
	}

	// prepare request to next hop
	nextHopRequest := ConnectRequest{
		Username:        request.Username,
		Password:        request.Password,
		AccessToken:     request.AccessToken,
		ClientPublicKey: nextHopPrivateKey.PublicKey().String(),
		NextHops:        request.NextHops[1:],
	}
	nextHopRequestBytes, err := json.Marshal(nextHopRequest)
	if err != nil {
		slog.Error("failed to marshal next hop connect request", slog.Any("err", err))
		ErrInternalServerError.WithError(err).Handle(w)
		return
	}

	nextHopReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, nextHopUrl, bytes.NewReader(nextHopRequestBytes))
	if err != nil {
		slog.Error("failed to create next hop request", slog.Any("err", err))
		ErrInternalServerError.WithError(err).Handle(w)
		return
	}
	nextHopReq.Header.Set("Content-Type", "application/json")
	nextHopReq.Header.Set("Accept", "application/json")
	// Skip original IP address forwarding
	// nextHopReq.Header.Set("X-Forwarded-For", getNextHeader(r))

	// send request to next hop
	nextHopResp, err := s.c.Do(nextHopReq)
	if err != nil {
		slog.Warn("failed to send connect request to next hop", slog.String("host", nextHop), slog.Any("err", err))
		ErrNextHopUnavailable.WithError(err).Handle(w)
		return
	}
	defer nextHopResp.Body.Close()

	// forward response from next hop
	if nextHopResp.StatusCode != http.StatusOK {
		var nextHopError ApiError
		err = json.NewDecoder(nextHopResp.Body).Decode(&nextHopError)
		if err != nil {
			slog.Warn("failed to decode error from next hop", slog.String("host", nextHop), slog.Any("err", err))
			ErrInternalServerError.WithError(err).Handle(w)
			return
		}

		slog.Warn("error from next hop connect",
			slog.String("host", request.NextHops[0]),
			slog.String("result", nextHopError.Result),
			slog.String("error_msg", nextHopError.ErrorMsg))

		nextHopError.HttpCode = nextHopResp.StatusCode
		nextHopError.ErrorMsg = fmt.Errorf("error from %s: %s", nextHopReq.URL.Host, nextHopError.ErrorMsg).Error()
		nextHopError.Handle(w)
		return
	}

	// decode response from next hop
	var rresponse ConnectResponse
	err = json.NewDecoder(nextHopResp.Body).Decode(&rresponse)
	if err != nil {
		slog.Warn("failed to decode response from next hop", slog.String("host", nextHop), slog.Any("err", err))
		ErrInternalServerError.WithError(err).Handle(w)
		return
	}

	slog.Info("response from next hop", slog.String("username", request.Username), slog.String("host", nextHop),
		slog.String("result", rresponse.Result),
		slog.String("connect_ip", rresponse.ConnectIP),
		slog.String("internal_ip", rresponse.InternalIP),
		slog.String("session_id", rresponse.SessionID))

	internalIP4, internalIP6, err := s.wgServer.AllocateInternalIPs()
	if err != nil {
		slog.Error("failed to allocate internal IPs", slog.Any("err", err))
		ErrInternalServerError.WithError(err).Handle(w)
		return
	}
	var internalIP4Str, internalIP6Str string
	if internalIP4 != nil {
		internalIP4Str = internalIP4.String()
	}
	if internalIP6 != nil {
		internalIP6Str = internalIP6.String()
	}

	currentTime := time.Now()
	session := &Session{
		Id:              rresponse.SessionID,
		StartTime:       currentTime,
		UpdateTime:      currentTime,
		ExpireTime:      time.Now().Add(time.Duration(rresponse.TTL) * time.Second),
		Username:        request.Username,
		Password:        request.Password,
		AccessToken:     request.AccessToken,
		ClientPublicKey: request.ClientPublicKey,
		NextHops:        request.NextHops,

		NextHopServerPublicKey: rresponse.ServerPublicKey,
		NextHopConnectIP4:      rresponse.ConnectIP,
		NextHopConnectIP6:      rresponse.ConnectIP6,
		NextHopConnectPort:     rresponse.ConnectPort,
		NextHopInternalIP4:     rresponse.InternalIP,
		NextHopInternalIP6:     rresponse.InternalIP6,

		DNS4:                        rresponse.DNS,
		DNS6:                        rresponse.DNS6,
		MTU:                         rresponse.MTU,
		PersistentKeepaliveInterval: rresponse.PersistentKeepaliveInterval,
		RXTimeout:                   rresponse.RXTimeout,

		ClientProfile: &wgclient.Profile{
			ServerIP:                    rresponse.ConnectIP,
			ServerPort:                  rresponse.ConnectPort,
			ServerPublicKey:             rresponse.ServerPublicKey,
			ClientPrivateKey:            nextHopPrivateKey.String(),
			ClientPublicKey:             nextHopPrivateKey.PublicKey().String(),
			InternalIP4:                 rresponse.InternalIP,
			InternalIP6:                 rresponse.InternalIP6,
			PersistentKeepaliveInterval: rresponse.PersistentKeepaliveInterval,
			MTU:                         rresponse.MTU,
		},
		ServerProfile: &wgserver.ServerProfile{
			ClientPublicKey: request.ClientPublicKey,
			ServerPublicKey: s.wgServer.GetPublicKey(),
			KeepAlive:       rresponse.PersistentKeepaliveInterval,
			InternalIP4:     internalIP4Str,
			InternalIP6:     internalIP6Str,
		},
	}

	err = s.setupSession(session)
	if err != nil {
		slog.Error("failed to setup session", slog.Any("err", err))
		ErrInternalServerError.WithError(err).Handle(w)
		return
	}

	serverIP4, serverIP6 := s.wgServer.GetIPs()
	var serverIP4Str, serverIP6Str string
	if serverIP4 != nil {
		serverIP4Str = serverIP4.String()
	}
	if serverIP6 != nil {
		serverIP6Str = serverIP6.String()
	}

	var internalIP4Len, internalIP6Len int
	if internalIP4Str != "" {
		internalIP4Len = 32
	}
	if internalIP6Str != "" {
		internalIP6Len = 128
	}

	slog.Info("connected", slog.String("username", request.Username), slog.String("session_id", rresponse.SessionID),
		slog.String("internal_ip", rresponse.InternalIP), slog.String("internal_ip6", rresponse.InternalIP6))

	writeResponse(w, http.StatusOK, ConnectResponse{
		Result:                      "OK",
		SessionID:                   session.Id,
		ServerPublicKey:             s.wgServer.GetPublicKey(),
		InternalIP:                  internalIP4Str,
		InternalIPLen:               internalIP4Len,
		InternalIP6:                 internalIP6Str,
		InternalIP6Len:              internalIP6Len,
		ConnectIP:                   serverIP4Str,
		ConnectIP6:                  serverIP6Str,
		ConnectPort:                 s.wgServer.GetListenPort(),
		DNS:                         rresponse.DNS,
		DNS6:                        rresponse.DNS6,
		MTU:                         rresponse.MTU,
		PersistentKeepaliveInterval: rresponse.PersistentKeepaliveInterval,
		RXTimeout:                   rresponse.RXTimeout,
		TTL:                         rresponse.TTL,
	})
}
