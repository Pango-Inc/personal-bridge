package apiserver

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
)

type DisconnectRequest struct {
	Username    string `json:"username"`
	Password    string `json:"password"`
	AccessToken string `json:"access_token"`
	SessionID   string `json:"session_id"`
}

type DisconnectResponse struct {
	Result string `json:"result"`
}

func (s *Service) handleDisconnect(w http.ResponseWriter, r *http.Request) {
	if err := s.authClient(r); err != nil {
		writeError(w, err)
		return
	}

	defer r.Body.Close()
	var request DisconnectRequest
	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		slog.Warn("failed to decode disconnect request", slog.Any("err", err))
		ErrBadRequest.WithError(err).Handle(w)
		return
	}

	// search for session
	s.lock.Lock()
	sess, ok := s.sessions[request.SessionID]
	if ok {
		delete(s.sessions, request.SessionID)
	}
	s.lock.Unlock()

	if !ok {
		slog.Warn("session not found on disconnect", slog.String("session_id", request.SessionID))
		ErrSessionNotFound.Handle(w)
		return
	}

	// remove session
	err = s.wgServer.Remove(sess.ServerProfileHandle)
	if err != nil {
		slog.Error("failed to remove peer", slog.Any("err", err))
		// ignore error, disconnect still needs to be propagated
	}

	err = s.wgClient.Remove(sess.ClientProfileHandle)
	if err != nil {
		slog.Error("failed to remove profile", slog.Any("err", err))
		// ignore error, disconnect still needs to be propagated
	}

	// send disconnect request to next hop
	nextHopUrl, err := url.JoinPath(sess.NextHops[0], "/wireguard/disconnect")
	if err != nil {
		slog.Error("failed to join next hop url", slog.Any("err", err))
		ErrInternalServerError.WithError(err).Handle(w)
		return
	}

	nextHopRequest := request
	nextHopRequestBytes, err := json.Marshal(nextHopRequest)
	if err != nil {
		slog.Error("failed to marshal disconnect request", slog.Any("err", err))
		ErrInternalServerError.WithError(err).Handle(w)
		return
	}

	nextHopReq, err := http.NewRequest(http.MethodPost, nextHopUrl, bytes.NewReader(nextHopRequestBytes))
	if err != nil {
		slog.Error("failed to create disconnect request", slog.Any("err", err))
		ErrInternalServerError.WithError(err).Handle(w)
		return
	}
	nextHopReq.Header.Set("Content-Type", "application/json")
	nextHopReq.Header.Set("Accept", "application/json")
	// Skip origin IP address forwarding
	//nextHopReq.Header.Set("X-Forwarded-For", getNextHeader(r))

	nextHopResp, err := s.c.Do(nextHopReq)
	if err != nil {
		ErrInternalServerError.WithError(err).Handle(w)
		return
	}
	defer nextHopResp.Body.Close()

	if nextHopResp.StatusCode != http.StatusOK {
		var nextHopError ApiError
		err = json.NewDecoder(nextHopResp.Body).Decode(&nextHopError)
		if err != nil {
			slog.Error("failed to decode error from next hop disconnect",
				slog.String("host", sess.NextHops[0]),
				slog.String("status", nextHopResp.Status),
				slog.Any("err", err))
			ErrInternalServerError.WithError(err).Handle(w)
			return
		}

		slog.Warn("error from next hop disconnect",
			slog.String("host", sess.NextHops[0]),
			slog.String("result", nextHopError.Result),
			slog.String("error_msg", nextHopError.ErrorMsg))

		nextHopError.HttpCode = nextHopResp.StatusCode
		nextHopError.ErrorMsg = "Error from " + nextHopUrl + ": " + nextHopError.ErrorMsg

		writeResponse(w, nextHopResp.StatusCode, &nextHopError)
		return
	}

	var nextHopResponse DisconnectResponse
	err = json.NewDecoder(nextHopResp.Body).Decode(&nextHopResponse)
	if err != nil {
		slog.Error("failed to decode response from next hop disconnect",
			slog.String("host", sess.NextHops[0]),
			slog.Any("err", err))
		ErrInternalServerError.WithError(err).Handle(w)
		return
	}

	writeResponse(w, http.StatusOK, DisconnectResponse{Result: "OK"})
}
