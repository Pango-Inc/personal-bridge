package apiserver

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"time"
)

type UpdateRequest struct {
	Username    string `json:"username"`
	Password    string `json:"password"`
	AccessToken string `json:"access_token"`
	SessionID   string `json:"session_id"`
}

type UpdateResponse struct {
	Result string `json:"result"`
	TTL    int    `json:"ttl"`
}

func (s *Service) handleUpdate(w http.ResponseWriter, r *http.Request) {
	if err := s.authClient(r); err != nil {
		writeError(w, err)
		return
	}

	var request UpdateRequest
	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		slog.Warn("failed to decode update request", slog.Any("err", err))
		ErrBadRequest.WithErrorMsg("Invalid json").Handle(w)
		return
	}

	// TODO: handle disconnected sessions for traffic limits - or maybe we don't need to do it explicitly - it will be
	// handler by exit node

	slog.Info("update request", slog.String("session_id", request.SessionID))

	s.lock.Lock()
	sess, ok := s.sessions[request.SessionID]
	s.lock.Unlock()

	if !ok {
		slog.Warn("session not found on update", slog.String("session_id", request.SessionID))
		ErrSessionNotFound.Handle(w)
		return
	}

	nextHopUrl, err := url.JoinPath(sess.NextHops[0], "/wireguard/update")
	if err != nil {
		slog.Error("failed to join next hop url", slog.Any("err", err))
		ErrInternalServerError.WithError(err).Handle(w)
		return
	}

	nextHopRequest := request
	nextHopRequestBytes, err := json.Marshal(nextHopRequest)
	if err != nil {
		slog.Error("failed to marshal update request", slog.Any("err", err))
		ErrInternalServerError.WithError(err).Handle(w)
		return
	}

	nextHopReq, err := http.NewRequest(http.MethodPost, nextHopUrl, bytes.NewReader(nextHopRequestBytes))
	if err != nil {
		slog.Error("failed to create update request", slog.Any("err", err))
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
			slog.Error("failed to decode error from next hop update",
				slog.String("host", sess.NextHops[0]),
				slog.String("status", nextHopResp.Status),
				slog.Any("err", err))
			ErrInternalServerError.WithError(err).Handle(w)
			return
		}

		slog.Warn("error from next hop update",
			slog.String("host", sess.NextHops[0]),
			slog.String("result", nextHopError.Result),
			slog.String("error_msg", nextHopError.ErrorMsg))

		nextHopError.HttpCode = nextHopResp.StatusCode
		nextHopError.ErrorMsg = "Error from " + nextHopUrl + ": " + nextHopError.ErrorMsg

		writeResponse(w, nextHopResp.StatusCode, &nextHopError)
		return
	}

	var nextHopResponse UpdateResponse
	err = json.NewDecoder(nextHopResp.Body).Decode(&nextHopResponse)
	if err != nil {
		slog.Error("failed to decode response from next hop update",
			slog.String("host", sess.NextHops[0]),
			slog.Any("err", err))
		ErrInternalServerError.WithError(err).Handle(w)
		return
	}

	s.lock.Lock()
	currentTime := time.Now()
	sess.UpdateTime = currentTime
	sess.ExpireTime = currentTime.Add(time.Duration(nextHopResponse.TTL) * time.Second)
	s.lock.Unlock()

	writeResponse(w, http.StatusOK, &nextHopResponse)
}
