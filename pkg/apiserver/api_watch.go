package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"time"
)

type WatchRequest struct {
	SessionID string `json:"session_id"`
}

type WatchResponse struct {
	Result string `json:"result"`
}

func (s *Service) handleWatch(w http.ResponseWriter, r *http.Request) {
	if err := s.authClient(r); err != nil {
		writeError(w, err)
		return
	}

	var request WatchRequest
	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		slog.Warn("failed to decode watch request", slog.Any("err", err))
		ErrBadRequest.WithErrorMsg("Invalid json").Handle(w)
		return
	}

	slog.Info("watch request", slog.String("session_id", request.SessionID))

	s.lock.Lock()
	sess, ok := s.sessions[request.SessionID]
	s.lock.Unlock()

	if !ok {
		slog.Warn("session not found on watch", slog.String("session_id", request.SessionID))
		ErrSessionNotFound.Handle(w)
		return
	}

	nextHopUrl, err := url.JoinPath(sess.NextHops[0], "/wireguard/watch")
	if err != nil {
		slog.Error("failed to join next hop url", slog.Any("err", err))
		ErrInternalServerError.WithError(err).Handle(w)
		return
	}

	nextHopRequest := request
	nextHopRequestBytes, err := json.Marshal(nextHopRequest)
	if err != nil {
		slog.Error("failed to marshal watch request", slog.Any("err", err))
		ErrInternalServerError.WithError(err).Handle(w)
		return
	}

	ctx := r.Context()
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	nextHopReq, err := http.NewRequestWithContext(ctx, http.MethodPost, nextHopUrl, bytes.NewReader(nextHopRequestBytes))
	if err != nil {
		slog.Error("failed to create watch request", slog.Any("err", err))
		ErrInternalServerError.WithError(err).Handle(w)
		return
	}
	nextHopReq.Header.Set("Content-Type", "application/json")
	nextHopReq.Header.Set("Accept", "application/json")

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
			slog.Error("failed to decode error from next hop watch",
				slog.String("host", sess.NextHops[0]),
				slog.String("status", nextHopResp.Status),
				slog.Any("err", err))
			ErrInternalServerError.WithError(err).Handle(w)
			return
		}

		slog.Warn("error from next hop watch",
			slog.String("host", sess.NextHops[0]),
			slog.String("result", nextHopError.Result),
			slog.String("error_msg", nextHopError.ErrorMsg))

		nextHopError.HttpCode = nextHopResp.StatusCode
		nextHopError.ErrorMsg = "Error from " + nextHopUrl + ": " + nextHopError.ErrorMsg

		writeResponse(w, nextHopResp.StatusCode, &nextHopError)
		return
	}

	var nextHopResponse WatchResponse
	err = json.NewDecoder(nextHopResp.Body).Decode(&nextHopResponse)
	if err != nil {
		slog.Error("failed to decode response from next hop watch",
			slog.String("host", sess.NextHops[0]),
			slog.Any("err", err))
		ErrInternalServerError.WithError(err).Handle(w)
		return
	}

	writeResponse(w, http.StatusOK, &nextHopResponse)
}
