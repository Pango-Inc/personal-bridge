package apiserver

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
)

type ApiError struct {
	HttpCode int    `json:"-"`
	Result   string `json:"result"`
	ErrorMsg string `json:"error"`
}

var ErrInternalServerError = &ApiError{
	HttpCode: http.StatusInternalServerError,
	Result:   "INTERNAL_SERVER_ERROR",
}

var ErrBadRequest = &ApiError{
	HttpCode: http.StatusBadRequest,
	Result:   "BAD_REQUEST",
}

var ErrUnauthorized = &ApiError{
	HttpCode: http.StatusUnauthorized,
	Result:   "UNAUTHORIZED",
}

var ErrForbidden = &ApiError{
	HttpCode: http.StatusForbidden,
	Result:   "FORBIDDEN",
}

var ErrSessionNotFound = &ApiError{
	HttpCode: http.StatusNotFound,
	Result:   "SESSION_NOT_FOUND",
	ErrorMsg: "Session not found",
}

var ErrNextHopUnavailable = &ApiError{
	HttpCode: http.StatusBadGateway,
	Result:   "NEXT_HOP_UNAVAILABLE",
	ErrorMsg: "Next hop unavailable",
}

func (s ApiError) WithErrorMsg(errorMsg string) *ApiError {
	s.ErrorMsg = errorMsg
	return &s
}

func (s ApiError) WithError(err error) *ApiError {
	s.ErrorMsg = err.Error()
	return &s
}

func (s *ApiError) Error() string {
	return fmt.Sprintf("ApiError %d %s %s", s.HttpCode, s.Result, s.ErrorMsg)
}

func (s *ApiError) Handle(w http.ResponseWriter) {
	writeError(w, s)
}

func writeResponse(w http.ResponseWriter, statusCode int, r any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	e := json.NewEncoder(w)
	_ = e.Encode(r)
}

func writeError(w http.ResponseWriter, err error) {
	if apiError, ok := err.(*ApiError); ok {
		writeResponse(w, apiError.HttpCode, apiError)
		return
	}

	ErrInternalServerError.WithError(err).Handle(w)
}

func getClientIP(r *http.Request) string {
	forwardedIp := r.Header.Get("X-Forwarded-For")
	if forwardedIp != "" {
		// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Forwarded-For#syntax
		return strings.TrimSpace(strings.Split(forwardedIp, ",")[0])
	}

	remoteIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return remoteIP
	}
	return r.RemoteAddr
}

func getNextHeader(r *http.Request) string {
	remoteIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	h := r.Header.Get("X-Forwarded-For")
	if h != "" {
		return h + ", " + remoteIP
	}
	return remoteIP
}
