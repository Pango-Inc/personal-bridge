package apiserver

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"sort"
	"time"
	"vpnlite/pkg/token"
	"vpnlite/templates"
)

type SessionWithStats struct {
	Session

	TxPackets uint64 `json:"tx_packets"`
	TxBytes   uint64 `json:"tx_bytes"`
	RxPackets uint64 `json:"rx_packets"`
	RxBytes   uint64 `json:"rx_bytes"`
}

type AdminSessionsTemplateParams struct {
	Sessions []*SessionWithStats
}

type AdminLoginTemplateParams struct {
	Error string
}

func (s *Service) handleAdminLogin(w http.ResponseWriter, r *http.Request) {
	message := ""
	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")
		found := false
		for _, a := range s.cfg.Admins {
			if username == a.Username && password == a.Password {
				accessToken, err := token.NewToken(username)
				if err != nil {
					slog.Error("failed to create access token", slog.Any("err", err))
					ErrInternalServerError.WithErrorMsg("Failed to create access token").Handle(w)
					return
				}

				found = true
				http.SetCookie(w, &http.Cookie{
					Name:     "access_token",
					Value:    accessToken,
					Expires:  time.Now().Add(token.ExpireTime),
					HttpOnly: true,
					Secure:   true,
				})
				http.Redirect(w, r, "/admin/dashboard", http.StatusSeeOther)
				break
			}
		}
		if !found {
			message = "Invalid username or password"
		}
	}

	templates.RenderTemplate(w, "admin_login.template.html", &AdminLoginTemplateParams{
		Error: message,
	})
}

func (s *Service) handleAdminDashboard(w http.ResponseWriter, r *http.Request) {
	//renderTemplate(w, "admin_dashboard.template.html", nil)
	templates.RenderTemplate(w, "admin_table.template.html", nil)
}

func (s *Service) handleAdminSessions(w http.ResponseWriter, r *http.Request) {
	s.lock.Lock()
	sessions := make([]*SessionWithStats, 0, len(s.sessions))
	for _, sess := range s.sessions {
		sessions = append(sessions, sess.ToOutputSession())
	}
	s.lock.Unlock()

	// sort by start time
	sort.Slice(sessions, func(i, j int) bool {
		return sessions[i].StartTime.Before(sessions[j].StartTime)
	})

	templates.RenderTemplate(w, "admin_sessions.template.html", &AdminSessionsTemplateParams{
		Sessions: sessions,
	})
}

type AdminAPIStatusResponse struct {
	Sessions   []*SessionWithStats `json:"sessions"`
	ServerName string              `json:"server_name"`
}

func (s *Service) handleAdminAPIStatus(w http.ResponseWriter, r *http.Request) {
	var response AdminAPIStatusResponse
	s.lock.Lock()
	response.Sessions = make([]*SessionWithStats, 0, len(s.sessions))
	for _, sess := range s.sessions {
		response.Sessions = append(response.Sessions, sess.ToOutputSession())
	}
	s.lock.Unlock()

	response.ServerName = s.cfg.ServerName

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("access_token")
		if err != nil {
			http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
			return
		}

		accessToken, err := token.ParseToken(cookie.Value)
		if err != nil {
			http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
			return
		}

		r = r.WithContext(context.WithValue(r.Context(), "access_token", accessToken))

		next(w, r)
	}
}
