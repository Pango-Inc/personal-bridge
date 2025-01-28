package templates

import (
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
	"vpnlite/pkg/apiserver"
)

func TestTemplateAdminSessions(t *testing.T) {
	w := httptest.NewRecorder()
	renderTemplate(w, "admin_sessions.template.html", &apiserver.AdminSessionsTemplateParams{
		Sessions: []*apiserver.SessionWithStats{
			{
				Session: apiserver.Session{
					Id:         "1",
					StartTime:  time.Now(),
					UpdateTime: time.Now(),
					ExpireTime: time.Now().Add(time.Hour),
					Username:   "user1",
				},
			},
		},
	})
	require.Equal(t, http.StatusOK, w.Code)
	require.Contains(t, w.Body.String(), "user1")
}
