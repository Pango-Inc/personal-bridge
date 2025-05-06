package apiserver

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"pbridge/pkg/config"
	"pbridge/pkg/listeners"
	"pbridge/pkg/wgclient"
	"pbridge/pkg/wgserver"
	"sync"
)

type Service struct {
	http.Handler

	cfg      config.APIConfig
	c        *http.Client
	wgServer *wgserver.Service
	wgClient *wgclient.Service

	saveCh chan struct{}

	lock     sync.Mutex
	sessions map[string]*Session
}

func New(cfg config.APIConfig, wgServer *wgserver.Service, wgClient *wgclient.Service) (*Service, error) {
	s := &Service{
		cfg:      cfg,
		c:        &http.Client{},
		wgServer: wgServer,
		wgClient: wgClient,
		saveCh:   make(chan struct{}, 1),
		sessions: map[string]*Session{},
	}

	// load trust CA if provided
	if cfg.TrustCAFile != "" {
		trustCaPem, err := os.ReadFile(cfg.TrustCAFile)
		if err != nil {
			return nil, fmt.Errorf("error reading trust CA file: %v", err)
		}

		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(trustCaPem)
		tlsConfig := &tls.Config{
			RootCAs: caCertPool,
		}
		s.c.Transport = &http.Transport{
			TLSClientConfig: tlsConfig,
		}
	}

	r := http.NewServeMux()
	r.HandleFunc("POST /wireguard/connect", s.handleConnect)
	r.HandleFunc("POST /wireguard/update", s.handleUpdate)
	r.HandleFunc("POST /wireguard/watch", s.handleWatch)
	r.HandleFunc("POST /wireguard/disconnect", s.handleDisconnect)

	r.HandleFunc("/admin/login", s.handleAdminLogin)
	r.HandleFunc("GET /admin/dashboard", authMiddleware(s.handleAdminDashboard))
	r.HandleFunc("GET /admin/sessions", authMiddleware(s.handleAdminSessions))

	r.HandleFunc("/admin/api/status", authMiddleware(s.handleAdminAPIStatus))

	s.Handler = r

	go s.expireWorker()
	go s.saveWorker()

	return s, nil
}

func (s *Service) ListenAndServe() error {
	// TODO: load sessions from storage
	// TODO: backup sessions to storage
	for _, listenCfg := range s.cfg.Listen {
		slog.Info("listen API", slog.String("addr", listenCfg.Addr))
		listener, err := listeners.Listen(listenCfg)
		if err != nil {
			return err
		}

		go func() {
			err := http.Serve(listener, s)
			if err != nil {
				if errors.Is(err, http.ErrServerClosed) {
					slog.Info("server closed", slog.String("addr", listenCfg.Addr))
				} else {
					slog.Error("error serving", slog.String("addr", listenCfg.Addr), slog.Any("err", err))
				}
			}
		}()
	}

	return nil
}

func (s *Service) authClient(r *http.Request) error {
	if len(s.cfg.Clients) > 0 {
		username, password, ok := r.BasicAuth()
		if !ok {
			return ErrUnauthorized.WithErrorMsg("Basic auth required")
		}

		found := false
		for _, client := range s.cfg.Clients {
			if client.Username == username && client.Password == password {
				found = true
				break
			}
		}

		if !found {
			return ErrUnauthorized.WithErrorMsg("Invalid username or password")
		}
	}

	return nil
}
