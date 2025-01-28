package listeners

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"golang.org/x/crypto/acme/autocert"
	"net"
	"vpnlite/pkg/config"
)

func Listen(cfg config.ListenConfig) (net.Listener, error) {
	// Load the TLS configuration if it is provided
	var tlsConfig *tls.Config
	if cfg.TLS != nil {
		if cfg.TLS.Static != nil {
			if cfg.TLS.Static.Crt != "" && cfg.TLS.Static.Key != "" {
				crt, err := loadPemCertificate([]byte(cfg.TLS.Static.Crt), []byte(cfg.TLS.Static.Key))
				if err != nil {
					return nil, fmt.Errorf("error loading static certificate: %v", err)
				}
				tlsConfig = &tls.Config{
					Certificates: []tls.Certificate{*crt},
				}
			}
		}
		if cfg.TLS.Acme != nil {
			ac := &autocert.Manager{
				Prompt:     autocert.AcceptTOS,
				Cache:      autocert.DirCache(cfg.TLS.Acme.CacheDir),
				HostPolicy: autocert.HostWhitelist(cfg.TLS.Acme.Domains...),
			}
			tlsConfig = ac.TLSConfig()
		}
	}

	// Listen on the provided address
	listener, err := net.Listen("tcp", cfg.Addr)
	if err != nil {
		return nil, fmt.Errorf("error listening on %s: %v", cfg.Addr, err)
	}

	// Wrap the listener with the TLS configuration if it is provided
	if tlsConfig != nil {
		listener = tls.NewListener(listener, tlsConfig)
	}

	return listener, nil
}

func loadPemCertificate(crtPem, keyPem []byte) (*tls.Certificate, error) {
	crt, err := tls.X509KeyPair(crtPem, keyPem)
	if err != nil {
		return nil, fmt.Errorf("failed to parse x509 key pair: %w", err)
	}
	if len(crt.Certificate) == 0 {
		return nil, fmt.Errorf("list of certificates is empty")
	}

	crt.Leaf, err = x509.ParseCertificate(crt.Certificate[0])
	if err != nil {
		return nil, err
	}

	return &crt, nil
}
