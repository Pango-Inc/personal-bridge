package apiserver

import (
	"fmt"
	"log/slog"
	"net"
)

func (s *Service) setupSession(session *Session) error {
	var err error

	slog.Info("start wireguard connection to upstream", slog.String("username", session.Username))
	session.ClientProfileHandle, err = s.wgClient.Add(session.ClientProfile)
	if err != nil {
		return fmt.Errorf("failed to add client profile: %v", err)
	}

	slog.Info("start wireguard connection to downstream", slog.String("username", session.Username))
	session.ServerProfileHandle, err = s.wgServer.Add(session.ServerProfile)
	if err != nil {
		if err := s.wgClient.Remove(session.ClientProfileHandle); err != nil {
			slog.Error("failed to cleanup client profile",
				slog.Any("originalErr", err), slog.Any("cleanupErr", err))
		}

		return fmt.Errorf("failed to add peer: %v", err)
	}

	slog.Info("setup server forwarding", slog.String("username", session.Username))
	err = session.ServerProfileHandle.SetupForwarding(net.ParseIP(session.NextHopInternalIP4), net.ParseIP(session.NextHopInternalIP6), session.ClientProfileHandle.GetLink())
	if err != nil {
		if err := s.wgClient.Remove(session.ClientProfileHandle); err != nil {
			slog.Error("failed to cleanup client profile",
				slog.Any("originalErr", err), slog.Any("cleanupErr", err))
		}

		if err := s.wgServer.Remove(session.ServerProfileHandle); err != nil {
			slog.Error("failed to cleanup server profile",
				slog.Any("originalErr", err), slog.Any("cleanupErr", err))
		}

		return fmt.Errorf("failed to setup server forwarding: %v", err)
	}

	slog.Info("setup client forwarding", slog.String("username", session.Username))
	err = session.ClientProfileHandle.SetupForwarding(session.ServerProfileHandle.IP4, session.ServerProfileHandle.IP6, s.wgServer.GetLink())
	if err != nil {
		if err := s.wgClient.Remove(session.ClientProfileHandle); err != nil {
			slog.Error("failed to cleanup client profile",
				slog.Any("originalErr", err), slog.Any("cleanupErr", err))
		}

		if err := s.wgServer.Remove(session.ServerProfileHandle); err != nil {
			slog.Error("failed to cleanup server profile",
				slog.Any("originalErr", err), slog.Any("cleanupErr", err))
		}

		return fmt.Errorf("failed to setup client forwarding: %v", err)
	}

	s.lock.Lock()
	s.sessions[session.Id] = session
	s.lock.Unlock()

	slog.Info("session setup complete", slog.String("username", session.Username))

	select {
	case s.saveCh <- struct{}{}:
	default:
	}

	return nil
}
