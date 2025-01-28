package apiserver

import (
	"log/slog"
	"time"
)

func (s *Service) expireWorker() {
	for range time.Tick(10 * time.Second) {
		s.dropExpiredSessions()
	}
}

func (s *Service) saveWorker() {
	ticker := time.NewTicker(60 * time.Second)
	for {
		select {
		case <-ticker.C:
		case <-s.saveCh:
		}

		err := s.Save()
		if err != nil {
			slog.Error("failed to save session", slog.Any("err", err))
		}
	}
}

func (s *Service) dropExpiredSessions() {
	s.lock.Lock()
	for pubKey, sess := range s.sessions {
		if time.Since(sess.ExpireTime) > 0 {
			delete(s.sessions, pubKey)

			var err error
			err = s.wgServer.Remove(sess.ServerProfileHandle)
			if err != nil {
				slog.Error("failed to remove peer", slog.Any("err", err))
			}

			err = s.wgClient.Remove(sess.ClientProfileHandle)
			if err != nil {
				slog.Error("failed to remove profile", slog.Any("err", err))
			}
		}
	}
	s.lock.Unlock()
}
