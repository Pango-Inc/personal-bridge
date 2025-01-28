package apiserver

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path"
	"strings"
	"time"
)

func (s *Service) Save() error {
	s.lock.Lock()
	sessionList := make([]*Session, 0, len(s.sessions))
	for _, session := range s.sessions {
		if time.Since(session.ExpireTime) > 0 {
			continue
		}
		sessionList = append(sessionList, session)
	}
	s.lock.Unlock()

	return saveSessions(sessionList, s.cfg.SessionStorage)
}

func (s *Service) Load() error {
	sessionList, err := loadSessions(s.cfg.SessionStorage)
	if err != nil {
		return err
	}

	serverPublicKey := s.wgServer.GetPublicKey()
	for _, session := range sessionList {
		if time.Since(session.ExpireTime) > 0 {
			continue
		}

		if session.ServerProfile.ServerPublicKey != serverPublicKey {
			continue
		}

		s.wgServer.ReserveInternalIPs(
			net.ParseIP(session.ServerProfile.InternalIP4),
			net.ParseIP(session.ServerProfile.InternalIP6),
		)

		err = s.setupSession(session)
		if err != nil {
			return fmt.Errorf("failed to setup session: %v", err)
		}
	}

	return nil
}

func saveSessions(sessionList []*Session, sessionDir string) error {
	err := os.MkdirAll(sessionDir, 0755)
	if err != nil {
		return fmt.Errorf("failed to create session storage directory: %v", err)
	}

	savedSessionMap := make(map[string]struct{})
	for _, session := range sessionList {
		tempSessionFile := path.Join(sessionDir, fmt.Sprintf("%s.tmp.json", session.Id))
		sessionFile := path.Join(sessionDir, fmt.Sprintf("%s.json", session.Id))

		fd, err := os.Create(tempSessionFile)
		if err != nil {
			return fmt.Errorf("failed to create session file: %v", err)
		}

		e := json.NewEncoder(fd)
		e.SetIndent("", "  ")
		err = e.Encode(session)
		if err != nil {
			return fmt.Errorf("failed to encode session: %v", err)
		}

		err = fd.Close()
		if err != nil {
			return fmt.Errorf("failed to close session file: %v", err)
		}

		err = os.Rename(tempSessionFile, sessionFile)
		if err != nil {
			return fmt.Errorf("failed to rename session file: %v", err)
		}

		savedSessionMap[session.Id] = struct{}{}
	}

	fileList, err := os.ReadDir(sessionDir)
	if err != nil {
		return fmt.Errorf("failed to read session storage directory: %v", err)
	}

	for _, file := range fileList {
		if file.IsDir() {
			continue
		}

		// Remove temp session files
		if strings.HasSuffix(file.Name(), ".tmp.json") {
			err := os.Remove(path.Join(sessionDir, file.Name()))
			if err != nil {
				return fmt.Errorf("failed to remove temp session file: %v", err)
			}
			continue
		}

		if !strings.HasSuffix(file.Name(), ".json") {
			continue
		}

		// Remove session files that are not in the session map
		id := strings.TrimSuffix(file.Name(), ".json")
		if _, ok := savedSessionMap[id]; !ok {
			err := os.Remove(path.Join(sessionDir, file.Name()))
			if err != nil {
				return fmt.Errorf("failed to remove session file: %v", err)
			}
			continue
		}
	}

	return nil
}

func loadSessions(sessionDir string) ([]*Session, error) {
	fileList, err := os.ReadDir(sessionDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read session storage directory: %v", err)
	}

	sessionList := make([]*Session, 0, len(fileList))
	for _, file := range fileList {
		if file.IsDir() {
			continue
		}

		if !strings.HasSuffix(file.Name(), ".json") {
			continue
		}

		fd, err := os.Open(path.Join(sessionDir, file.Name()))
		if err != nil {
			return nil, fmt.Errorf("failed to open session file: %v", err)
		}

		var session Session
		d := json.NewDecoder(fd)
		err = d.Decode(&session)
		if err != nil {
			return nil, fmt.Errorf("failed to decode session: %v", err)
		}

		err = fd.Close()
		if err != nil {
			return nil, fmt.Errorf("failed to close session file: %v", err)
		}

		sessionList = append(sessionList, &session)
	}

	return sessionList, nil
}
