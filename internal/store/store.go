package store

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"

	"nimbus/internal/model"
)

type Store struct {
	mu   sync.RWMutex
	path string
	data model.State
}

func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	s := &Store{path: filepath.Join(dir, "state.json")}
	s.data.Settings = model.DefaultSettings()
	if raw, err := os.ReadFile(s.path); err == nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, &s.data); err != nil {
			return nil, err
		}
	}
	if s.data.Settings.MixedPort == 0 {
		s.data.Settings = model.DefaultSettings()
	}
	if s.data.Subscriptions == nil {
		s.data.Subscriptions = []model.Subscription{}
	}
	if s.data.Nodes == nil {
		s.data.Nodes = []model.Node{}
	}
	return s, nil
}

func (s *Store) Snapshot() model.State {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneState(s.data)
}

func (s *Store) Settings() model.Settings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.data.Settings
}

func (s *Store) PutSettings(st model.Settings) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if st.MixedPort <= 0 || st.MixedPort > 65535 {
		return errors.New("некорректный mixed port")
	}
	if st.Mode == "" {
		st.Mode = model.ModeRule
	}
	s.data.Settings = st
	return s.saveLocked()
}

func (s *Store) AddSubscription(sub model.Subscription) (model.Subscription, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sub.ID == "" {
		sub.ID = newID()
	}
	if sub.Name == "" {
		sub.Name = "Подписка"
	}
	s.data.Subscriptions = append(s.data.Subscriptions, sub)
	if err := s.saveLocked(); err != nil {
		return model.Subscription{}, err
	}
	return sub, nil
}

func (s *Store) UpdateSubscription(id string, mut func(*model.Subscription)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.data.Subscriptions {
		if s.data.Subscriptions[i].ID == id {
			mut(&s.data.Subscriptions[i])
			return s.saveLocked()
		}
	}
	return errors.New("подписка не найдена")
}

func (s *Store) DeleteSubscription(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	subs := s.data.Subscriptions[:0]
	for _, sub := range s.data.Subscriptions {
		if sub.ID != id {
			subs = append(subs, sub)
		}
	}
	s.data.Subscriptions = subs
	nodes := s.data.Nodes[:0]
	for _, n := range s.data.Nodes {
		if n.SubID != id {
			nodes = append(nodes, n)
		}
	}
	s.data.Nodes = nodes
	if s.data.SelectedNodeID != "" {
		found := false
		for _, n := range s.data.Nodes {
			if n.ID == s.data.SelectedNodeID {
				found = true
				break
			}
		}
		if !found {
			s.data.SelectedNodeID = ""
		}
	}
	return s.saveLocked()
}

func (s *Store) ReplaceNodes(subID string, incoming []model.Node) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	latency := map[string]int{}
	disabled := map[string]bool{}
	for _, n := range s.data.Nodes {
		if n.SubID == subID {
			key := n.Protocol + "|" + n.Server + "|" + itoa(n.Port) + "|" + n.UUID + "|" + n.Password
			latency[key] = n.LatencyMS
			disabled[key] = n.Disabled
		}
	}
	kept := s.data.Nodes[:0]
	for _, n := range s.data.Nodes {
		if n.SubID != subID {
			kept = append(kept, n)
		}
	}
	now := model.NowUnix()
	for _, n := range incoming {
		n.SubID = subID
		if n.ID == "" {
			n.ID = newID()
		}
		n.UpdatedAt = now
		key := n.Protocol + "|" + n.Server + "|" + itoa(n.Port) + "|" + n.UUID + "|" + n.Password
		if v, ok := latency[key]; ok {
			n.LatencyMS = v
		}
		if v, ok := disabled[key]; ok {
			n.Disabled = v
		}
		kept = append(kept, n)
	}
	s.data.Nodes = kept
	return s.saveLocked()
}

func (s *Store) AddManualNodes(subID string, incoming []model.Node) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := model.NowUnix()
	for _, n := range incoming {
		n.SubID = subID
		n.ID = newID()
		n.UpdatedAt = now
		s.data.Nodes = append(s.data.Nodes, n)
	}
	return s.saveLocked()
}

func (s *Store) SetLatency(id string, ms int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.data.Nodes {
		if s.data.Nodes[i].ID == id {
			s.data.Nodes[i].LatencyMS = ms
			return s.saveLocked()
		}
	}
	return errors.New("узел не найден")
}

func (s *Store) SetManyLatency(values map[string]int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.data.Nodes {
		if v, ok := values[s.data.Nodes[i].ID]; ok {
			s.data.Nodes[i].LatencyMS = v
		}
	}
	return s.saveLocked()
}

func (s *Store) SelectNode(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id == "" {
		s.data.SelectedNodeID = ""
		return s.saveLocked()
	}
	for _, n := range s.data.Nodes {
		if n.ID == id {
			s.data.SelectedNodeID = id
			return s.saveLocked()
		}
	}
	return errors.New("узел не найден")
}

func (s *Store) SelectedNode() *model.Node {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.data.SelectedNodeID == "" {
		return nil
	}
	for i := range s.data.Nodes {
		if s.data.Nodes[i].ID == s.data.SelectedNodeID {
			cp := s.data.Nodes[i]
			return &cp
		}
	}
	return nil
}

func (s *Store) NodeByID(id string) *model.Node {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for i := range s.data.Nodes {
		if s.data.Nodes[i].ID == id {
			cp := s.data.Nodes[i]
			return &cp
		}
	}
	return nil
}

func (s *Store) SubscriptionByID(id string) *model.Subscription {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for i := range s.data.Subscriptions {
		if s.data.Subscriptions[i].ID == id {
			cp := s.data.Subscriptions[i]
			return &cp
		}
	}
	return nil
}

func (s *Store) Nodes() []model.Node {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]model.Node, len(s.data.Nodes))
	copy(out, s.data.Nodes)
	return out
}

func (s *Store) saveLocked() error {
	tmp := s.path + ".tmp"
	raw, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func cloneState(in model.State) model.State {
	out := in
	out.Subscriptions = append([]model.Subscription{}, in.Subscriptions...)
	out.Nodes = append([]model.Node{}, in.Nodes...)
	return out
}

func newID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return hex.EncodeToString([]byte("fallback"))
	}
	return hex.EncodeToString(b[:])
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [16]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
