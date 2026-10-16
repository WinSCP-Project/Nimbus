package api

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"nimbus/internal/app"
	"nimbus/internal/model"
)

type Server struct {
	App *app.App
	FS  http.Handler
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/state", s.wrap(s.state))
	mux.HandleFunc("/api/settings", s.wrap(s.settings))
	mux.HandleFunc("/api/subscriptions", s.wrap(s.subscriptions))
	mux.HandleFunc("/api/subscriptions/", s.wrap(s.subscriptionItem))
	mux.HandleFunc("/api/import", s.wrap(s.importShare))
	mux.HandleFunc("/api/nodes/select", s.wrap(s.selectNode))
	mux.HandleFunc("/api/connect", s.wrap(s.connect))
	mux.HandleFunc("/api/disconnect", s.wrap(s.disconnect))
	mux.HandleFunc("/api/ping", s.wrap(s.pingOne))
	mux.HandleFunc("/api/ping-all", s.wrap(s.pingAll))
	mux.HandleFunc("/api/logs", s.wrap(s.logs))
	mux.HandleFunc("/api/events", s.events)
	if s.FS != nil {
		mux.Handle("/", s.FS)
	} else {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			http.NotFound(w, r)
		})
	}
	return withCORS(mux)
}

func (s *Server) wrap(h func(http.ResponseWriter, *http.Request) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := h(w, r); err != nil {
			writeErr(w, 400, err.Error())
		}
	}
}

func (s *Server) state(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodGet {
		return errMethod
	}
	return writeJSON(w, 200, s.App.Snapshot())
}

func (s *Server) settings(w http.ResponseWriter, r *http.Request) error {
	switch r.Method {
	case http.MethodGet:
		return writeJSON(w, 200, s.App.Store.Settings())
	case http.MethodPut, http.MethodPost:
		var st model.Settings
		if err := readJSON(r, &st); err != nil {
			return err
		}
		if err := s.App.Store.PutSettings(st); err != nil {
			return err
		}
		return writeJSON(w, 200, s.App.Store.Settings())
	default:
		return errMethod
	}
}

func (s *Server) subscriptions(w http.ResponseWriter, r *http.Request) error {
	switch r.Method {
	case http.MethodGet:
		return writeJSON(w, 200, s.App.Snapshot().Subscriptions)
	case http.MethodPost:
		var req struct {
			Name      string `json:"name"`
			URL       string `json:"url"`
			UserAgent string `json:"user_agent"`
		}
		if err := readJSON(r, &req); err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(r.Context(), 50*time.Second)
		defer cancel()
		sub, err := s.App.AddSubscription(ctx, req.Name, req.URL, req.UserAgent)
		if err != nil {
			return err
		}
		return writeJSON(w, 200, sub)
	default:
		return errMethod
	}
}

func (s *Server) subscriptionItem(w http.ResponseWriter, r *http.Request) error {
	path := strings.TrimPrefix(r.URL.Path, "/api/subscriptions/")
	path = strings.Trim(path, "/")
	parts := strings.Split(path, "/")
	if len(parts) == 0 || parts[0] == "" {
		return errNotFound
	}
	id := parts[0]
	action := ""
	if len(parts) > 1 {
		action = parts[1]
	}
	switch {
	case action == "update" && r.Method == http.MethodPost:
		ctx, cancel := context.WithTimeout(r.Context(), 50*time.Second)
		defer cancel()
		if err := s.App.UpdateSubscription(ctx, id); err != nil {
			return err
		}
		return writeJSON(w, 200, s.App.Store.SubscriptionByID(id))
	case action == "" && r.Method == http.MethodDelete:
		connected, _, _, _, _, _, _ := s.App.Engine.Status()
		sel := s.App.Store.SelectedNode()
		if connected && sel != nil && sel.SubID == id {
			_ = s.App.Disconnect()
		}
		return s.App.Store.DeleteSubscription(id)
	case action == "" && (r.Method == http.MethodPut || r.Method == http.MethodPost):
		var req struct {
			Name      string `json:"name"`
			URL       string `json:"url"`
			UserAgent string `json:"user_agent"`
		}
		if err := readJSON(r, &req); err != nil {
			return err
		}
		return s.App.Store.UpdateSubscription(id, func(x *model.Subscription) {
			if req.Name != "" {
				x.Name = req.Name
			}
			if req.URL != "" {
				x.URL = req.URL
				x.Manual = false
			}
			if req.UserAgent != "" {
				x.UserAgent = req.UserAgent
			}
		})
	default:
		return errNotFound
	}
}

func (s *Server) importShare(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodPost {
		return errMethod
	}
	var req struct {
		SubID string `json:"sub_id"`
		Text  string `json:"text"`
	}
	if err := readJSON(r, &req); err != nil {
		return err
	}
	n, err := s.App.ImportShare(r.Context(), req.SubID, req.Text)
	if err != nil {
		return err
	}
	return writeJSON(w, 200, map[string]any{"imported": n})
}

func (s *Server) selectNode(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodPost {
		return errMethod
	}
	var req struct {
		ID string `json:"id"`
	}
	if err := readJSON(r, &req); err != nil {
		return err
	}
	if err := s.App.Store.SelectNode(req.ID); err != nil {
		return err
	}
	return writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) connect(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodPost {
		return errMethod
	}
	var req struct {
		ID string `json:"id"`
	}
	_ = readJSON(r, &req)
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	if err := s.App.Connect(ctx, req.ID); err != nil {
		return err
	}
	return writeJSON(w, 200, s.App.Snapshot())
}

func (s *Server) disconnect(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodPost {
		return errMethod
	}
	if err := s.App.Disconnect(); err != nil {
		return err
	}
	return writeJSON(w, 200, s.App.Snapshot())
}

func (s *Server) pingOne(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodPost {
		return errMethod
	}
	var req struct {
		ID string `json:"id"`
	}
	if err := readJSON(r, &req); err != nil {
		return err
	}
	ms, err := s.App.PingOne(r.Context(), req.ID)
	if err != nil {
		return err
	}
	return writeJSON(w, 200, map[string]any{"id": req.ID, "latency_ms": ms})
}

func (s *Server) pingAll(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodPost {
		return errMethod
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	values, err := s.App.PingAll(ctx)
	if err != nil {
		return err
	}
	return writeJSON(w, 200, values)
}

func (s *Server) logs(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodGet {
		return errMethod
	}
	return writeJSON(w, 200, map[string]any{"lines": s.App.Engine.Logs()})
}

func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "no flush", 500)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	tick := time.NewTicker(1 * time.Second)
	defer tick.Stop()
	send := func() {
		raw, _ := json.Marshal(s.App.Snapshot())
		_, _ = w.Write([]byte("data: "))
		_, _ = w.Write(raw)
		_, _ = w.Write([]byte("\n\n"))
		flusher.Flush()
	}
	send()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-tick.C:
			send()
		}
	}
}

func (s *Server) Listen(addr string) (net.Listener, error) {
	return net.Listen("tcp", addr)
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(204)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) error {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	return json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	_ = writeJSON(w, code, map[string]string{"error": msg})
}

func readJSON(r *http.Request, v any) error {
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	if err != nil {
		return err
	}
	if len(body) == 0 {
		return nil
	}
	return json.Unmarshal(body, v)
}

type apiErr string

func (e apiErr) Error() string { return string(e) }

const (
	errMethod  apiErr = "метод не поддерживается"
	errNotFound apiErr = "не найдено"
)
