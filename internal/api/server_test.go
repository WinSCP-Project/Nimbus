package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"nimbus/internal/app"
	"nimbus/internal/core"
	"nimbus/internal/store"
)

func TestStateAndImport(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "data"))
	if err != nil {
		t.Fatal(err)
	}
	eng := core.New(dir)
	s := &Server{App: app.New(st, eng)}
	h := s.Handler()

	req := httptest.NewRequest(http.MethodGet, "/api/state", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("state %d %s", rec.Code, rec.Body.String())
	}

	body := `{"name":"manual","url":""}`
	req = httptest.NewRequest(http.MethodPost, "/api/subscriptions", bytes.NewBufferString(body))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("add sub %d %s", rec.Code, rec.Body.String())
	}
	var sub struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &sub); err != nil {
		t.Fatal(err)
	}

	imp := `{"sub_id":"` + sub.ID + `","text":"vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls&type=tcp#api-node"}`
	req = httptest.NewRequest(http.MethodPost, "/api/import", bytes.NewBufferString(imp))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("import %d %s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/api/state", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var snap map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &snap); err != nil {
		t.Fatal(err)
	}
	nodes := snap["nodes"].([]any)
	if len(nodes) != 1 {
		t.Fatalf("nodes %v", snap["nodes"])
	}
}

func TestSettingsRoundTrip(t *testing.T) {
	st, _ := store.Open(t.TempDir())
	s := &Server{App: app.New(st, core.New(t.TempDir()))}
	h := s.Handler()
	payload := `{"listen":"127.0.0.1:8787","mixed_port":18080,"clash_api_port":19090,"mode":"global","tun":false,"tun_stack":"mixed","remote_dns":"tls://1.1.1.1","direct_dns":"local","log_level":"warn","auto_update_h":3,"user_agent":"Nimbus-Test","test_url":"https://www.gstatic.com/generate_204","ping_timeout_ms":1500}`
	req := httptest.NewRequest(http.MethodPut, "/api/settings", bytes.NewBufferString(payload))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	if st.Settings().MixedPort != 18080 || st.Settings().Mode != "global" {
		t.Fatalf("%+v", st.Settings())
	}
}
