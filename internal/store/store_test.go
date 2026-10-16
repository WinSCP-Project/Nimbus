package store

import (
	"os"
	"path/filepath"
	"testing"

	"nimbus/internal/model"
)

func TestSnapshotEmptySlices(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	st := s.Snapshot()
	if st.Subscriptions == nil || st.Nodes == nil {
		t.Fatalf("nil slices: subs=%v nodes=%v", st.Subscriptions, st.Nodes)
	}
}

func TestOpenReplaceSelect(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	sub, err := s.AddSubscription(model.Subscription{Name: "test", URL: "https://example.com/sub"})
	if err != nil {
		t.Fatal(err)
	}
	nodes := []model.Node{
		{Name: "a", Protocol: model.ProtocolVLESS, Server: "a.example.com", Port: 443, UUID: "u1"},
		{Name: "b", Protocol: model.ProtocolTrojan, Server: "b.example.com", Port: 443, Password: "p"},
	}
	if err := s.ReplaceNodes(sub.ID, nodes); err != nil {
		t.Fatal(err)
	}
	got := s.Nodes()
	if len(got) != 2 {
		t.Fatalf("len %d", len(got))
	}
	if err := s.SelectNode(got[1].ID); err != nil {
		t.Fatal(err)
	}
	sel := s.SelectedNode()
	if sel == nil || sel.Name != "b" {
		t.Fatalf("%v", sel)
	}
	if err := s.SetLatency(got[0].ID, 42); err != nil {
		t.Fatal(err)
	}
	if s.NodeByID(got[0].ID).LatencyMS != 42 {
		t.Fatal("latency")
	}
	s2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(s2.Nodes()) != 2 {
		t.Fatal("persist")
	}
	if _, err := os.Stat(filepath.Join(dir, "state.json")); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteSubscription(sub.ID); err != nil {
		t.Fatal(err)
	}
	if len(s.Nodes()) != 0 {
		t.Fatal("nodes leftover")
	}
}

func TestReplaceKeepsLatency(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sub, _ := s.AddSubscription(model.Subscription{Name: "x"})
	_ = s.ReplaceNodes(sub.ID, []model.Node{{
		Name: "n", Protocol: model.ProtocolVLESS, Server: "h", Port: 1, UUID: "id",
	}})
	id := s.Nodes()[0].ID
	_ = s.SetLatency(id, 77)
	_ = s.ReplaceNodes(sub.ID, []model.Node{{
		Name: "n2", Protocol: model.ProtocolVLESS, Server: "h", Port: 1, UUID: "id",
	}})
	if s.Nodes()[0].LatencyMS != 77 {
		t.Fatalf("wanted 77 got %d", s.Nodes()[0].LatencyMS)
	}
}
