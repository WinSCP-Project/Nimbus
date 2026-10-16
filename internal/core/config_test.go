package core

import (
	"encoding/json"
	"testing"

	"nimbus/internal/model"
)

func TestGenerateVLESSReality(t *testing.T) {
	n := model.Node{
		Name:      "NL",
		Protocol:  model.ProtocolVLESS,
		Server:    "example.com",
		Port:      443,
		UUID:      "11111111-1111-1111-1111-111111111111",
		Flow:      "xtls-rprx-vision",
		Security:  "reality",
		SNI:       "www.apple.com",
		PublicKey: "KEY",
		ShortID:   "ab",
		Network:   "tcp",
		Fingerprint: "chrome",
	}
	st := model.DefaultSettings()
	cfg, err := Generate(n, st)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(cfg)
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	outs := decoded["outbounds"].([]any)
	proxy := outs[0].(map[string]any)
	if proxy["type"] != "vless" || proxy["tag"] != "proxy" {
		t.Fatalf("%v", proxy)
	}
	tls := proxy["tls"].(map[string]any)
	reality := tls["reality"].(map[string]any)
	if reality["public_key"] != "KEY" {
		t.Fatalf("reality %v", reality)
	}
	if decoded["inbounds"] == nil {
		t.Fatal("no inbounds")
	}
}

func TestGenerateShadowsocksAndPorts(t *testing.T) {
	n := model.Node{
		Name:     "ss",
		Protocol: model.ProtocolShadowsocks,
		Server:   "ss.example.com",
		Port:     8388,
		Method:   "aes-256-gcm",
		Password: "x",
	}
	st := model.DefaultSettings()
	st.MixedPort = 12345
	st.BindLAN = true
	cfg, err := Generate(n, st)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := Marshal(cfg)
	var decoded map[string]any
	_ = json.Unmarshal(raw, &decoded)
	in := decoded["inbounds"].([]any)[0].(map[string]any)
	if int(in["listen_port"].(float64)) != 12345 {
		t.Fatalf("port %v", in["listen_port"])
	}
	if in["listen"] != "0.0.0.0" {
		t.Fatalf("listen %v", in["listen"])
	}
}

func TestGenerateRejectsEmpty(t *testing.T) {
	_, err := Generate(model.Node{Protocol: model.ProtocolVLESS}, model.DefaultSettings())
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestHysteria2Outbound(t *testing.T) {
	n := model.Node{
		Protocol:     model.ProtocolHysteria2,
		Server:       "hy.example.com",
		Port:         443,
		Password:     "pw",
		Obfs:         "salamander",
		ObfsPassword: "obf",
		SNI:          "hy.example.com",
	}
	ob, err := outbound(n, model.DefaultSettings())
	if err != nil {
		t.Fatal(err)
	}
	if ob["type"] != "hysteria2" {
		t.Fatalf("%v", ob)
	}
	if ob["tls"] == nil {
		t.Fatal("tls required")
	}
}
