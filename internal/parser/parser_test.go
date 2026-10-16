package parser

import (
	"encoding/base64"
	"strings"
	"testing"

	"nimbus/internal/model"
)

func TestParseVLESSReality(t *testing.T) {
	line := "vless://11111111-1111-1111-1111-111111111111@example.com:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.apple.com&fp=chrome&pbk=PUBLICKEYEXAMPLE&sid=ab12cd&type=tcp#NL-Reality"
	n, err := ParseShare(line)
	if err != nil {
		t.Fatal(err)
	}
	if n.Protocol != model.ProtocolVLESS {
		t.Fatalf("protocol %s", n.Protocol)
	}
	if n.UUID != "11111111-1111-1111-1111-111111111111" {
		t.Fatalf("uuid %s", n.UUID)
	}
	if n.Server != "example.com" || n.Port != 443 {
		t.Fatalf("endpoint %s:%d", n.Server, n.Port)
	}
	if n.Security != "reality" || n.PublicKey != "PUBLICKEYEXAMPLE" || n.ShortID != "ab12cd" {
		t.Fatalf("reality %+v", n)
	}
	if n.Flow != "xtls-rprx-vision" {
		t.Fatalf("flow %s", n.Flow)
	}
	if n.Name != "NL-Reality" {
		t.Fatalf("name %s", n.Name)
	}
}

func TestParseVMess(t *testing.T) {
	jsonBody := `{"v":"2","ps":"DE-VMess","add":"10.1.2.3","port":"443","id":"22222222-2222-2222-2222-222222222222","aid":"0","scy":"auto","net":"ws","type":"none","host":"cdn.example.com","path":"/ws","tls":"tls","sni":"cdn.example.com","fp":"chrome"}`
	line := "vmess://" + base64.StdEncoding.EncodeToString([]byte(jsonBody))
	n, err := ParseShare(line)
	if err != nil {
		t.Fatal(err)
	}
	if n.Protocol != model.ProtocolVMess || n.Server != "10.1.2.3" || n.Port != 443 {
		t.Fatalf("%+v", n)
	}
	if n.Network != "ws" || n.Path != "/ws" || n.Security != "tls" {
		t.Fatalf("transport %+v", n)
	}
	if n.Name != "DE-VMess" {
		t.Fatalf("name %s", n.Name)
	}
}

func TestParseTrojanWS(t *testing.T) {
	line := "trojan://password123@node.example.com:443?security=tls&sni=node.example.com&type=ws&path=%2Fws&host=node.example.com#Trojan-WS"
	n, err := ParseShare(line)
	if err != nil {
		t.Fatal(err)
	}
	if n.Protocol != model.ProtocolTrojan || n.Password != "password123" {
		t.Fatalf("%+v", n)
	}
	if n.Network != "ws" || n.Path != "/ws" {
		t.Fatalf("ws %+v", n)
	}
}

func TestParseShadowsocksSIP002(t *testing.T) {
	user := base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:secret-pass"))
	line := "ss://" + user + "@ss.example.com:8388#SS-Node"
	n, err := ParseShare(line)
	if err != nil {
		t.Fatal(err)
	}
	if n.Method != "aes-256-gcm" || n.Password != "secret-pass" {
		t.Fatalf("%+v", n)
	}
	if n.Server != "ss.example.com" || n.Port != 8388 {
		t.Fatalf("endpoint %+v", n)
	}
}

func TestParseShadowsocksLegacy(t *testing.T) {
	payload := base64.StdEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:hello@legacy.example.com:443"))
	n, err := ParseShare("ss://" + payload + "#Legacy")
	if err != nil {
		t.Fatal(err)
	}
	if n.Method != "chacha20-ietf-poly1305" || n.Password != "hello" || n.Server != "legacy.example.com" {
		t.Fatalf("%+v", n)
	}
}

func TestParseHysteria2AndTUIC(t *testing.T) {
	hy := "hysteria2://secret@hy2.example.com:443?sni=hy2.example.com&insecure=1#HY2"
	n, err := ParseShare(hy)
	if err != nil {
		t.Fatal(err)
	}
	if n.Protocol != model.ProtocolHysteria2 || !n.Insecure || n.Password != "secret" {
		t.Fatalf("%+v", n)
	}
	tu := "tuic://33333333-3333-3333-3333-333333333333:pw@tuic.example.com:8443?sni=tuic.example.com&congestion_control=bbr#TUIC"
	n2, err := ParseShare(tu)
	if err != nil {
		t.Fatal(err)
	}
	if n2.Protocol != model.ProtocolTUIC || n2.Password != "pw" || n2.Congestion != "bbr" {
		t.Fatalf("%+v", n2)
	}
}

func TestDecodeURIListAndBase64(t *testing.T) {
	body := "vless://11111111-1111-1111-1111-111111111111@a.example.com:443?security=tls&type=tcp#A\n" +
		"trojan://pw@b.example.com:443?security=tls#B\n"
	r, err := DecodeSubscription([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if r.Kind != "uri" || len(r.Nodes) != 2 {
		t.Fatalf("%s %d", r.Kind, len(r.Nodes))
	}
	wrapped := base64.StdEncoding.EncodeToString([]byte(body))
	r2, err := DecodeSubscription([]byte(wrapped))
	if err != nil {
		t.Fatal(err)
	}
	if len(r2.Nodes) != 2 {
		t.Fatalf("b64 nodes %d kind %s", len(r2.Nodes), r2.Kind)
	}
}

func TestDecodeClash(t *testing.T) {
	yml := `
proxies:
  - name: clash-ss
    type: ss
    server: clash.example.com
    port: 8388
    cipher: aes-256-gcm
    password: hunter2
  - name: clash-vless
    type: vless
    server: vless.example.com
    port: 443
    uuid: 11111111-1111-1111-1111-111111111111
    tls: true
    network: tcp
    flow: xtls-rprx-vision
    servername: www.apple.com
    reality-opts:
      public-key: KEY
      short-id: abcd
`
	r, err := DecodeSubscription([]byte(yml))
	if err != nil {
		t.Fatal(err)
	}
	if r.Kind != "clash" || len(r.Nodes) != 2 {
		t.Fatalf("%s %d", r.Kind, len(r.Nodes))
	}
	var found bool
	for _, n := range r.Nodes {
		if n.Protocol == model.ProtocolVLESS && n.Security == "reality" && n.PublicKey == "KEY" {
			found = true
		}
	}
	if !found {
		t.Fatalf("reality not parsed: %+v", r.Nodes)
	}
}

func TestDecodeSingBox(t *testing.T) {
	raw := `{
  "outbounds": [
    {"type":"vless","tag":"sb-vless","server":"sb.example.com","server_port":443,"uuid":"11111111-1111-1111-1111-111111111111","tls":{"enabled":true,"server_name":"sb.example.com"}},
    {"type":"direct","tag":"direct"}
  ]
}`
	r, err := DecodeSubscription([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if r.Kind != "sing-box" || len(r.Nodes) != 1 {
		t.Fatalf("%s %d", r.Kind, len(r.Nodes))
	}
	if r.Nodes[0].Name != "sb-vless" || r.Nodes[0].Port != 443 {
		t.Fatalf("%+v", r.Nodes[0])
	}
}

func TestSkipGarbage(t *testing.T) {
	nodes := ParseShareList("# comment\nnot-a-link\n\nhttp://example.com/page\n")
	if len(nodes) != 0 {
		t.Fatalf("expected empty, got %#v", nodes)
	}
}

func TestIPv6Host(t *testing.T) {
	line := "vless://11111111-1111-1111-1111-111111111111@[2001:db8::1]:443?security=tls&type=tcp#v6"
	n, err := ParseShare(line)
	if err != nil {
		t.Fatal(err)
	}
	if n.Server != "2001:db8::1" || n.Port != 443 {
		t.Fatalf("%+v", n)
	}
}

func TestShareListKeepsOrder(t *testing.T) {
	text := strings.Join([]string{
		"ss://YWVzLTI1Ni1nY206cGFzcw@one.example.com:1#one",
		"ss://YWVzLTI1Ni1nY206cGFzcw@two.example.com:2#two",
	}, "\n")
	nodes := ParseShareList(text)
	if len(nodes) != 2 || nodes[0].Name != "one" || nodes[1].Name != "two" {
		t.Fatalf("%+v", nodes)
	}
}
