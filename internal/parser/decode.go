package parser

import (
	"bytes"
	"encoding/json"
	"strings"
	"unicode/utf8"

	"nimbus/internal/model"

	"gopkg.in/yaml.v3"
)

type DecodeResult struct {
	Kind  string
	Nodes []model.Node
}

func DecodeSubscription(body []byte) (DecodeResult, error) {
	raw := bytes.TrimSpace(body)
	if len(raw) == 0 {
		return DecodeResult{Kind: "empty"}, nil
	}

	if nodes, ok := tryClash(raw); ok && len(nodes) > 0 {
		return DecodeResult{Kind: "clash", Nodes: nodes}, nil
	}
	if nodes, ok := trySingBox(raw); ok && len(nodes) > 0 {
		return DecodeResult{Kind: "sing-box", Nodes: nodes}, nil
	}

	text := string(raw)
	if nodes := ParseShareList(text); len(nodes) > 0 {
		return DecodeResult{Kind: "uri", Nodes: nodes}, nil
	}

	decoded, err := b64Decode(stripWhitespace(text))
	if err == nil && len(decoded) > 0 && looksLikeText(decoded) {
		if nodes, ok := tryClash(decoded); ok && len(nodes) > 0 {
			return DecodeResult{Kind: "clash", Nodes: nodes}, nil
		}
		if nodes, ok := trySingBox(decoded); ok && len(nodes) > 0 {
			return DecodeResult{Kind: "sing-box", Nodes: nodes}, nil
		}
		if nodes := ParseShareList(string(decoded)); len(nodes) > 0 {
			return DecodeResult{Kind: "uri", Nodes: nodes}, nil
		}
	}

	return DecodeResult{Kind: "unknown"}, nil
}

func ParseShareList(text string) []model.Node {
	var nodes []model.Node
	for _, line := range strings.Split(normalizeNewlines(text), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		n, err := ParseShare(line)
		if err != nil || n == nil {
			continue
		}
		nodes = append(nodes, *n)
	}
	return nodes
}

func ParseShare(line string) (*model.Node, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil, errSkip
	}
	scheme, rest, ok := strings.Cut(strings.ToLower(line), "://")
	if !ok {
		return nil, errSkip
	}
	_ = rest
	switch scheme {
	case "vmess":
		return parseVMess(line)
	case "vless":
		return parseVLESS(line)
	case "trojan":
		return parseTrojan(line)
	case "ss", "shadowsocks":
		return parseShadowsocks(line)
	case "hysteria2", "hy2":
		return parseHysteria2(line)
	case "hysteria", "hy":
		return parseHysteria(line)
	case "tuic":
		return parseTUIC(line)
	case "socks", "socks5", "socks4":
		return parseSocks(line)
	case "http", "https":
		if strings.Contains(line, "@") {
			return parseHTTPProxy(line)
		}
		return nil, errSkip
	case "wireguard", "wg":
		return parseWireGuard(line)
	case "anytls":
		return parseAnyTLS(line)
	default:
		return nil, errSkip
	}
}

func tryClash(raw []byte) ([]model.Node, bool) {
	trim := bytes.TrimSpace(raw)
	if len(trim) == 0 || trim[0] == '[' || trim[0] == '{' {
		if !bytes.Contains(trim, []byte("proxies:")) && !bytes.Contains(trim, []byte("proxy-groups:")) {
			return nil, false
		}
	}
	lower := strings.ToLower(string(trim[:min(len(trim), 800)]))
	if !strings.Contains(lower, "proxies:") && !strings.Contains(lower, "mixed-port:") && !strings.Contains(lower, "port:") {
		if !bytes.Contains(trim, []byte("\ntype:")) && !bytes.Contains(trim, []byte("type: ss")) {
			return nil, false
		}
	}
	var doc map[string]any
	if err := yaml.Unmarshal(trim, &doc); err != nil {
		return nil, false
	}
	if doc == nil {
		return nil, false
	}
	nodes := parseClashDoc(doc)
	if len(nodes) == 0 {
		return nil, false
	}
	return nodes, true
}

func trySingBox(raw []byte) ([]model.Node, bool) {
	trim := bytes.TrimLeft(raw, " \t\r\n")
	if len(trim) == 0 || (trim[0] != '{' && trim[0] != '[') {
		return nil, false
	}
	var doc map[string]any
	dec := json.NewDecoder(bytes.NewReader(trim))
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil {
		var arr []any
		dec = json.NewDecoder(bytes.NewReader(trim))
		dec.UseNumber()
		if err2 := dec.Decode(&arr); err2 != nil {
			return nil, false
		}
		nodes := parseSingBoxOutbounds(arr)
		if len(nodes) == 0 {
			return nil, false
		}
		return nodes, true
	}
	if obs, ok := doc["outbounds"]; ok {
		nodes := parseSingBoxOutbounds(asSlice(obs))
		if len(nodes) == 0 {
			return nil, false
		}
		return nodes, true
	}
	return nil, false
}

func looksLikeText(b []byte) bool {
	if !utf8.Valid(b) {
		return false
	}
	bin := 0
	for _, c := range b {
		if c == 0 {
			return false
		}
		if c < 9 || (c > 13 && c < 32) {
			bin++
		}
	}
	return bin < len(b)/10
}

func stripWhitespace(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ' ' || c == '\n' || c == '\r' || c == '\t' {
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

func normalizeNewlines(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	return strings.ReplaceAll(s, "\r", "\n")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

type skipError string

func (e skipError) Error() string { return string(e) }

const errSkip skipError = "skip"
