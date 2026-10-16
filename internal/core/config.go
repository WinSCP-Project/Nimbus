package core

import (
	"encoding/json"
	"fmt"
	"strings"

	"nimbus/internal/model"
)

type BoxConfig map[string]any

func Generate(node model.Node, st model.Settings) (BoxConfig, error) {
	if node.Server == "" || node.Port <= 0 {
		return nil, fmt.Errorf("узел без адреса")
	}
	proxy, err := outbound(node, st)
	if err != nil {
		return nil, err
	}
	proxy["tag"] = "proxy"

	listen := st.EffectiveListenAddr()
	inbounds := []any{
		map[string]any{
			"type":         "mixed",
			"tag":          "mixed-in",
			"listen":       listen,
			"listen_port":  st.MixedPort,
			"sniff":        true,
			"sniff_override_destination": true,
		},
	}
	if st.TUN {
		inbounds = append(inbounds, map[string]any{
			"type":                  "tun",
			"tag":                   "tun-in",
			"interface_name":        "nimbus",
			"address":               []string{"172.19.0.1/30"},
			"mtu":                   9000,
			"auto_route":            true,
			"strict_route":          true,
			"stack":                 first(st.TUNStack, "mixed"),
			"sniff":                 true,
			"sniff_override_destination": true,
		})
	}

	final := "proxy"
	switch st.Mode {
	case model.ModeDirect:
		final = "direct"
	case model.ModeGlobal:
		final = "proxy"
	default:
		final = "proxy"
	}

	dnsServers := []any{
		map[string]any{"tag": "remote", "address": first(st.RemoteDNS, "tls://8.8.8.8"), "detour": "proxy"},
		map[string]any{"tag": "local", "address": first(st.DirectDNS, "local"), "detour": "direct"},
	}

	routeRules := []any{
		map[string]any{"protocol": "dns", "outbound": "direct"},
		map[string]any{"ip_is_private": true, "outbound": "direct"},
	}
	if st.Mode == model.ModeRule {
		routeRules = append(routeRules,
			map[string]any{"domain_suffix": []string{"cn", "qq.com", "weixin.qq.com"}, "outbound": "direct"},
		)
	}
	if st.Mode == model.ModeDirect {
		final = "direct"
	}

	cfg := BoxConfig{
		"log": map[string]any{
			"level":     first(st.LogLevel, "info"),
			"timestamp": true,
		},
		"dns": map[string]any{
			"servers": dnsServers,
			"strategy": "prefer_ipv4",
			"final":    "remote",
		},
		"inbounds": inbounds,
		"outbounds": []any{
			proxy,
			map[string]any{"type": "direct", "tag": "direct"},
			map[string]any{"type": "block", "tag": "block"},
		},
		"route": map[string]any{
			"rules":                 routeRules,
			"final":                 final,
			"auto_detect_interface": true,
		},
		"experimental": map[string]any{
			"clash_api": map[string]any{
				"external_controller": fmt.Sprintf("%s:%d", listen, st.ClashAPIPort),
				"secret":              "",
			},
			"cache_file": map[string]any{
				"enabled": true,
				"path":    "cache.db",
			},
		},
	}
	return cfg, nil
}

func outbound(n model.Node, st model.Settings) (map[string]any, error) {
	base := map[string]any{
		"server":      n.Server,
		"server_port": n.Port,
	}
	switch n.Protocol {
	case model.ProtocolVLESS:
		base["type"] = "vless"
		base["uuid"] = n.UUID
		if n.Flow != "" {
			base["flow"] = n.Flow
		}
		base["packet_encoding"] = first(n.PacketEncoding, "xudp")
		applyTLS(base, n, st)
		applyTransport(base, n)
	case model.ProtocolVMess:
		base["type"] = "vmess"
		base["uuid"] = n.UUID
		base["security"] = first(n.Method, "auto")
		if n.AlterID > 0 {
			base["alter_id"] = n.AlterID
		}
		applyTLS(base, n, st)
		applyTransport(base, n)
	case model.ProtocolTrojan:
		base["type"] = "trojan"
		base["password"] = n.Password
		applyTLS(base, n, st)
		applyTransport(base, n)
	case model.ProtocolShadowsocks:
		base["type"] = "shadowsocks"
		base["method"] = n.Method
		base["password"] = n.Password
		if n.Plugin != "" {
			base["plugin"] = n.Plugin
			if n.PluginOpts != "" {
				base["plugin_opts"] = n.PluginOpts
			}
		}
	case model.ProtocolHysteria2:
		base["type"] = "hysteria2"
		base["password"] = n.Password
		if n.Obfs != "" {
			base["obfs"] = map[string]any{"type": n.Obfs, "password": n.ObfsPassword}
		}
		if n.UpMbps > 0 {
			base["up_mbps"] = n.UpMbps
		}
		if n.DownMbps > 0 {
			base["down_mbps"] = n.DownMbps
		}
		applyTLS(base, n, st)
	case model.ProtocolHysteria:
		base["type"] = "hysteria"
		if n.Password != "" {
			base["auth_str"] = n.Password
		}
		if n.UpMbps > 0 {
			base["up_mbps"] = n.UpMbps
		}
		if n.DownMbps > 0 {
			base["down_mbps"] = n.DownMbps
		}
		applyTLS(base, n, st)
	case model.ProtocolTUIC:
		base["type"] = "tuic"
		base["uuid"] = n.UUID
		base["password"] = n.Password
		base["congestion_control"] = first(n.Congestion, "bbr")
		if n.UDPRelayMode != "" {
			base["udp_relay_mode"] = n.UDPRelayMode
		}
		base["zero_rtt_handshake"] = n.ReduceRTT
		applyTLS(base, n, st)
	case model.ProtocolSocks:
		base["type"] = "socks"
		if n.UUID != "" {
			base["username"] = n.UUID
			base["password"] = n.Password
		}
	case model.ProtocolHTTP:
		base["type"] = "http"
		if n.UUID != "" {
			base["username"] = n.UUID
			base["password"] = n.Password
		}
		if n.Security == "tls" {
			applyTLS(base, n, st)
		}
	case model.ProtocolWireGuard:
		base["type"] = "wireguard"
		base["private_key"] = n.PrivateKey
		base["peer_public_key"] = n.PeerPublicKey
		if n.PreSharedKey != "" {
			base["pre_shared_key"] = n.PreSharedKey
		}
		if n.LocalAddress != "" {
			base["local_address"] = strings.Split(n.LocalAddress, ",")
		}
		if n.MTU > 0 {
			base["mtu"] = n.MTU
		}
	case model.ProtocolAnyTLS:
		base["type"] = "anytls"
		base["password"] = n.Password
		applyTLS(base, n, st)
	case model.ProtocolSSH:
		base["type"] = "ssh"
		base["user"] = first(n.UUID, "root")
		if n.Password != "" {
			base["password"] = n.Password
		}
		if n.PrivateKey != "" {
			base["private_key"] = n.PrivateKey
		}
	default:
		return nil, fmt.Errorf("протокол %s не поддерживается", n.Protocol)
	}
	if st.Mux && (n.Protocol == model.ProtocolVLESS || n.Protocol == model.ProtocolVMess || n.Protocol == model.ProtocolTrojan) {
		if n.Flow == "" {
			base["multiplex"] = map[string]any{"enabled": true, "protocol": "h2mux", "max_streams": 8}
		}
	}
	return base, nil
}

func applyTLS(base map[string]any, n model.Node, st model.Settings) {
	sec := strings.ToLower(n.Security)
	need := sec == "tls" || sec == "reality" || n.Protocol == model.ProtocolHysteria2 || n.Protocol == model.ProtocolHysteria || n.Protocol == model.ProtocolTUIC || n.Protocol == model.ProtocolAnyTLS || n.Protocol == model.ProtocolTrojan
	if n.Protocol == model.ProtocolVLESS || n.Protocol == model.ProtocolVMess {
		need = sec == "tls" || sec == "reality" || n.SNI != "" || n.PublicKey != ""
	}
	if !need && n.PublicKey == "" {
		return
	}
	tls := map[string]any{
		"enabled":     true,
		"insecure":    n.Insecure || st.AllowInsecure,
		"server_name": first(n.SNI, n.Host, n.Server),
	}
	if n.ALPN != "" {
		tls["alpn"] = splitCSV(n.ALPN)
	}
	fp := first(n.Fingerprint, "chrome")
	tls["utls"] = map[string]any{"enabled": true, "fingerprint": fp}
	if sec == "reality" || n.PublicKey != "" {
		tls["reality"] = map[string]any{
			"enabled":    true,
			"public_key": n.PublicKey,
			"short_id":   n.ShortID,
		}
		if n.SpiderX != "" {
			if r, ok := tls["reality"].(map[string]any); ok {
				_ = r
			}
		}
	}
	base["tls"] = tls
}

func applyTransport(base map[string]any, n model.Node) {
	netw := strings.ToLower(n.Network)
	if netw == "" || netw == "tcp" {
		if n.HeaderType != "" && n.HeaderType != "none" {
			base["transport"] = map[string]any{
				"type": "http",
				"host": nonEmpty(n.Host),
				"path": first(n.Path, "/"),
			}
		}
		return
	}
	tr := map[string]any{"type": netw}
	switch netw {
	case "ws", "websocket":
		tr["type"] = "ws"
		tr["path"] = first(n.Path, "/")
		if n.Host != "" {
			tr["headers"] = map[string]any{"Host": n.Host}
		}
	case "grpc":
		tr["type"] = "grpc"
		tr["service_name"] = first(n.ServiceName, n.Path, "TunService")
	case "httpupgrade":
		tr["type"] = "httpupgrade"
		tr["path"] = first(n.Path, "/")
		if n.Host != "" {
			tr["host"] = n.Host
		}
	case "h2", "http":
		tr["type"] = "http"
		tr["path"] = first(n.Path, "/")
		if n.Host != "" {
			tr["host"] = splitCSV(n.Host)
		}
	case "quic":
		tr["type"] = "quic"
	default:
		return
	}
	base["transport"] = tr
}

func Marshal(cfg BoxConfig) ([]byte, error) {
	return json.MarshalIndent(cfg, "", "  ")
}

func first(v ...string) string {
	for _, s := range v {
		if strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func nonEmpty(s string) []string {
	if s == "" {
		return nil
	}
	return []string{s}
}
