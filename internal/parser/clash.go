package parser

import (
	"strings"

	"nimbus/internal/model"
)

func parseClashDoc(doc map[string]any) []model.Node {
	proxies := asSlice(doc["proxies"])
	if len(proxies) == 0 {
		return nil
	}
	var nodes []model.Node
	for _, item := range proxies {
		m := asMap(item)
		if m == nil {
			continue
		}
		n, err := clashProxy(m)
		if err != nil || n == nil {
			continue
		}
		nodes = append(nodes, *n)
	}
	return nodes
}

func clashProxy(m map[string]any) (*model.Node, error) {
	typ := strings.ToLower(toString(m["type"]))
	n := &model.Node{
		Name:     firstNonEmpty(toString(m["name"]), toString(m["server"])),
		Server:   toString(m["server"]),
		Port:     toInt(m["port"]),
		Network:  firstNonEmpty(toString(m["network"]), toString(m["net"]), "tcp"),
		Insecure: toBool(m["skip-cert-verify"]) || toBool(m["insecure"]),
		SNI: firstNonEmpty(
			toString(m["sni"]),
			toString(m["servername"]),
			toString(m["server-name"]),
		),
		ALPN:        joinAny(m["alpn"]),
		Fingerprint: firstNonEmpty(toString(m["client-fingerprint"]), toString(m["fingerprint"])),
		UUID:        firstNonEmpty(toString(m["uuid"]), toString(m["id"])),
		Password:    firstNonEmpty(toString(m["password"]), toString(m["auth-str"]), toString(m["auth_str"])),
		Method:      firstNonEmpty(toString(m["cipher"]), toString(m["method"])),
		Flow:        toString(m["flow"]),
		AlterID:     toInt(m["alterId"]),
		Path:        toString(m["path"]),
		Host:        toString(m["host"]),
		Plugin:      toString(m["plugin"]),
		PluginOpts:  encodePluginOpts(m["plugin-opts"]),
	}
	if tls := m["tls"]; tls != nil {
		if toBool(tls) {
			n.Security = "tls"
		}
	}
	applyTransport(n, m)
	applyReality(n, m)

	switch typ {
	case "ss", "shadowsocks":
		n.Protocol = model.ProtocolShadowsocks
	case "vmess":
		n.Protocol = model.ProtocolVMess
		if n.Method == "" {
			n.Method = "auto"
		}
	case "vless":
		n.Protocol = model.ProtocolVLESS
		if toString(m["encryption"]) != "" {
			n.Encryption = toString(m["encryption"])
		}
	case "trojan":
		n.Protocol = model.ProtocolTrojan
		if n.Security == "" {
			n.Security = "tls"
		}
	case "hysteria2", "hy2":
		n.Protocol = model.ProtocolHysteria2
		n.Obfs = toString(m["obfs"])
		n.ObfsPassword = firstNonEmpty(toString(m["obfs-password"]), toString(m["obfs_param"]))
		n.Ports = toString(m["ports"])
		n.UpMbps = toInt(m["up"])
		n.DownMbps = toInt(m["down"])
	case "hysteria":
		n.Protocol = model.ProtocolHysteria
		n.Obfs = toString(m["obfs"])
		n.UpMbps = toInt(m["up"])
		n.DownMbps = toInt(m["down"])
	case "tuic":
		n.Protocol = model.ProtocolTUIC
		n.Congestion = firstNonEmpty(toString(m["congestion-controller"]), "bbr")
		n.UDPRelayMode = toString(m["udp-relay-mode"])
		n.ReduceRTT = toBool(m["reduce-rtt"])
	case "socks", "socks5":
		n.Protocol = model.ProtocolSocks
		n.UUID = toString(m["username"])
		n.Password = toString(m["password"])
	case "http":
		n.Protocol = model.ProtocolHTTP
		n.UUID = toString(m["username"])
		n.Password = toString(m["password"])
	case "wireguard":
		n.Protocol = model.ProtocolWireGuard
		n.PrivateKey = toString(m["private-key"])
		n.PeerPublicKey = firstNonEmpty(toString(m["public-key"]), toString(m["peer-public-key"]))
		n.PreSharedKey = toString(m["pre-shared-key"])
		n.LocalAddress = joinAny(m["ip"])
		if n.LocalAddress == "" {
			n.LocalAddress = joinAny(m["ipv6"])
		}
		n.MTU = toInt(m["mtu"])
		n.Reserved = joinAny(m["reserved"])
	case "anytls":
		n.Protocol = model.ProtocolAnyTLS
	case "ssh":
		n.Protocol = model.ProtocolSSH
		n.UUID = firstNonEmpty(toString(m["username"]), "root")
		n.Password = toString(m["password"])
		n.PrivateKey = toString(m["private-key"])
	default:
		return nil, errSkip
	}
	if n.Server == "" || n.Port <= 0 {
		return nil, errSkip
	}
	if n.Name == "" {
		n.Name = n.Server
	}
	return n, nil
}

func applyTransport(n *model.Node, m map[string]any) {
	netw := strings.ToLower(n.Network)
	switch netw {
	case "ws", "websocket":
		n.Network = "ws"
		opts := asMap(m["ws-opts"])
		if opts == nil {
			opts = asMap(m["ws_opts"])
		}
		if opts != nil {
			n.Path = firstNonEmpty(toString(opts["path"]), n.Path)
			if hdr := asMap(opts["headers"]); hdr != nil {
				n.Host = firstNonEmpty(toString(hdr["Host"]), toString(hdr["host"]))
			}
		}
	case "grpc":
		opts := asMap(m["grpc-opts"])
		if opts == nil {
			opts = asMap(m["grpc_opts"])
		}
		if opts != nil {
			n.ServiceName = firstNonEmpty(toString(opts["grpc-service-name"]), toString(opts["serviceName"]))
		}
	case "h2", "http":
		opts := asMap(m["h2-opts"])
		if opts == nil {
			opts = asMap(m["http-opts"])
		}
		if opts != nil {
			n.Path = firstNonEmpty(toString(opts["path"]), n.Path)
			n.Host = firstNonEmpty(joinAny(opts["host"]), n.Host)
		}
	case "httpupgrade":
		opts := asMap(m["http-opts"])
		if opts != nil {
			n.Path = firstNonEmpty(toString(opts["path"]), n.Path)
			n.Host = firstNonEmpty(toString(opts["host"]), n.Host)
		}
	}
	if smux := asMap(m["smux"]); smux != nil {
		n.Multiplex = toBool(smux["enabled"])
	}
}

func applyReality(n *model.Node, m map[string]any) {
	sec := strings.ToLower(toString(m["security"]))
	if sec != "" {
		n.Security = sec
	}
	opts := asMap(m["reality-opts"])
	if opts == nil {
		opts = asMap(m["reality_opts"])
	}
	if opts != nil {
		n.Security = "reality"
		n.PublicKey = firstNonEmpty(toString(opts["public-key"]), toString(opts["public_key"]))
		n.ShortID = toString(opts["short-id"])
	}
	if toString(m["reality"]) == "true" || toBool(m["reality"]) {
		n.Security = "reality"
	}
	if n.PublicKey == "" {
		n.PublicKey = toString(m["public-key"])
	}
	if n.ShortID == "" {
		n.ShortID = toString(m["short-id"])
	}
}

func joinAny(v any) string {
	switch t := v.(type) {
	case []any:
		parts := make([]string, 0, len(t))
		for _, x := range t {
			s := toString(x)
			if s != "" {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, ",")
	default:
		return toString(v)
	}
}

func encodePluginOpts(v any) string {
	m := asMap(v)
	if m == nil {
		return toString(v)
	}
	parts := make([]string, 0, len(m))
	for k, val := range m {
		parts = append(parts, k+"="+toString(val))
	}
	return strings.Join(parts, ";")
}
