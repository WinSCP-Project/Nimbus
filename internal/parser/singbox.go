package parser

import (
	"strings"

	"nimbus/internal/model"
)

func parseSingBoxOutbounds(arr []any) []model.Node {
	var nodes []model.Node
	for _, item := range arr {
		m := asMap(item)
		if m == nil {
			continue
		}
		n, err := singBoxOutbound(m)
		if err != nil || n == nil {
			continue
		}
		nodes = append(nodes, *n)
	}
	return nodes
}

func singBoxOutbound(m map[string]any) (*model.Node, error) {
	typ := strings.ToLower(toString(m["type"]))
	switch typ {
	case "direct", "block", "dns", "selector", "urltest", "tor":
		return nil, errSkip
	}
	n := &model.Node{
		Name:     firstNonEmpty(toString(m["tag"]), toString(m["server"])),
		Server:   toString(m["server"]),
		Port:     toInt(m["server_port"]),
		UUID:     toString(m["uuid"]),
		Password: toString(m["password"]),
		Method:   toString(m["method"]),
		Flow:     toString(m["flow"]),
	}
	if tls := asMap(m["tls"]); tls != nil {
		if toBool(tls["enabled"]) {
			n.Security = "tls"
		}
		n.SNI = toString(tls["server_name"])
		n.Insecure = toBool(tls["insecure"])
		n.ALPN = joinAny(tls["alpn"])
		if utls := asMap(tls["utls"]); utls != nil {
			n.Fingerprint = toString(utls["fingerprint"])
		}
		if reality := asMap(tls["reality"]); reality != nil && toBool(reality["enabled"]) {
			n.Security = "reality"
			n.PublicKey = toString(reality["public_key"])
			n.ShortID = toString(reality["short_id"])
		}
	}
	if tr := asMap(m["transport"]); tr != nil {
		n.Network = toString(tr["type"])
		n.Path = toString(tr["path"])
		n.ServiceName = toString(tr["service_name"])
		if hdr := asMap(tr["headers"]); hdr != nil {
			n.Host = firstNonEmpty(toString(hdr["Host"]), toString(hdr["host"]))
		}
		n.Host = firstNonEmpty(n.Host, joinAny(tr["host"]), toString(tr["host"]))
	}
	switch typ {
	case "vless":
		n.Protocol = model.ProtocolVLESS
		n.PacketEncoding = toString(m["packet_encoding"])
		n.Encryption = toString(m["encryption"])
	case "vmess":
		n.Protocol = model.ProtocolVMess
		n.AlterID = toInt(m["alter_id"])
		if n.Method == "" {
			n.Method = firstNonEmpty(toString(m["security"]), "auto")
		}
	case "trojan":
		n.Protocol = model.ProtocolTrojan
	case "shadowsocks":
		n.Protocol = model.ProtocolShadowsocks
		n.Plugin = toString(m["plugin"])
		n.PluginOpts = toString(m["plugin_opts"])
	case "hysteria2":
		n.Protocol = model.ProtocolHysteria2
		if obfs := asMap(m["obfs"]); obfs != nil {
			n.Obfs = toString(obfs["type"])
			n.ObfsPassword = toString(obfs["password"])
		}
		n.UpMbps = toInt(m["up_mbps"])
		n.DownMbps = toInt(m["down_mbps"])
	case "hysteria":
		n.Protocol = model.ProtocolHysteria
		n.UpMbps = toInt(m["up_mbps"])
		n.DownMbps = toInt(m["down_mbps"])
		n.Obfs = toString(m["obfs"])
		n.Password = firstNonEmpty(n.Password, toString(m["auth_str"]))
	case "tuic":
		n.Protocol = model.ProtocolTUIC
		n.Congestion = toString(m["congestion_control"])
		n.UDPRelayMode = toString(m["udp_relay_mode"])
	case "socks":
		n.Protocol = model.ProtocolSocks
		n.UUID = toString(m["username"])
	case "http":
		n.Protocol = model.ProtocolHTTP
		n.UUID = toString(m["username"])
	case "wireguard":
		n.Protocol = model.ProtocolWireGuard
		n.PrivateKey = toString(m["private_key"])
		n.PeerPublicKey = toString(m["peer_public_key"])
		n.PreSharedKey = toString(m["pre_shared_key"])
		n.LocalAddress = joinAny(m["local_address"])
		n.MTU = toInt(m["mtu"])
	case "anytls":
		n.Protocol = model.ProtocolAnyTLS
	case "ssh":
		n.Protocol = model.ProtocolSSH
		n.UUID = toString(m["user"])
		n.PrivateKey = toString(m["private_key"])
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
