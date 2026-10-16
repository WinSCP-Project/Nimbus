package parser

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"nimbus/internal/model"
)

func parseVMess(line string) (*model.Node, error) {
	raw := strings.TrimSpace(strings.TrimPrefix(line, "vmess://"))
	raw = strings.TrimPrefix(raw, "VMESS://")
	nameFromHash := ""
	if i := strings.Index(raw, "#"); i >= 0 {
		nameFromHash = urlUnescape(raw[i+1:])
		raw = raw[:i]
	}
	payload, err := b64Decode(raw)
	if err != nil {
		return nil, fmt.Errorf("vmess base64: %w", err)
	}
	var m map[string]any
	if err := json.Unmarshal(payload, &m); err != nil {
		return nil, fmt.Errorf("vmess json: %w", err)
	}
	n := &model.Node{
		Protocol:       model.ProtocolVMess,
		Name:           firstNonEmpty(nameFromHash, toString(m["ps"]), toString(m["remark"]), toString(m["name"])),
		Server:         firstNonEmpty(toString(m["add"]), toString(m["address"]), toString(m["host"])),
		Port:           toInt(firstNonEmpty(toString(m["port"]), "443")),
		UUID:           firstNonEmpty(toString(m["id"]), toString(m["uuid"])),
		AlterID:        toInt(m["aid"]),
		Method:         firstNonEmpty(toString(m["scy"]), toString(m["cipher"]), "auto"),
		Network:        firstNonEmpty(toString(m["net"]), toString(m["network"]), "tcp"),
		HeaderType:     toString(m["type"]),
		Path:           firstNonEmpty(toString(m["path"]), "/"),
		Host:           firstNonEmpty(toString(m["host"]), toString(m["sni"])),
		SNI:            firstNonEmpty(toString(m["sni"]), toString(m["host"])),
		ALPN:           toString(m["alpn"]),
		Fingerprint:    firstNonEmpty(toString(m["fp"]), toString(m["fingerprint"])),
		Security:       firstNonEmpty(toString(m["tls"]), toString(m["security"])),
		PacketEncoding: toString(m["packetEncoding"]),
		ShareURI:       line,
	}
	if toString(m["tls"]) == "tls" || toString(m["tls"]) == "1" || toString(m["tls"]) == "true" {
		n.Security = "tls"
	}
	if n.Name == "" {
		n.Name = n.Server
	}
	if n.Server == "" || n.UUID == "" || n.Port <= 0 {
		return nil, fmt.Errorf("vmess missing fields")
	}
	return n, nil
}

func parseVLESS(line string) (*model.Node, error) {
	u, err := url.Parse(line)
	if err != nil {
		return nil, err
	}
	host, port := splitHostPort(u.Host, 443)
	q := u.Query()
	n := &model.Node{
		Protocol:       model.ProtocolVLESS,
		Name:           fragmentName(u, host),
		Server:         host,
		Port:           port,
		UUID:           u.User.Username(),
		Flow:           queryFirst(q, "flow"),
		Encryption:     firstNonEmpty(queryFirst(q, "encryption"), "none"),
		Security:       queryFirst(q, "security"),
		SNI:            queryFirst(q, "sni", "peer"),
		ALPN:           queryFirst(q, "alpn"),
		Fingerprint:    queryFirst(q, "fp", "fingerprint"),
		PublicKey:      queryFirst(q, "pbk", "publicKey", "public-key"),
		ShortID:        queryFirst(q, "sid", "shortId", "short-id"),
		SpiderX:        queryFirst(q, "spx", "spiderX"),
		Network:        firstNonEmpty(queryFirst(q, "type", "network"), "tcp"),
		Path:           queryFirst(q, "path", "serviceName"),
		Host:           queryFirst(q, "host", "authority"),
		ServiceName:    queryFirst(q, "serviceName", "service_name"),
		HeaderType:     queryFirst(q, "headerType", "header_type"),
		PacketEncoding: queryFirst(q, "packetEncoding", "packet_encoding"),
		Insecure:       atob(queryFirst(q, "allowInsecure", "insecure")),
		ShareURI:       line,
	}
	if n.Network == "grpc" && n.ServiceName == "" {
		n.ServiceName = queryFirst(q, "serviceName", "path")
	}
	if n.Name == "" {
		n.Name = host
	}
	if n.Server == "" || n.UUID == "" || n.Port <= 0 {
		return nil, fmt.Errorf("vless missing fields")
	}
	return n, nil
}

func parseTrojan(line string) (*model.Node, error) {
	u, err := url.Parse(line)
	if err != nil {
		return nil, err
	}
	host, port := splitHostPort(u.Host, 443)
	pass, _ := u.User.Password()
	if pass == "" {
		pass = u.User.Username()
	}
	q := u.Query()
	n := &model.Node{
		Protocol:    model.ProtocolTrojan,
		Name:        fragmentName(u, host),
		Server:      host,
		Port:        port,
		Password:    pass,
		Security:    firstNonEmpty(queryFirst(q, "security"), "tls"),
		SNI:         queryFirst(q, "sni", "peer"),
		ALPN:        queryFirst(q, "alpn"),
		Fingerprint: queryFirst(q, "fp", "fingerprint"),
		Network:     firstNonEmpty(queryFirst(q, "type", "network"), "tcp"),
		Path:        queryFirst(q, "path"),
		Host:        queryFirst(q, "host"),
		ServiceName: queryFirst(q, "serviceName"),
		HeaderType:  queryFirst(q, "headerType"),
		Insecure:    atob(queryFirst(q, "allowInsecure", "insecure")),
		ShareURI:    line,
	}
	if n.Name == "" {
		n.Name = host
	}
	if n.Server == "" || n.Password == "" || n.Port <= 0 {
		return nil, fmt.Errorf("trojan missing fields")
	}
	return n, nil
}

func parseShadowsocks(line string) (*model.Node, error) {
	trimmed := line
	for _, p := range []string{"ss://", "SS://", "shadowsocks://"} {
		if strings.HasPrefix(trimmed, p) {
			trimmed = trimmed[len(p):]
			break
		}
	}
	name := ""
	if i := strings.Index(trimmed, "#"); i >= 0 {
		name = urlUnescape(trimmed[i+1:])
		trimmed = trimmed[:i]
	}
	plugin := ""
	pluginOpts := ""
	if i := strings.Index(trimmed, "/?"); i >= 0 {
		q, _ := url.ParseQuery(trimmed[i+2:])
		plugin = q.Get("plugin")
		trimmed = trimmed[:i]
	} else if i := strings.Index(trimmed, "?"); i >= 0 {
		q, _ := url.ParseQuery(trimmed[i+1:])
		plugin = q.Get("plugin")
		trimmed = trimmed[:i]
	}
	if plugin != "" {
		if j := strings.IndexByte(plugin, ';'); j >= 0 {
			pluginOpts = plugin[j+1:]
			plugin = plugin[:j]
		}
	}

	method, password, host, port, err := decodeSSUserHost(trimmed)
	if err != nil {
		return nil, err
	}
	n := &model.Node{
		Protocol:   model.ProtocolShadowsocks,
		Name:       firstNonEmpty(name, host),
		Server:     host,
		Port:       port,
		Method:     method,
		Password:   password,
		Plugin:     plugin,
		PluginOpts: pluginOpts,
		ShareURI:   line,
	}
	if n.Server == "" || n.Method == "" || n.Password == "" || n.Port <= 0 {
		return nil, fmt.Errorf("ss missing fields")
	}
	return n, nil
}

func decodeSSUserHost(s string) (method, password, host string, port int, err error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "@") {
		userinfo, hostport, ok := strings.Cut(s, "@")
		if !ok {
			return "", "", "", 0, fmt.Errorf("ss host")
		}
		host, port = splitHostPort(hostport, 8388)
		if decoded, derr := b64Decode(userinfo); derr == nil && strings.Contains(string(decoded), ":") {
			userinfo = string(decoded)
		} else {
			userinfo = urlUnescape(userinfo)
		}
		method, password, ok = strings.Cut(userinfo, ":")
		if !ok {
			return "", "", "", 0, fmt.Errorf("ss userinfo")
		}
		return method, password, host, port, nil
	}
	decoded, derr := b64Decode(s)
	if derr != nil {
		return "", "", "", 0, fmt.Errorf("ss legacy: %w", derr)
	}
	legacy := string(decoded)
	if !strings.Contains(legacy, "@") {
		return "", "", "", 0, fmt.Errorf("ss legacy format")
	}
	userinfo, hostport, _ := strings.Cut(legacy, "@")
	host, port = splitHostPort(hostport, 8388)
	method, password, ok := strings.Cut(userinfo, ":")
	if !ok {
		return "", "", "", 0, fmt.Errorf("ss legacy userinfo")
	}
	return method, password, host, port, nil
}

func parseHysteria2(line string) (*model.Node, error) {
	u, err := url.Parse(line)
	if err != nil {
		return nil, err
	}
	host, port := splitHostPort(u.Host, 443)
	pass, _ := u.User.Password()
	if pass == "" {
		pass = u.User.Username()
	}
	q := u.Query()
	n := &model.Node{
		Protocol:     model.ProtocolHysteria2,
		Name:         fragmentName(u, host),
		Server:       host,
		Port:         port,
		Password:     pass,
		SNI:          queryFirst(q, "sni", "peer"),
		Insecure:     atob(queryFirst(q, "insecure", "allowInsecure")),
		Obfs:         queryFirst(q, "obfs"),
		ObfsPassword: queryFirst(q, "obfs-password", "obfs_password", "obfsPassword"),
		Ports:        queryFirst(q, "mport", "ports"),
		ShareURI:     line,
	}
	if n.Name == "" {
		n.Name = host
	}
	if n.Server == "" || n.Port <= 0 {
		return nil, fmt.Errorf("hysteria2 missing fields")
	}
	return n, nil
}

func parseHysteria(line string) (*model.Node, error) {
	u, err := url.Parse(line)
	if err != nil {
		return nil, err
	}
	host, port := splitHostPort(u.Host, 443)
	q := u.Query()
	auth := firstNonEmpty(queryFirst(q, "auth", "auth_str", "auth-str"), u.User.Username())
	n := &model.Node{
		Protocol:     model.ProtocolHysteria,
		Name:         fragmentName(u, host),
		Server:       host,
		Port:         port,
		Password:     auth,
		SNI:          queryFirst(q, "peer", "sni"),
		Insecure:     atob(queryFirst(q, "insecure", "allowInsecure")),
		Obfs:         queryFirst(q, "obfs"),
		ObfsPassword: queryFirst(q, "obfsParam", "obfs-password"),
		UpMbps:       atoi(queryFirst(q, "upmbps", "up")),
		DownMbps:     atoi(queryFirst(q, "downmbps", "down")),
		ALPN:         queryFirst(q, "alpn"),
		ShareURI:     line,
	}
	if n.Name == "" {
		n.Name = host
	}
	if n.Server == "" || n.Port <= 0 {
		return nil, fmt.Errorf("hysteria missing fields")
	}
	return n, nil
}

func parseTUIC(line string) (*model.Node, error) {
	u, err := url.Parse(line)
	if err != nil {
		return nil, err
	}
	host, port := splitHostPort(u.Host, 443)
	q := u.Query()
	uuid := u.User.Username()
	pass, _ := u.User.Password()
	if pass == "" {
		pass = queryFirst(q, "password")
	}
	if queryFirst(q, "uuid") != "" {
		uuid = queryFirst(q, "uuid")
	}
	n := &model.Node{
		Protocol:     model.ProtocolTUIC,
		Name:         fragmentName(u, host),
		Server:       host,
		Port:         port,
		UUID:         uuid,
		Password:     pass,
		SNI:          queryFirst(q, "sni"),
		ALPN:         queryFirst(q, "alpn"),
		Congestion:   firstNonEmpty(queryFirst(q, "congestion_control", "congestion-control"), "bbr"),
		UDPRelayMode: firstNonEmpty(queryFirst(q, "udp_relay_mode", "udp-relay-mode"), "native"),
		Insecure:     atob(queryFirst(q, "allow_insecure", "insecure")),
		DisableSNI:   atob(queryFirst(q, "disable_sni")),
		ReduceRTT:    atob(queryFirst(q, "reduce_rtt")),
		ShareURI:     line,
	}
	if n.Name == "" {
		n.Name = host
	}
	if n.Server == "" || n.Port <= 0 {
		return nil, fmt.Errorf("tuic missing fields")
	}
	return n, nil
}

func parseSocks(line string) (*model.Node, error) {
	u, err := url.Parse(line)
	if err != nil {
		return nil, err
	}
	host, port := splitHostPort(u.Host, 1080)
	pass, _ := u.User.Password()
	n := &model.Node{
		Protocol: model.ProtocolSocks,
		Name:     fragmentName(u, host),
		Server:   host,
		Port:     port,
		UUID:     u.User.Username(),
		Password: pass,
		ShareURI: line,
	}
	if n.Name == "" {
		n.Name = host
	}
	if n.Server == "" || n.Port <= 0 {
		return nil, fmt.Errorf("socks missing fields")
	}
	return n, nil
}

func parseHTTPProxy(line string) (*model.Node, error) {
	u, err := url.Parse(line)
	if err != nil {
		return nil, err
	}
	def := 80
	if u.Scheme == "https" {
		def = 443
	}
	host, port := splitHostPort(u.Host, def)
	pass, _ := u.User.Password()
	n := &model.Node{
		Protocol: model.ProtocolHTTP,
		Name:     fragmentName(u, host),
		Server:   host,
		Port:     port,
		UUID:     u.User.Username(),
		Password: pass,
		Security: map[bool]string{true: "tls"}[u.Scheme == "https"],
		ShareURI: line,
	}
	if n.Name == "" {
		n.Name = host
	}
	if n.Server == "" || n.Port <= 0 {
		return nil, fmt.Errorf("http proxy missing fields")
	}
	return n, nil
}

func parseWireGuard(line string) (*model.Node, error) {
	u, err := url.Parse(line)
	if err != nil {
		return nil, err
	}
	host, port := splitHostPort(u.Host, 51820)
	q := u.Query()
	n := &model.Node{
		Protocol:      model.ProtocolWireGuard,
		Name:          fragmentName(u, host),
		Server:        host,
		Port:          port,
		PrivateKey:    queryFirst(q, "privateKey", "private-key", "private_key"),
		PeerPublicKey: queryFirst(q, "publicKey", "public-key", "peerPublicKey"),
		PreSharedKey:  queryFirst(q, "presharedKey", "psk", "pre-shared-key"),
		LocalAddress:  queryFirst(q, "address", "ip", "local_address"),
		Reserved:      queryFirst(q, "reserved"),
		MTU:           atoi(queryFirst(q, "mtu")),
		ShareURI:      line,
	}
	if n.Name == "" {
		n.Name = host
	}
	if n.Server == "" || n.Port <= 0 {
		return nil, fmt.Errorf("wireguard missing fields")
	}
	return n, nil
}

func parseAnyTLS(line string) (*model.Node, error) {
	u, err := url.Parse(line)
	if err != nil {
		return nil, err
	}
	host, port := splitHostPort(u.Host, 443)
	pass, _ := u.User.Password()
	if pass == "" {
		pass = u.User.Username()
	}
	q := u.Query()
	n := &model.Node{
		Protocol:    model.ProtocolAnyTLS,
		Name:        fragmentName(u, host),
		Server:      host,
		Port:        port,
		Password:    pass,
		SNI:         queryFirst(q, "sni"),
		Fingerprint: queryFirst(q, "fp", "fingerprint"),
		Insecure:    atob(queryFirst(q, "insecure", "allowInsecure")),
		IdleTimeout: queryFirst(q, "idle-session-check-interval"),
		ShareURI:    line,
	}
	if n.Name == "" {
		n.Name = host
	}
	if n.Server == "" || n.Password == "" || n.Port <= 0 {
		return nil, fmt.Errorf("anytls missing fields")
	}
	return n, nil
}
