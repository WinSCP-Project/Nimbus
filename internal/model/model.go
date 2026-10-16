package model

import "time"

const (
	ProtocolVLESS        = "vless"
	ProtocolVMess        = "vmess"
	ProtocolTrojan       = "trojan"
	ProtocolShadowsocks  = "shadowsocks"
	ProtocolHysteria     = "hysteria"
	ProtocolHysteria2    = "hysteria2"
	ProtocolTUIC         = "tuic"
	ProtocolSocks        = "socks"
	ProtocolHTTP         = "http"
	ProtocolWireGuard    = "wireguard"
	ProtocolAnyTLS       = "anytls"
	ProtocolSSH          = "ssh"
	ProtocolShadowTLS    = "shadowtls"

	ModeRule   = "rule"
	ModeGlobal = "global"
	ModeDirect = "direct"

	LatencyUnknown = 0
	LatencyFail    = -1
)

type Subscription struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	URL       string `json:"url"`
	UserAgent string `json:"user_agent"`
	LastError string `json:"last_error"`
	UpdatedAt int64  `json:"updated_at"`
	Upload    int64  `json:"upload"`
	Download  int64  `json:"download"`
	Total     int64  `json:"total"`
	Expire    int64  `json:"expire"`
	Manual    bool   `json:"manual"`
}

type Node struct {
	ID       string `json:"id"`
	SubID    string `json:"sub_id"`
	Name     string `json:"name"`
	Protocol string `json:"protocol"`
	Server   string `json:"server"`
	Port     int    `json:"port"`

	UUID     string `json:"uuid,omitempty"`
	Password string `json:"password,omitempty"`
	Method   string `json:"method,omitempty"`
	Flow     string `json:"flow,omitempty"`
	AlterID  int    `json:"alter_id,omitempty"`

	Security    string `json:"security,omitempty"`
	SNI         string `json:"sni,omitempty"`
	ALPN        string `json:"alpn,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	PublicKey   string `json:"public_key,omitempty"`
	ShortID     string `json:"short_id,omitempty"`
	SpiderX     string `json:"spider_x,omitempty"`
	Insecure    bool   `json:"insecure,omitempty"`

	Network     string `json:"network,omitempty"`
	Path        string `json:"path,omitempty"`
	Host        string `json:"host,omitempty"`
	ServiceName string `json:"service_name,omitempty"`
	HeaderType  string `json:"header_type,omitempty"`
	ExtraHost   string `json:"extra_host,omitempty"`

	PacketEncoding string `json:"packet_encoding,omitempty"`
	Encryption     string `json:"encryption,omitempty"`

	Obfs         string `json:"obfs,omitempty"`
	ObfsPassword string `json:"obfs_password,omitempty"`
	UpMbps       int    `json:"up_mbps,omitempty"`
	DownMbps     int    `json:"down_mbps,omitempty"`
	Ports        string `json:"ports,omitempty"`

	Congestion     string `json:"congestion,omitempty"`
	UDPRelayMode   string `json:"udp_relay_mode,omitempty"`
	Plugin         string `json:"plugin,omitempty"`
	PluginOpts     string `json:"plugin_opts,omitempty"`
	PrivateKey     string `json:"private_key,omitempty"`
	PeerPublicKey  string `json:"peer_public_key,omitempty"`
	PreSharedKey   string `json:"pre_shared_key,omitempty"`
	LocalAddress   string `json:"local_address,omitempty"`
	Reserved       string `json:"reserved,omitempty"`
	MTU            int    `json:"mtu,omitempty"`
	DisableSNI     bool   `json:"disable_sni,omitempty"`
	ReduceRTT      bool   `json:"reduce_rtt,omitempty"`
	IdleTimeout    string `json:"idle_timeout,omitempty"`
	Multiplex      bool   `json:"multiplex,omitempty"`
	ShareURI       string `json:"share_uri,omitempty"`

	LatencyMS int   `json:"latency_ms"`
	Disabled  bool  `json:"disabled"`
	UpdatedAt int64 `json:"updated_at"`
}

type Settings struct {
	Listen        string `json:"listen"`
	MixedPort     int    `json:"mixed_port"`
	ClashAPIPort  int    `json:"clash_api_port"`
	BindLAN       bool   `json:"bind_lan"`
	Mode          string `json:"mode"`
	TUN           bool   `json:"tun"`
	TUNStack      string `json:"tun_stack"`
	AllowInsecure bool   `json:"allow_insecure"`
	Mux           bool   `json:"mux"`
	RemoteDNS     string `json:"remote_dns"`
	DirectDNS     string `json:"direct_dns"`
	LogLevel      string `json:"log_level"`
	AutoUpdateH   int    `json:"auto_update_h"`
	UserAgent     string `json:"user_agent"`
	TestURL       string `json:"test_url"`
	PingTimeoutMS int    `json:"ping_timeout_ms"`
	Exclude       string `json:"exclude"`
	Include       string `json:"include"`
}

func DefaultSettings() Settings {
	return Settings{
		Listen:        "127.0.0.1:8787",
		MixedPort:     10808,
		ClashAPIPort:  9090,
		BindLAN:       false,
		Mode:          ModeRule,
		TUN:           false,
		TUNStack:      "mixed",
		AllowInsecure: false,
		Mux:           false,
		RemoteDNS:     "tls://8.8.8.8",
		DirectDNS:     "local",
		LogLevel:      "info",
		AutoUpdateH:   6,
		UserAgent:     "Nimbus/1.0 (sing-box; clash-meta)",
		TestURL:       "https://www.gstatic.com/generate_204",
		PingTimeoutMS: 4000,
	}
}

type State struct {
	Settings       Settings       `json:"settings"`
	Subscriptions  []Subscription `json:"subscriptions"`
	Nodes          []Node         `json:"nodes"`
	SelectedNodeID string         `json:"selected_node_id"`
}

type Snapshot struct {
	Settings       Settings       `json:"settings"`
	Subscriptions  []Subscription `json:"subscriptions"`
	Nodes          []Node         `json:"nodes"`
	SelectedNodeID string         `json:"selected_node_id"`
	Connected      bool           `json:"connected"`
	Connecting     bool           `json:"connecting"`
	CoreVersion    string         `json:"core_version"`
	Uplink         int64          `json:"uplink"`
	Downlink       int64          `json:"downlink"`
	StartedAt      int64          `json:"started_at"`
	LastError      string         `json:"last_error"`
	Now            int64          `json:"now"`
}

func (s Settings) EffectiveListenAddr() string {
	host := "127.0.0.1"
	if s.BindLAN {
		host = "0.0.0.0"
	}
	return host
}

func (n Node) Endpoint() string {
	if n.Server == "" || n.Port <= 0 {
		return ""
	}
	return n.Server
}

func QuotaLabel(sub Subscription) string {
	if sub.Total <= 0 && sub.Expire <= 0 {
		return ""
	}
	return ""
}

func NodeMatches(n Node, include, exclude string) bool {
	name := n.Name
	if exclude != "" && containsFold(name, exclude) {
		return false
	}
	if include != "" && !containsFold(name, include) {
		return false
	}
	return true
}

func containsFold(hay, needlesCSV string) bool {
	if needlesCSV == "" {
		return false
	}
	h := fold(hay)
	start := 0
	for i := 0; i <= len(needlesCSV); i++ {
		if i == len(needlesCSV) || needlesCSV[i] == ',' {
			part := trim(needlesCSV[start:i])
			if part != "" && containsStr(h, fold(part)) {
				return true
			}
			start = i + 1
		}
	}
	return false
}

func fold(s string) string {
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		b = append(b, c)
	}
	return string(b)
}

func containsStr(h, n string) bool {
	return len(n) > 0 && len(h) >= len(n) && (h == n || indexOf(h, n) >= 0)
}

func indexOf(h, n string) int {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return i
		}
	}
	return -1
}

func trim(s string) string {
	i, j := 0, len(s)
	for i < j && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	for j > i && (s[j-1] == ' ' || s[j-1] == '\t') {
		j--
	}
	return s[i:j]
}

func NowUnix() int64 { return time.Now().Unix() }
