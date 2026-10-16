package parser

import (
	"encoding/base64"
	"encoding/json"
	"net"
	"net/url"
	"strconv"
	"strings"
)

func b64Decode(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "-", "+")
	s = strings.ReplaceAll(s, "_", "/")
	s = strings.TrimRight(s, "=")
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	if raw, err := base64.StdEncoding.DecodeString(s); err == nil {
		return raw, nil
	}
	return base64.RawStdEncoding.DecodeString(s)
}

func queryFirst(q url.Values, keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(q.Get(k)); v != "" {
			return v
		}
	}
	return ""
}

func atoi(s string) int {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		f, err2 := strconv.ParseFloat(s, 64)
		if err2 != nil {
			return 0
		}
		return int(f)
	}
	return n
}

func atob(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func splitHostPort(hostport string, defPort int) (string, int) {
	hostport = strings.TrimSpace(hostport)
	if hostport == "" {
		return "", defPort
	}
	if h, p, err := net.SplitHostPort(hostport); err == nil {
		return h, atoi(p)
	}
	if strings.HasPrefix(hostport, "[") {
		if i := strings.LastIndex(hostport, "]"); i > 0 {
			host := hostport[1:i]
			rest := hostport[i+1:]
			if strings.HasPrefix(rest, ":") {
				return host, atoi(rest[1:])
			}
			return host, defPort
		}
	}
	if i := strings.LastIndex(hostport, ":"); i > 0 && strings.Count(hostport, ":") == 1 {
		return hostport[:i], atoi(hostport[i+1:])
	}
	return hostport, defPort
}

func urlUnescape(s string) string {
	if s == "" {
		return s
	}
	if u, err := url.QueryUnescape(s); err == nil {
		return u
	}
	return s
}

func fragmentName(u *url.URL, fallback string) string {
	if u == nil {
		return fallback
	}
	if u.Fragment != "" {
		return urlUnescape(u.Fragment)
	}
	return fallback
}

func asMap(v any) map[string]any {
	switch t := v.(type) {
	case map[string]any:
		return t
	case map[any]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			out[toString(k)] = val
		}
		return out
	default:
		return nil
	}
}

func asSlice(v any) []any {
	switch t := v.(type) {
	case []any:
		return t
	default:
		return nil
	}
}

func toString(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case []byte:
		return string(t)
	case json.Number:
		return t.String()
	case int:
		return strconv.Itoa(t)
	case int64:
		return strconv.FormatInt(t, 10)
	case float64:
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		if t {
			return "true"
		}
		return "false"
	default:
		b, err := json.Marshal(t)
		if err != nil {
			return ""
		}
		return strings.Trim(string(b), `"`)
	}
}

func toInt(v any) int {
	switch t := v.(type) {
	case int:
		return t
	case int64:
		return int(t)
	case float64:
		return int(t)
	case json.Number:
		n, _ := t.Int64()
		return int(n)
	case string:
		return atoi(t)
	case bool:
		if t {
			return 1
		}
		return 0
	default:
		return atoi(toString(v))
	}
}

func toBool(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	default:
		return atob(toString(v))
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func csvALPN(s string) string {
	return strings.ReplaceAll(strings.TrimSpace(s), ",", ",")
}
