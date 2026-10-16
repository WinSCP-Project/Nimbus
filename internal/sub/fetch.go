package sub

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"nimbus/internal/model"
	"nimbus/internal/parser"
)

type Result struct {
	Nodes     []model.Node
	Kind      string
	Upload    int64
	Download  int64
	Total     int64
	Expire    int64
	Title     string
}

func Fetch(ctx context.Context, rawURL, userAgent string) (Result, error) {
	var r Result
	if strings.TrimSpace(rawURL) == "" {
		return r, fmt.Errorf("пустой URL")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return r, err
	}
	if userAgent == "" {
		userAgent = "Nimbus/1.0 (clash-meta; sing-box; v2rayN/6.0)"
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "*/*")
	client := &http.Client{Timeout: 45 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return r, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return r, fmt.Errorf("HTTP %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return r, err
	}
	parseUserInfo(resp.Header, &r)
	if t := strings.TrimSpace(resp.Header.Get("profile-title")); t != "" {
		r.Title = t
	}
	if t := strings.TrimSpace(resp.Header.Get("content-disposition")); t != "" && r.Title == "" {
		r.Title = t
	}
	decoded, err := parser.DecodeSubscription(body)
	if err != nil {
		return r, err
	}
	r.Kind = decoded.Kind
	r.Nodes = decoded.Nodes
	if len(r.Nodes) == 0 {
		return r, fmt.Errorf("в ответе нет узлов (kind=%s)", decoded.Kind)
	}
	return r, nil
}

func parseUserInfo(h http.Header, r *Result) {
	raw := h.Get("subscription-userinfo")
	if raw == "" {
		raw = h.Get("Subscription-Userinfo")
	}
	if raw == "" {
		return
	}
	for _, part := range strings.Split(raw, ";") {
		part = strings.TrimSpace(part)
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		n, _ := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "upload":
			r.Upload = n
		case "download":
			r.Download = n
		case "total":
			r.Total = n
		case "expire":
			r.Expire = n
		}
	}
}
