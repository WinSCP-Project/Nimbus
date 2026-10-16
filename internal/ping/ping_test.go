package ping

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestTCPLocal(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			_ = c.Close()
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	var p int
	for _, ch := range port {
		p = p*10 + int(ch-'0')
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ms := TCP(ctx, "127.0.0.1", p, 2000)
	if ms <= 0 {
		t.Fatalf("latency %d", ms)
	}
}

func TestTCPFail(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ms := TCP(ctx, "127.0.0.1", 1, 400)
	if ms != -1 {
		t.Fatalf("want fail, got %d", ms)
	}
}
