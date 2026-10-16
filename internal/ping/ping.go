package ping

import (
	"context"
	"net"
	"strconv"
	"sync"
	"time"

	"nimbus/internal/model"
)

func TCP(ctx context.Context, host string, port, timeoutMS int) int {
	if host == "" || port <= 0 {
		return model.LatencyFail
	}
	d := time.Duration(timeoutMS) * time.Millisecond
	if d <= 0 {
		d = 4 * time.Second
	}
	dialer := net.Dialer{Timeout: d}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	start := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return model.LatencyFail
	}
	_ = conn.Close()
	ms := int(time.Since(start).Milliseconds())
	if ms <= 0 {
		ms = 1
	}
	return ms
}

func Many(ctx context.Context, nodes []model.Node, timeoutMS, workers int) map[string]int {
	if workers <= 0 {
		workers = 32
	}
	out := make(map[string]int, len(nodes))
	var mu sync.Mutex
	ch := make(chan model.Node)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := range ch {
				ms := TCP(ctx, n.Server, n.Port, timeoutMS)
				mu.Lock()
				out[n.ID] = ms
				mu.Unlock()
			}
		}()
	}
	for _, n := range nodes {
		select {
		case <-ctx.Done():
		case ch <- n:
		}
	}
	close(ch)
	wg.Wait()
	return out
}
