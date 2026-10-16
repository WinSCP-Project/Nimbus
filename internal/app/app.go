package app

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"nimbus/internal/core"
	"nimbus/internal/model"
	"nimbus/internal/parser"
	"nimbus/internal/ping"
	"nimbus/internal/store"
	"nimbus/internal/sub"
)

type App struct {
	Store  *store.Store
	Engine *core.Engine

	mu     sync.Mutex
	stopAU context.CancelFunc
}

func New(st *store.Store, eng *core.Engine) *App {
	return &App{Store: st, Engine: eng}
}

func (a *App) Snapshot() model.Snapshot {
	st := a.Store.Snapshot()
	connected, connecting, started, lastErr, ver, up, down := a.Engine.Status()
	return model.Snapshot{
		Settings:       st.Settings,
		Subscriptions:  st.Subscriptions,
		Nodes:          st.Nodes,
		SelectedNodeID: st.SelectedNodeID,
		Connected:      connected,
		Connecting:     connecting,
		CoreVersion:    firstLine(ver),
		Uplink:         up,
		Downlink:       down,
		StartedAt:      started,
		LastError:      lastErr,
		Now:            time.Now().Unix(),
	}
}

func (a *App) AddSubscription(ctx context.Context, name, rawURL, ua string) (model.Subscription, error) {
	rawURL = strings.TrimSpace(rawURL)
	name = strings.TrimSpace(name)
	manual := rawURL == ""
	subrec := model.Subscription{
		Name:      name,
		URL:       rawURL,
		UserAgent: ua,
		Manual:    manual,
		UpdatedAt: model.NowUnix(),
	}
	if name == "" {
		if manual {
			subrec.Name = "Ручные узлы"
		} else {
			subrec.Name = "Подписка"
		}
	}
	created, err := a.Store.AddSubscription(subrec)
	if err != nil {
		return created, err
	}
	if !manual {
		if err := a.UpdateSubscription(ctx, created.ID); err != nil {
			return created, err
		}
		if refreshed := a.Store.SubscriptionByID(created.ID); refreshed != nil {
			created = *refreshed
		}
	}
	a.Engine.Logf("добавлена подписка %s", created.Name)
	return created, nil
}

func (a *App) UpdateSubscription(ctx context.Context, id string) error {
	s := a.Store.SubscriptionByID(id)
	if s == nil {
		return fmt.Errorf("подписка не найдена")
	}
	if s.Manual || s.URL == "" {
		return fmt.Errorf("ручная подписка не обновляется по URL")
	}
	ua := s.UserAgent
	if ua == "" {
		ua = a.Store.Settings().UserAgent
	}
	res, err := sub.Fetch(ctx, s.URL, ua)
	if err != nil {
		_ = a.Store.UpdateSubscription(id, func(x *model.Subscription) {
			x.LastError = err.Error()
		})
		return err
	}
	include := a.Store.Settings().Include
	exclude := a.Store.Settings().Exclude
	filtered := res.Nodes[:0]
	for _, n := range res.Nodes {
		if model.NodeMatches(n, include, exclude) {
			filtered = append(filtered, n)
		}
	}
	res.Nodes = filtered
	if err := a.Store.ReplaceNodes(id, res.Nodes); err != nil {
		return err
	}
	return a.Store.UpdateSubscription(id, func(x *model.Subscription) {
		x.LastError = ""
		x.UpdatedAt = model.NowUnix()
		x.Upload = res.Upload
		x.Download = res.Download
		x.Total = res.Total
		x.Expire = res.Expire
		if res.Title != "" && (x.Name == "" || x.Name == "Подписка") {
			x.Name = res.Title
		}
	})
}

func (a *App) UpdateAll(ctx context.Context) error {
	st := a.Store.Snapshot()
	var first error
	for _, s := range st.Subscriptions {
		if s.Manual || s.URL == "" {
			continue
		}
		if err := a.UpdateSubscription(ctx, s.ID); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func (a *App) ImportShare(ctx context.Context, subID, text string) (int, error) {
	nodes := parser.ParseShareList(text)
	if len(nodes) == 0 {
		decoded, err := parser.DecodeSubscription([]byte(text))
		if err != nil {
			return 0, err
		}
		nodes = decoded.Nodes
	}
	if len(nodes) == 0 {
		return 0, fmt.Errorf("не распознано ни одного узла")
	}
	if subID == "" {
		created, err := a.AddSubscription(ctx, "Импорт", "", "")
		if err != nil {
			return 0, err
		}
		subID = created.ID
	}
	if err := a.Store.AddManualNodes(subID, nodes); err != nil {
		return 0, err
	}
	return len(nodes), nil
}

func (a *App) Connect(ctx context.Context, nodeID string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if nodeID != "" {
		if err := a.Store.SelectNode(nodeID); err != nil {
			return err
		}
	}
	node := a.Store.SelectedNode()
	if node == nil {
		return fmt.Errorf("узел не выбран")
	}
	connected, _, _, _, _, _, _ := a.Engine.Status()
	if connected {
		_ = a.Engine.Stop()
	}
	return a.Engine.Start(ctx, *node, a.Store.Settings())
}

func (a *App) Disconnect() error {
	return a.Engine.Stop()
}

func (a *App) PingOne(ctx context.Context, id string) (int, error) {
	n := a.Store.NodeByID(id)
	if n == nil {
		return model.LatencyFail, fmt.Errorf("узел не найден")
	}
	ms := ping.TCP(ctx, n.Server, n.Port, a.Store.Settings().PingTimeoutMS)
	_ = a.Store.SetLatency(id, ms)
	return ms, nil
}

func (a *App) PingAll(ctx context.Context) (map[string]int, error) {
	nodes := a.Store.Nodes()
	values := ping.Many(ctx, nodes, a.Store.Settings().PingTimeoutMS, 32)
	if err := a.Store.SetManyLatency(values); err != nil {
		return values, err
	}
	return values, nil
}

func (a *App) StartAutoUpdate() {
	a.mu.Lock()
	if a.stopAU != nil {
		a.stopAU()
	}
	ctx, cancel := context.WithCancel(context.Background())
	a.stopAU = cancel
	a.mu.Unlock()
	go func() {
		for {
			h := a.Store.Settings().AutoUpdateH
			if h <= 0 {
				h = 6
			}
			t := time.NewTimer(time.Duration(h) * time.Hour)
			select {
			case <-ctx.Done():
				t.Stop()
				return
			case <-t.C:
				c2, cancel2 := context.WithTimeout(ctx, 4*time.Minute)
				_ = a.UpdateAll(c2)
				cancel2()
			}
		}
	}()
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return strings.TrimSpace(s)
}
