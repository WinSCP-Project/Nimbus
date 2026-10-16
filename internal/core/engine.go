package core

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"nimbus/internal/model"
)

type Engine struct {
	mu         sync.Mutex
	dir        string
	cmd        *exec.Cmd
	cancel     context.CancelFunc
	connected  bool
	connecting bool
	startedAt  int64
	lastErr    string
	version    string
	logBuf     *ring
	up         int64
	down       int64
}

func New(dir string) *Engine {
	return &Engine{
		dir:    dir,
		logBuf: newRing(400),
	}
}

func (e *Engine) Status() (connected, connecting bool, startedAt int64, lastErr, version string, up, down int64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.connected, e.connecting, e.startedAt, e.lastErr, e.version, e.up, e.down
}

func (e *Engine) Logs() []string {
	return e.logBuf.snapshot()
}

func (e *Engine) Logf(format string, args ...any) {
	e.logBuf.add(fmt.Sprintf(format, args...))
}

func (e *Engine) EnsureBinary(ctx context.Context) (string, error) {
	if p, err := e.lookup(); err == nil {
		e.mu.Lock()
		e.version = e.readVersion(p)
		e.mu.Unlock()
		return p, nil
	}
	e.Logf("ядро sing-box не найдено, скачиваю релиз")
	p, err := e.download(ctx)
	if err != nil {
		return "", err
	}
	e.mu.Lock()
	e.version = e.readVersion(p)
	e.mu.Unlock()
	return p, nil
}

func (e *Engine) Start(ctx context.Context, node model.Node, st model.Settings) error {
	e.mu.Lock()
	if e.connected || e.connecting {
		e.mu.Unlock()
		return errors.New("уже подключено")
	}
	e.connecting = true
	e.lastErr = ""
	e.mu.Unlock()

	fail := func(err error) error {
		e.mu.Lock()
		e.connecting = false
		e.connected = false
		e.lastErr = err.Error()
		e.mu.Unlock()
		e.Logf("ошибка запуска: %s", err.Error())
		return err
	}

	bin, err := e.EnsureBinary(ctx)
	if err != nil {
		return fail(err)
	}
	cfg, err := Generate(node, st)
	if err != nil {
		return fail(err)
	}
	raw, err := Marshal(cfg)
	if err != nil {
		return fail(err)
	}
	cfgPath := filepath.Join(e.dir, "sing-box.json")
	if err := os.WriteFile(cfgPath, raw, 0o600); err != nil {
		return fail(err)
	}

	check := exec.CommandContext(ctx, bin, "check", "-c", cfgPath)
	if out, err := check.CombinedOutput(); err != nil {
		return fail(fmt.Errorf("sing-box check: %s (%w)", strings.TrimSpace(string(out)), err))
	}

	runCtx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(runCtx, bin, "run", "-c", cfgPath, "-D", e.dir)
	cmd.Dir = e.dir
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return fail(err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		cancel()
		return fail(err)
	}
	if err := cmd.Start(); err != nil {
		cancel()
		return fail(err)
	}
	go e.pipeLogs(stdout)
	go e.pipeLogs(stderr)
	go e.wait(cmd, cancel)

	e.mu.Lock()
	e.cmd = cmd
	e.cancel = cancel
	e.connected = true
	e.connecting = false
	e.startedAt = time.Now().Unix()
	e.up, e.down = 0, 0
	e.mu.Unlock()
	e.Logf("подключено к %s (%s:%d)", node.Name, node.Server, node.Port)

	go e.pollTraffic(st)
	return nil
}

func (e *Engine) Stop() error {
	e.mu.Lock()
	cmd := e.cmd
	cancel := e.cancel
	e.cmd = nil
	e.cancel = nil
	e.connected = false
	e.connecting = false
	e.startedAt = 0
	e.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}
	e.Logf("отключено")
	return nil
}

func (e *Engine) wait(cmd *exec.Cmd, cancel context.CancelFunc) {
	err := cmd.Wait()
	cancel()
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.cmd == cmd {
		e.cmd = nil
		e.connected = false
		e.connecting = false
		if err != nil && !errors.Is(err, context.Canceled) {
			e.lastErr = err.Error()
			e.logBuf.add("ядро остановилось: " + err.Error())
		}
	}
}

func (e *Engine) pipeLogs(r io.Reader) {
	buf := make([]byte, 4096)
	var leftover []byte
	for {
		n, err := r.Read(buf)
		if n > 0 {
			chunk := append(leftover, buf[:n]...)
			lines := bytes.Split(chunk, []byte{'\n'})
			leftover = lines[len(lines)-1]
			for _, line := range lines[:len(lines)-1] {
				s := strings.TrimSpace(string(line))
				if s != "" {
					e.logBuf.add(s)
				}
			}
		}
		if err != nil {
			if len(leftover) > 0 {
				e.logBuf.add(strings.TrimSpace(string(leftover)))
			}
			return
		}
	}
}

func (e *Engine) pollTraffic(st model.Settings) {
	client := &http.Client{Timeout: 2 * time.Second}
	url := fmt.Sprintf("http://%s:%d/connections", st.EffectiveListenAddr(), st.ClashAPIPort)
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		e.mu.Lock()
		alive := e.connected
		e.mu.Unlock()
		if !alive {
			return
		}
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		var payload struct {
			DownloadTotal int64 `json:"downloadTotal"`
			UploadTotal   int64 `json:"uploadTotal"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&payload)
		resp.Body.Close()
		e.mu.Lock()
		e.down = payload.DownloadTotal
		e.up = payload.UploadTotal
		e.mu.Unlock()
	}
}

func (e *Engine) lookup() (string, error) {
	candidates := []string{
		filepath.Join(e.dir, "bin", exeName()),
		filepath.Join(e.dir, exeName()),
	}
	if p, err := exec.LookPath("sing-box"); err == nil {
		candidates = append([]string{p}, candidates...)
	}
	for _, p := range candidates {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, nil
		}
	}
	return "", errors.New("sing-box not found")
}

func (e *Engine) readVersion(bin string) string {
	out, err := exec.Command(bin, "version").CombinedOutput()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func (e *Engine) download(ctx context.Context) (string, error) {
	arch := runtime.GOARCH
	osName := runtime.GOOS
	assetArch := arch
	switch arch {
	case "amd64":
		assetArch = "amd64"
	case "arm64":
		assetArch = "arm64"
	case "386":
		assetArch = "386"
	}
	api := "https://api.github.com/repos/SagerNet/sing-box/releases/latest"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, api, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "Nimbus/1.0")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("github releases: %s", resp.Status)
	}
	var rel struct {
		TagName string `json:"tag_name"`
		Assets  []struct {
			Name               string `json:"name"`
			BrowserDownloadURL string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return "", err
	}
	want := fmt.Sprintf("sing-box-%s-%s-%s.tar.gz", strings.TrimPrefix(rel.TagName, "v"), osName, assetArch)
	if osName == "windows" {
		want = fmt.Sprintf("sing-box-%s-%s-%s.zip", strings.TrimPrefix(rel.TagName, "v"), osName, assetArch)
	}
	var url string
	for _, a := range rel.Assets {
		if a.Name == want {
			url = a.BrowserDownloadURL
			break
		}
	}
	if url == "" {
		return "", fmt.Errorf("нет ассета %s", want)
	}
	binDir := filepath.Join(e.dir, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		return "", err
	}
	archive := filepath.Join(binDir, want)
	if err := httpGetFile(ctx, url, archive); err != nil {
		return "", err
	}
	if err := extractArchive(archive, binDir); err != nil {
		return "", err
	}
	target := filepath.Join(binDir, exeName())
	if _, err := os.Stat(target); err != nil {
		_ = filepath.Walk(binDir, func(path string, info os.FileInfo, err error) error {
			if err == nil && !info.IsDir() && info.Name() == exeName() && path != target {
				_ = os.Rename(path, target)
			}
			return nil
		})
	}
	if runtime.GOOS != "windows" {
		_ = os.Chmod(target, 0o755)
	}
	if _, err := os.Stat(target); err != nil {
		return "", fmt.Errorf("не удалось извлечь sing-box")
	}
	e.Logf("ядро %s установлено", rel.TagName)
	return target, nil
}

func httpGetFile(ctx context.Context, url, dest string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "Nimbus/1.0")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("download %s", resp.Status)
	}
	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, resp.Body)
	return err
}

func extractArchive(archive, dest string) error {
	if strings.HasSuffix(archive, ".zip") {
		cmd := exec.Command("tar", "-xf", archive, "-C", dest)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("unzip: %s %w", out, err)
		}
		return nil
	}
	cmd := exec.Command("tar", "-xzf", archive, "-C", dest, "--strip-components=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		cmd = exec.Command("tar", "-xzf", archive, "-C", dest)
		if out2, err2 := cmd.CombinedOutput(); err2 != nil {
			return fmt.Errorf("tar: %s %s", strings.TrimSpace(string(out)), strings.TrimSpace(string(out2)))
		}
	}
	return nil
}

func exeName() string {
	if runtime.GOOS == "windows" {
		return "sing-box.exe"
	}
	return "sing-box"
}

type ring struct {
	mu   sync.Mutex
	max  int
	data []string
}

func newRing(n int) *ring { return &ring{max: n} }

func (r *ring) add(s string) {
	line := time.Now().Format("15:04:05") + "  " + s
	r.mu.Lock()
	defer r.mu.Unlock()
	r.data = append(r.data, line)
	if len(r.data) > r.max {
		r.data = r.data[len(r.data)-r.max:]
	}
}

func (r *ring) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.data))
	copy(out, r.data)
	return out
}
