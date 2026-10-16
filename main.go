package main

import (
	"context"
	"embed"
	"flag"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"nimbus/internal/api"
	"nimbus/internal/app"
	"nimbus/internal/core"
	"nimbus/internal/store"
)

//go:embed web
var embeddedWeb embed.FS

func main() {
	defDir, _ := os.UserHomeDir()
	if defDir == "" {
		defDir = "."
	}
	defDir = filepath.Join(defDir, ".nimbus")

	dataDir := flag.String("data", defDir, "каталог данных")
	listen := flag.String("listen", "", "адрес UI (перекрывает настройки)")
	flag.Parse()

	if err := os.MkdirAll(*dataDir, 0o700); err != nil {
		log.Fatal(err)
	}

	st, err := store.Open(*dataDir)
	if err != nil {
		log.Fatal(err)
	}
	eng := core.New(*dataDir)
	application := app.New(st, eng)
	application.StartAutoUpdate()

	webRoot, err := fs.Sub(embeddedWeb, "web")
	if err != nil {
		log.Fatal(err)
	}

	srv := &api.Server{
		App: application,
		FS:  http.FileServer(http.FS(webRoot)),
	}

	addr := *listen
	if addr == "" {
		addr = st.Settings().Listen
	}
	if addr == "" {
		addr = "127.0.0.1:8787"
	}

	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		eng.Logf("Nimbus UI на http://%s", addr)
		log.Printf("Nimbus listening on http://%s", addr)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()

	<-ctx.Done()
	_ = application.Disconnect()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutdownCtx)
}
