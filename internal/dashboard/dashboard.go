// Package dashboard serves the embedded live-metrics page: a single HTML
// file (go:embed, no external assets), a JSON snapshot endpoint and an SSE
// stream pushing a fresh snapshot every 500ms.
package dashboard

import (
	"context"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"
)

//go:embed static/index.html
var static embed.FS

// Interval is the SSE push cadence.
const Interval = 500 * time.Millisecond

// Serve runs the dashboard until ctx is cancelled. src produces the
// current metrics snapshot; token (optional) gates every route.
func Serve(ctx context.Context, listen, token string, src func() any, log *slog.Logger) {
	mux := http.NewServeMux()

	auth := func(h http.HandlerFunc) http.HandlerFunc {
		if token == "" {
			return h
		}
		return func(w http.ResponseWriter, r *http.Request) {
			got := r.URL.Query().Get("token")
			if got == "" {
				got = r.Header.Get("Authorization")
				if len(got) > 7 && got[:7] == "Bearer " {
					got = got[7:]
				}
			}
			if subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			h(w, r)
		}
	}

	mux.HandleFunc("GET /", auth(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		page, _ := static.ReadFile("static/index.html")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(page)
	}))

	mux.HandleFunc("GET /api/metrics", auth(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(src())
	}))

	mux.HandleFunc("GET /events", auth(func(w http.ResponseWriter, r *http.Request) {
		fl, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-store")
		enc := json.NewEncoder(w)
		t := time.NewTicker(Interval)
		defer t.Stop()
		for {
			select {
			case <-r.Context().Done():
				return
			case <-ctx.Done():
				return
			case <-t.C:
				w.Write([]byte("data: "))
				if err := enc.Encode(src()); err != nil {
					return
				}
				w.Write([]byte("\n"))
				fl.Flush()
			}
		}
	}))

	srv := &http.Server{Addr: listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		srv.Shutdown(shutdownCtx)
	}()
	log.Info("dashboard listening", "addr", listen)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Error("dashboard", "err", err)
	}
}
