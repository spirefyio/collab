package api

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/spirefyio/collab/server/internal/config"
)

func newTestRouter(t *testing.T) http.Handler {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	return NewRouter(&config.Config{
		ListenAddr:         ":0",
		WSReadBufferBytes:  4096,
		WSWriteBufferBytes: 4096,
	}, logger)
}

func TestHealthHandler_ReturnsOK(t *testing.T) {
	r := newTestRouter(t)
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("expected JSON content-type, got %q", ct)
	}

	var body healthResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.Status != "ok" {
		t.Errorf("expected status=ok, got %q", body.Status)
	}
	if body.Version == "" {
		t.Errorf("expected non-empty version")
	}
	if time.Since(body.Time) > 5*time.Second {
		t.Errorf("expected fresh timestamp, got %v", body.Time)
	}
}

func TestRootHandler_ReturnsServiceBanner(t *testing.T) {
	r := newTestRouter(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), `"service":"spirefyio/collab"`) {
		t.Errorf("expected service banner, got %q", rr.Body.String())
	}
}

func TestHealthHandler_DoesNotLeakEnv(t *testing.T) {
	t.Setenv("COLLAB_JWT_SECRET", "sensitive-do-not-leak-into-responses")
	r := newTestRouter(t)
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if strings.Contains(rr.Body.String(), "sensitive-do-not-leak") {
		t.Fatal("response body leaked env var contents")
	}
	_ = os.Environ
}
