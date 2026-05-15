package config

import (
	"strings"
	"testing"
	"time"
)

func TestLoad_DefaultsForLocalDev(t *testing.T) {
	t.Setenv("COLLAB_LISTEN_ADDR", "")
	t.Setenv("COLLAB_PRODUCTION", "")
	t.Setenv("COLLAB_JWT_SECRET", "")
	t.Setenv("COLLAB_DATABASE_URL", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load returned error in dev mode: %v", err)
	}
	if cfg.ListenAddr != ":8443" {
		t.Errorf("default ListenAddr expected :8443, got %q", cfg.ListenAddr)
	}
	if cfg.JWTTTL != 24*time.Hour {
		t.Errorf("default JWTTTL expected 24h, got %v", cfg.JWTTTL)
	}
	if cfg.Production {
		t.Errorf("expected Production=false by default")
	}
}

func TestLoad_ProductionRequiresSecrets(t *testing.T) {
	t.Setenv("COLLAB_PRODUCTION", "1")
	t.Setenv("COLLAB_JWT_SECRET", "")
	t.Setenv("COLLAB_DATABASE_URL", "")

	_, err := Load()
	if err == nil {
		t.Fatal("expected error in production without JWT secret")
	}
	if !strings.Contains(err.Error(), "COLLAB_JWT_SECRET") {
		t.Errorf("expected COLLAB_JWT_SECRET in error, got %v", err)
	}
}

func TestLoad_ProductionRejectsShortSecret(t *testing.T) {
	t.Setenv("COLLAB_PRODUCTION", "1")
	t.Setenv("COLLAB_JWT_SECRET", "too-short")
	t.Setenv("COLLAB_DATABASE_URL", "postgres://x")
	t.Setenv("COLLAB_OAUTH_REDIRECT_BASE_URL", "https://example.com")

	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), ">= 32 bytes") {
		t.Fatalf("expected short-secret rejection, got %v", err)
	}
}

func TestLoad_ProductionAcceptsValidConfig(t *testing.T) {
	t.Setenv("COLLAB_PRODUCTION", "1")
	t.Setenv("COLLAB_JWT_SECRET", strings.Repeat("a", 32))
	t.Setenv("COLLAB_DATABASE_URL", "postgres://collab:collab@localhost:5432/collab")
	t.Setenv("COLLAB_OAUTH_REDIRECT_BASE_URL", "https://example.com")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("expected production load to succeed, got %v", err)
	}
	if !cfg.Production {
		t.Errorf("expected Production=true")
	}
	if len(cfg.JWTSecret) != 32 {
		t.Errorf("expected JWTSecret len=32, got %d", len(cfg.JWTSecret))
	}
}

func TestLoad_WSBufferFloor(t *testing.T) {
	t.Setenv("COLLAB_WS_READ_BUFFER_BYTES", "512")
	t.Setenv("COLLAB_PRODUCTION", "")

	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "WS buffer sizes") {
		t.Fatalf("expected WS buffer rejection, got %v", err)
	}
}
