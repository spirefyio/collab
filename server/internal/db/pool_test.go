package db

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestNewPool_RejectsEmptyURL(t *testing.T) {
	_, err := NewPool(context.Background(), "")
	if err == nil || !strings.Contains(err.Error(), "database url") {
		t.Fatalf("expected empty-url rejection, got %v", err)
	}
}

func TestNewPool_RejectsMalformedURL(t *testing.T) {
	_, err := NewPool(context.Background(), "::not-a-url::")
	if err == nil {
		t.Fatal("expected malformed-url rejection")
	}
}

func TestNewPool_FailsFastOnUnreachableHost(t *testing.T) {
	// Reserved-for-documentation TEST-NET-1 (RFC 5737) — guaranteed not routed.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := NewPool(ctx, "postgres://user:pass@192.0.2.1:5432/db?sslmode=disable&connect_timeout=1")
	if err == nil {
		t.Fatal("expected unreachable-host rejection")
	}
}
