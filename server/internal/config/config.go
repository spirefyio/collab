// Package config loads server configuration from environment variables.
//
// Defaults are wired so a developer can `go run ./cmd/relay` without any
// env vars and get a bare relay listening on :8443 (no auth, no DB, no
// OAuth). Production deployments must set COLLAB_JWT_SECRET (32+ bytes)
// and COLLAB_DATABASE_URL before enabling auth or team features.
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"
)

// Version is the build-time service version. Overridden via -ldflags at
// release; defaults to the in-repo development tag.
var Version = "0.0.1-dev"

type Config struct {
	ListenAddr string

	DatabaseURL string

	JWTSecret  []byte
	JWTIssuer  string
	JWTAudience string
	JWTTTL     time.Duration

	OAuthGoogleClientID     string
	OAuthGoogleClientSecret string
	OAuthGitHubClientID     string
	OAuthGitHubClientSecret string
	OAuthRedirectBaseURL    string

	WSReadBufferBytes  int
	WSWriteBufferBytes int

	Production bool
}

func Load() (*Config, error) {
	cfg := &Config{
		ListenAddr:           getEnv("COLLAB_LISTEN_ADDR", ":8443"),
		DatabaseURL:          os.Getenv("COLLAB_DATABASE_URL"),
		JWTIssuer:            getEnv("COLLAB_JWT_ISSUER", "spirefyio/collab"),
		JWTAudience:          getEnv("COLLAB_JWT_AUDIENCE", "spirefy-collab-clients"),
		JWTTTL:               getDuration("COLLAB_JWT_TTL", 24*time.Hour),
		OAuthGoogleClientID:     os.Getenv("COLLAB_OAUTH_GOOGLE_CLIENT_ID"),
		OAuthGoogleClientSecret: os.Getenv("COLLAB_OAUTH_GOOGLE_CLIENT_SECRET"),
		OAuthGitHubClientID:     os.Getenv("COLLAB_OAUTH_GITHUB_CLIENT_ID"),
		OAuthGitHubClientSecret: os.Getenv("COLLAB_OAUTH_GITHUB_CLIENT_SECRET"),
		OAuthRedirectBaseURL:    os.Getenv("COLLAB_OAUTH_REDIRECT_BASE_URL"),
		WSReadBufferBytes:    getInt("COLLAB_WS_READ_BUFFER_BYTES", 4096),
		WSWriteBufferBytes:   getInt("COLLAB_WS_WRITE_BUFFER_BYTES", 4096),
		Production:           getBool("COLLAB_PRODUCTION", false),
	}

	if secret := os.Getenv("COLLAB_JWT_SECRET"); secret != "" {
		cfg.JWTSecret = []byte(secret)
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// validate enforces the constraints that apply to whichever feature
// surface is enabled. The skeleton allows zero-config boot for local
// dev; production must opt-in via COLLAB_PRODUCTION=1.
func (c *Config) validate() error {
	if c.Production {
		if len(c.JWTSecret) < 32 {
			return errors.New("COLLAB_JWT_SECRET must be >= 32 bytes when COLLAB_PRODUCTION=1")
		}
		if c.DatabaseURL == "" {
			return errors.New("COLLAB_DATABASE_URL is required when COLLAB_PRODUCTION=1")
		}
		if c.OAuthRedirectBaseURL == "" {
			return errors.New("COLLAB_OAUTH_REDIRECT_BASE_URL is required when COLLAB_PRODUCTION=1")
		}
	}
	if c.WSReadBufferBytes < 1024 || c.WSWriteBufferBytes < 1024 {
		return fmt.Errorf("WS buffer sizes must be >= 1024 (got read=%d write=%d)", c.WSReadBufferBytes, c.WSWriteBufferBytes)
	}
	return nil
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getInt(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}

func getBool(key string, fallback bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return fallback
	}
	return b
}

func getDuration(key string, fallback time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return fallback
	}
	return d
}
