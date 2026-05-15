// Package auth wraps github.com/go-chi/jwtauth/v5 with a thin Issuer
// type that constructs and verifies HS256 JWTs for the collab service.
//
// Token shape:
//
//	{
//	  "iss":   "spirefyio/collab",
//	  "aud":   "spirefy-collab-clients",
//	  "sub":   "<account-uuid>",
//	  "iat":   <unix-seconds>,
//	  "exp":   <unix-seconds>,
//	  "jti":   "<random-uuid>",
//	  "email": "...",         // optional
//	  "name":  "...",          // optional
//	  "roles": ["...", ...]   // optional
//	}
//
// Validation order on the receive path (in jwtauth.Authenticator):
//  1. signature against shared secret (HS256)
//  2. exp (expiry, mandatory)
//  3. nbf (not-before, optional)
//
// iss + aud are not enforced by jwtauth; the Verify method here performs
// the extra check so a token signed for a different audience is refused.
package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/go-chi/jwtauth/v5"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

const (
	minSecretBytes = 32
)

// Issuer mints and validates HS256 JWTs.
type Issuer struct {
	tokenAuth *jwtauth.JWTAuth
	issuer    string
	audience  string
	ttl       time.Duration
}

// NewIssuer constructs an Issuer.
//
//	secret    — HMAC-SHA256 key, >= 32 bytes
//	issuer    — value placed in the iss claim
//	audience  — value placed in the aud claim
//	ttl       — token lifetime; the exp claim is iat + ttl
func NewIssuer(secret []byte, issuer, audience string, ttl time.Duration) (*Issuer, error) {
	if len(secret) < minSecretBytes {
		return nil, fmt.Errorf("jwt secret must be >= %d bytes (got %d)", minSecretBytes, len(secret))
	}
	if issuer == "" {
		return nil, errors.New("jwt issuer must be non-empty")
	}
	if audience == "" {
		return nil, errors.New("jwt audience must be non-empty")
	}
	if ttl <= 0 {
		return nil, errors.New("jwt ttl must be positive")
	}
	return &Issuer{
		tokenAuth: jwtauth.New("HS256", secret, nil),
		issuer:    issuer,
		audience:  audience,
		ttl:       ttl,
	}, nil
}

// TokenAuth returns the underlying jwtauth handle for chaining
// jwtauth.Verifier + jwtauth.Authenticator middleware.
func (i *Issuer) TokenAuth() *jwtauth.JWTAuth { return i.tokenAuth }

// Audience returns the configured audience claim value.
func (i *Issuer) Audience() string { return i.audience }

// Issuer returns the configured iss claim value.
func (i *Issuer) Issuer() string { return i.issuer }

// Claims is the application-level projection of the JWT payload.
type Claims struct {
	Subject string
	Email   string
	Name    string
	Roles   []string

	IssuedAt  time.Time
	ExpiresAt time.Time
	TokenID   string
}

// Issue mints a signed token for the given claims. Subject is required;
// other fields are optional. iat/exp/jti are filled in automatically.
func (i *Issuer) Issue(c Claims) (string, time.Time, error) {
	if c.Subject == "" {
		return "", time.Time{}, errors.New("subject is required")
	}
	now := time.Now().UTC()
	exp := now.Add(i.ttl)
	jti, err := randomHex(16)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("generate jti: %w", err)
	}
	payload := map[string]interface{}{
		"iss": i.issuer,
		"aud": i.audience,
		"sub": c.Subject,
		"iat": now.Unix(),
		"exp": exp.Unix(),
		"jti": jti,
	}
	if c.Email != "" {
		payload["email"] = c.Email
	}
	if c.Name != "" {
		payload["name"] = c.Name
	}
	if len(c.Roles) > 0 {
		payload["roles"] = c.Roles
	}
	_, tokenString, err := i.tokenAuth.Encode(payload)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("encode jwt: %w", err)
	}
	return tokenString, exp, nil
}

// Verify decodes + signature-checks + claim-checks a token.
//
// Use this for off-router code paths (e.g. WebSocket upgrade where a
// token comes via query param). Router-mounted code should use
// jwtauth.Verifier + jwtauth.Authenticator middleware instead.
func (i *Issuer) Verify(tokenString string) (*Claims, error) {
	tok, err := i.tokenAuth.Decode(tokenString)
	if err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	if tok == nil {
		return nil, errors.New("nil token")
	}
	if exp, ok := tok.Expiration(); ok && !exp.IsZero() && time.Now().After(exp) {
		return nil, errors.New("token expired")
	}
	iss, ok := tok.Issuer()
	if !ok || iss != i.issuer {
		return nil, fmt.Errorf("issuer mismatch: want %q, got %q", i.issuer, iss)
	}
	aud, ok := tok.Audience()
	if !ok || len(aud) != 1 || aud[0] != i.audience {
		return nil, fmt.Errorf("audience mismatch: want [%q], got %v", i.audience, aud)
	}
	return claimsFromToken(tok), nil
}

// ClaimsFromContext extracts validated claims set by jwtauth.Authenticator.
func ClaimsFromContext(ctx context.Context) (*Claims, error) {
	tok, _, err := jwtauth.FromContext(ctx)
	if err != nil {
		return nil, err
	}
	if tok == nil {
		return nil, errors.New("no token in context")
	}
	return claimsFromToken(tok), nil
}

func claimsFromToken(tok jwt.Token) *Claims {
	c := &Claims{}
	if v, ok := tok.Subject(); ok {
		c.Subject = v
	}
	if v, ok := tok.IssuedAt(); ok {
		c.IssuedAt = v
	}
	if v, ok := tok.Expiration(); ok {
		c.ExpiresAt = v
	}
	if v, ok := tok.JwtID(); ok {
		c.TokenID = v
	}
	var email string
	if err := tok.Get("email", &email); err == nil {
		c.Email = email
	}
	var name string
	if err := tok.Get("name", &name); err == nil {
		c.Name = name
	}
	// jwx v3 deserializes JSON arrays as []any, so a direct Get into
	// []string fails the type-assertion. Convert manually.
	var rolesAny []any
	if err := tok.Get("roles", &rolesAny); err == nil {
		for _, r := range rolesAny {
			if s, ok := r.(string); ok {
				c.Roles = append(c.Roles, s)
			}
		}
	}
	return c
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
