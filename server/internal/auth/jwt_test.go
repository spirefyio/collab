package auth

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/jwtauth/v5"
)

func newTestIssuer(t *testing.T) *Issuer {
	t.Helper()
	secret := []byte(strings.Repeat("k", 32))
	iss, err := NewIssuer(secret, "spirefyio/collab", "spirefy-collab-clients", time.Hour)
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	return iss
}

func TestNewIssuer_RejectsShortSecret(t *testing.T) {
	_, err := NewIssuer([]byte("short"), "iss", "aud", time.Hour)
	if err == nil || !strings.Contains(err.Error(), ">= 32 bytes") {
		t.Fatalf("expected short-secret rejection, got %v", err)
	}
}

func TestNewIssuer_RequiresIssuer(t *testing.T) {
	_, err := NewIssuer([]byte(strings.Repeat("k", 32)), "", "aud", time.Hour)
	if err == nil || !strings.Contains(err.Error(), "issuer") {
		t.Fatalf("expected missing-issuer rejection, got %v", err)
	}
}

func TestNewIssuer_RequiresAudience(t *testing.T) {
	_, err := NewIssuer([]byte(strings.Repeat("k", 32)), "iss", "", time.Hour)
	if err == nil || !strings.Contains(err.Error(), "audience") {
		t.Fatalf("expected missing-audience rejection, got %v", err)
	}
}

func TestNewIssuer_RequiresPositiveTTL(t *testing.T) {
	_, err := NewIssuer([]byte(strings.Repeat("k", 32)), "iss", "aud", 0)
	if err == nil || !strings.Contains(err.Error(), "ttl") {
		t.Fatalf("expected zero-ttl rejection, got %v", err)
	}
}

func TestIssue_RequiresSubject(t *testing.T) {
	iss := newTestIssuer(t)
	_, _, err := iss.Issue(Claims{})
	if err == nil || !strings.Contains(err.Error(), "subject") {
		t.Fatalf("expected missing-subject rejection, got %v", err)
	}
}

func TestIssueVerify_RoundTrip(t *testing.T) {
	iss := newTestIssuer(t)
	now := time.Now().UTC()

	token, exp, err := iss.Issue(Claims{
		Subject: "acct-uuid-123",
		Email:   "kevin@spirefy.io",
		Name:    "Kevin Duffey",
		Roles:   []string{"owner", "admin"},
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if token == "" {
		t.Fatal("empty token")
	}
	if exp.Before(now.Add(50 * time.Minute)) {
		t.Errorf("exp too soon: %v", exp)
	}

	got, err := iss.Verify(token)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.Subject != "acct-uuid-123" {
		t.Errorf("subject: got %q", got.Subject)
	}
	if got.Email != "kevin@spirefy.io" {
		t.Errorf("email: got %q", got.Email)
	}
	if got.Name != "Kevin Duffey" {
		t.Errorf("name: got %q", got.Name)
	}
	if len(got.Roles) != 2 || got.Roles[0] != "owner" || got.Roles[1] != "admin" {
		t.Errorf("roles: got %v", got.Roles)
	}
	if got.TokenID == "" {
		t.Errorf("jti missing")
	}
}

func TestVerify_RejectsTamperedToken(t *testing.T) {
	iss := newTestIssuer(t)
	token, _, err := iss.Issue(Claims{Subject: "acct-1"})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	// Mutate the payload section of the JWT. A JWT is base64url(header).base64url(payload).base64url(sig).
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 parts, got %d", len(parts))
	}
	parts[1] = parts[1][:len(parts[1])-2] + "AA"
	tampered := strings.Join(parts, ".")

	if _, err := iss.Verify(tampered); err == nil {
		t.Fatal("expected tamper rejection, got nil")
	}
}

func TestVerify_RejectsWrongSecret(t *testing.T) {
	a := newTestIssuer(t)
	b, _ := NewIssuer([]byte(strings.Repeat("z", 32)), "spirefyio/collab", "spirefy-collab-clients", time.Hour)

	token, _, err := a.Issue(Claims{Subject: "acct-1"})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := b.Verify(token); err == nil {
		t.Fatal("expected wrong-secret rejection, got nil")
	}
}

func TestVerify_RejectsWrongAudience(t *testing.T) {
	a, _ := NewIssuer([]byte(strings.Repeat("k", 32)), "spirefyio/collab", "audience-A", time.Hour)
	b, _ := NewIssuer([]byte(strings.Repeat("k", 32)), "spirefyio/collab", "audience-B", time.Hour)

	token, _, err := a.Issue(Claims{Subject: "acct-1"})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := b.Verify(token); err == nil {
		t.Fatal("expected wrong-audience rejection, got nil")
	}
}

func TestVerify_RejectsWrongIssuer(t *testing.T) {
	a, _ := NewIssuer([]byte(strings.Repeat("k", 32)), "issuer-A", "spirefy-collab-clients", time.Hour)
	b, _ := NewIssuer([]byte(strings.Repeat("k", 32)), "issuer-B", "spirefy-collab-clients", time.Hour)

	token, _, err := a.Issue(Claims{Subject: "acct-1"})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := b.Verify(token); err == nil {
		t.Fatal("expected wrong-issuer rejection, got nil")
	}
}

func TestVerify_RejectsExpiredToken(t *testing.T) {
	iss, _ := NewIssuer([]byte(strings.Repeat("k", 32)), "spirefyio/collab", "spirefy-collab-clients", 1*time.Nanosecond)
	token, _, err := iss.Issue(Claims{Subject: "acct-1"})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	time.Sleep(5 * time.Millisecond)
	if _, err := iss.Verify(token); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected expired rejection, got %v", err)
	}
}

func TestVerify_DistinctJTI(t *testing.T) {
	iss := newTestIssuer(t)
	a, _, _ := iss.Issue(Claims{Subject: "acct-1"})
	b, _, _ := iss.Issue(Claims{Subject: "acct-1"})

	ca, err := iss.Verify(a)
	if err != nil {
		t.Fatalf("Verify a: %v", err)
	}
	cb, err := iss.Verify(b)
	if err != nil {
		t.Fatalf("Verify b: %v", err)
	}
	if ca.TokenID == "" || cb.TokenID == "" {
		t.Fatal("missing jti")
	}
	if ca.TokenID == cb.TokenID {
		t.Errorf("expected distinct jti, got %q == %q", ca.TokenID, cb.TokenID)
	}
}

func TestClaimsFromContext_RoundTripViaJwtauth(t *testing.T) {
	iss := newTestIssuer(t)
	token, _, err := iss.Issue(Claims{
		Subject: "acct-uuid-123",
		Email:   "x@y.test",
		Roles:   []string{"member"},
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	tok, err := iss.TokenAuth().Decode(token)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	ctx := jwtauth.NewContext(context.Background(), tok, nil)

	got, err := ClaimsFromContext(ctx)
	if err != nil {
		t.Fatalf("ClaimsFromContext: %v", err)
	}
	if got.Subject != "acct-uuid-123" {
		t.Errorf("subject: got %q", got.Subject)
	}
	if got.Email != "x@y.test" {
		t.Errorf("email: got %q", got.Email)
	}
	if len(got.Roles) != 1 || got.Roles[0] != "member" {
		t.Errorf("roles: got %v", got.Roles)
	}
}
