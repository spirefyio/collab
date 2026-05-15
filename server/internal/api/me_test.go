package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/spirefyio/collab/server/internal/auth"
)

func TestMe_RejectsRequestsWithoutToken(t *testing.T) {
	r, _ := newTestRouterWithAuth(t)
	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without token, got %d", rr.Code)
	}
}

func TestMe_RejectsTokenWithBadSecret(t *testing.T) {
	r, _ := newTestRouterWithAuth(t)

	// Forge a token with the WRONG secret — server-side jwtauth must reject.
	other, err := auth.NewIssuer([]byte(strings.Repeat("z", 32)), "spirefyio/collab", "spirefy-collab-clients", time.Hour)
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	forged, _, err := other.Issue(auth.Claims{Subject: "attacker"})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req.Header.Set("Authorization", "Bearer "+forged)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 with wrong-secret token, got %d", rr.Code)
	}
}

func TestMe_AcceptsValidToken(t *testing.T) {
	r, issuer := newTestRouterWithAuth(t)

	token, _, err := issuer.Issue(auth.Claims{
		Subject: "acct-abc-123",
		Email:   "kevin@spirefy.io",
		Name:    "Kevin Duffey",
		Roles:   []string{"owner"},
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 with valid token, got %d body=%q", rr.Code, rr.Body.String())
	}
	var body meResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Subject != "acct-abc-123" {
		t.Errorf("sub: got %q", body.Subject)
	}
	if body.Email != "kevin@spirefy.io" {
		t.Errorf("email: got %q", body.Email)
	}
	if body.Name != "Kevin Duffey" {
		t.Errorf("name: got %q", body.Name)
	}
	if len(body.Roles) != 1 || body.Roles[0] != "owner" {
		t.Errorf("roles: got %v", body.Roles)
	}
}

func TestMe_NotMountedWhenIssuerNil(t *testing.T) {
	r := newTestRouter(t) // no issuer
	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when /me is not mounted, got %d", rr.Code)
	}
}
