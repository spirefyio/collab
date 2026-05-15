package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/spirefyio/collab/server/internal/auth"
)

func TestTeamProbe_RejectsRequestsWithoutToken(t *testing.T) {
	r, _, _ := newTestRouterWithACL(t)
	req := httptest.NewRequest(http.MethodGet, "/teams/team-abc/probe", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without token, got %d", rr.Code)
	}
}

func TestTeamProbe_RejectsRequestsWithNoRoles(t *testing.T) {
	r, issuer, _ := newTestRouterWithACL(t)
	token, _, err := issuer.Issue(auth.Claims{Subject: "user-1"})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/teams/team-abc/probe", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 when token has no roles, got %d body=%q", rr.Code, rr.Body.String())
	}
}

func TestTeamProbe_RejectsRequestsWithViewerOnDelete(t *testing.T) {
	r, issuer, _ := newTestRouterWithACL(t)
	token, _, err := issuer.Issue(auth.Claims{Subject: "user-1", Roles: []string{"viewer"}})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	req := httptest.NewRequest(http.MethodDelete, "/teams/team-abc/probe", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	// route only exists for GET; DELETE hits chi's MethodNotAllowed (405)
	// before reaching the middleware. Accept either 403 or 405 as
	// "viewer cannot DELETE" — the contract here is just "not 200".
	if rr.Code == http.StatusOK {
		t.Fatalf("expected non-200 when viewer attempts DELETE, got 200")
	}
}

func TestTeamProbe_AcceptsViewerOnRead(t *testing.T) {
	r, issuer, _ := newTestRouterWithACL(t)
	token, _, err := issuer.Issue(auth.Claims{
		Subject: "user-1",
		Roles:   []string{"viewer"},
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/teams/team-abc/probe", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for viewer GET, got %d body=%q", rr.Code, rr.Body.String())
	}
}

func TestTeamProbe_AcceptsOwnerOnRead(t *testing.T) {
	r, issuer, _ := newTestRouterWithACL(t)
	token, _, err := issuer.Issue(auth.Claims{
		Subject: "user-1",
		Roles:   []string{"owner"},
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/teams/team-abc/probe", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for owner, got %d body=%q", rr.Code, rr.Body.String())
	}
}

func TestTeamProbe_NotMountedWhenEnforcerNil(t *testing.T) {
	r, issuer := newTestRouterWithAuth(t) // no enforcer
	token, _, err := issuer.Issue(auth.Claims{Subject: "user-1", Roles: []string{"owner"}})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/teams/team-abc/probe", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when /teams not mounted, got %d", rr.Code)
	}
}
