package acl

import (
	"testing"
)

func newSeededEnforcer(t *testing.T) *Enforcer {
	t.Helper()
	e, err := NewEnforcer()
	if err != nil {
		t.Fatalf("NewEnforcer: %v", err)
	}
	if err := e.SeedDefaults(); err != nil {
		t.Fatalf("SeedDefaults: %v", err)
	}
	return e
}

func TestSeedDefaults_PoliciesPresent(t *testing.T) {
	e := newSeededEnforcer(t)
	policies := e.Policies()
	if len(policies) < 10 {
		t.Fatalf("expected at least 10 seeded policies, got %d", len(policies))
	}
}

func TestHasAccess_OwnerEverywhere(t *testing.T) {
	e := newSeededEnforcer(t)
	cases := []struct {
		obj, act string
	}{
		{"/teams/team-abc", "GET"},
		{"/teams/team-abc", "DELETE"},
		{"/workspaces/ws-1", "POST"},
		{"/workspaces/ws-1", "PATCH"},
		{"/invites/inv-1", "DELETE"},
	}
	for _, c := range cases {
		ok, err := e.HasAccess([]string{"owner"}, c.obj, c.act)
		if err != nil {
			t.Errorf("HasAccess(owner, %s, %s): err %v", c.obj, c.act, err)
			continue
		}
		if !ok {
			t.Errorf("HasAccess(owner, %s, %s): expected allow, got deny", c.obj, c.act)
		}
	}
}

func TestHasAccess_ViewerCannotMutate(t *testing.T) {
	e := newSeededEnforcer(t)
	cases := []struct {
		obj, act string
	}{
		{"/teams/team-abc", "DELETE"},
		{"/workspaces/ws-1", "POST"},
		{"/workspaces/ws-1", "PATCH"},
		{"/workspaces/ws-1", "DELETE"},
		{"/invites/inv-1", "POST"},
	}
	for _, c := range cases {
		ok, err := e.HasAccess([]string{"viewer"}, c.obj, c.act)
		if err != nil {
			t.Errorf("HasAccess(viewer, %s, %s): err %v", c.obj, c.act, err)
			continue
		}
		if ok {
			t.Errorf("HasAccess(viewer, %s, %s): expected deny, got allow", c.obj, c.act)
		}
	}
}

func TestHasAccess_ViewerCanRead(t *testing.T) {
	e := newSeededEnforcer(t)
	for _, obj := range []string{"/teams/team-abc", "/workspaces/ws-1"} {
		ok, err := e.HasAccess([]string{"viewer"}, obj, "GET")
		if err != nil {
			t.Fatalf("HasAccess: %v", err)
		}
		if !ok {
			t.Errorf("viewer should be able to GET %s", obj)
		}
	}
}

func TestHasAccess_MemberWriteRead(t *testing.T) {
	e := newSeededEnforcer(t)
	cases := []struct {
		obj, act string
		want     bool
	}{
		{"/workspaces/ws-1", "GET", true},
		{"/workspaces/ws-1", "POST", true},
		{"/workspaces/ws-1", "PATCH", true},
		{"/workspaces/ws-1", "DELETE", false},
		{"/teams/team-abc", "GET", true},
		{"/teams/team-abc", "POST", false},
		{"/audit/team-abc", "GET", false},
	}
	for _, c := range cases {
		ok, err := e.HasAccess([]string{"member"}, c.obj, c.act)
		if err != nil {
			t.Errorf("HasAccess(member, %s, %s): err %v", c.obj, c.act, err)
			continue
		}
		if ok != c.want {
			t.Errorf("HasAccess(member, %s, %s): got %v want %v", c.obj, c.act, ok, c.want)
		}
	}
}

func TestHasAccess_MultipleRolesFirstWins(t *testing.T) {
	e := newSeededEnforcer(t)
	// viewer alone can't DELETE, owner can. Combined → allow.
	ok, err := e.HasAccess([]string{"viewer", "owner"}, "/workspaces/ws-1", "DELETE")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !ok {
		t.Fatal("expected allow when one role grants access")
	}
}

func TestHasAccess_EmptyRoles(t *testing.T) {
	e := newSeededEnforcer(t)
	ok, err := e.HasAccess(nil, "/workspaces/ws-1", "GET")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if ok {
		t.Error("expected deny for empty roles")
	}
}

func TestHasAccess_UnknownRole(t *testing.T) {
	e := newSeededEnforcer(t)
	ok, err := e.HasAccess([]string{"some-undefined-role"}, "/workspaces/ws-1", "GET")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if ok {
		t.Error("expected deny for undefined role")
	}
}

func TestAddPolicy_TakesEffect(t *testing.T) {
	e := newSeededEnforcer(t)
	if ok, _ := e.HasAccess([]string{"custom"}, "/custom-resource", "GET"); ok {
		t.Fatal("expected deny before policy added")
	}
	added, err := e.AddPolicy("custom", "/custom-resource", "GET")
	if err != nil {
		t.Fatalf("AddPolicy: %v", err)
	}
	if !added {
		t.Fatal("AddPolicy reported no-op for new tuple")
	}
	if ok, _ := e.HasAccess([]string{"custom"}, "/custom-resource", "GET"); !ok {
		t.Error("expected allow after AddPolicy")
	}
}

func TestRemovePolicy_TakesEffect(t *testing.T) {
	e := newSeededEnforcer(t)
	if ok, _ := e.HasAccess([]string{"viewer"}, "/teams/x", "GET"); !ok {
		t.Fatal("precondition: viewer should be able to GET /teams/x")
	}
	removed, err := e.RemovePolicy("viewer", "/teams/*", "GET")
	if err != nil {
		t.Fatalf("RemovePolicy: %v", err)
	}
	if !removed {
		t.Fatal("RemovePolicy reported no-op")
	}
	if ok, _ := e.HasAccess([]string{"viewer"}, "/teams/x", "GET"); ok {
		t.Error("expected deny after RemovePolicy")
	}
}

func TestAddPolicy_Idempotent(t *testing.T) {
	e, err := NewEnforcer()
	if err != nil {
		t.Fatalf("NewEnforcer: %v", err)
	}
	a, _ := e.AddPolicy("r", "/o", "GET")
	b, _ := e.AddPolicy("r", "/o", "GET")
	if !a {
		t.Error("first AddPolicy should report added=true")
	}
	if b {
		t.Error("second AddPolicy should report added=false (idempotent)")
	}
}
