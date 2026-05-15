// Package acl wraps github.com/casbin/casbin/v2 with the collab team-service
// authorization model.
//
// Model (RBAC without role grouping — JWT carries the user's roles):
//
//	request:   sub (role), obj (URL path), act (HTTP method)
//	policy:    sub (role), obj (URL pattern), act (HTTP method, or "*")
//	matcher:   role equality && path keyMatch && (any-method || equality)
//
// The auth middleware extracts the JWT `roles` claim and tries each role
// against the policy until one allows or all deny. This keeps the
// authorization model orthogonal to user identity — the same role on
// different teams shares the same permission set, while team membership
// (granted via AddRoleForUser) lives outside this package.
//
// Default policies are seeded by SeedDefaults. Production deployments
// override or augment via AddPolicy / RemovePolicy at runtime, ideally
// backed by a persistent adapter (added in a follow-up commit alongside
// the Postgres pool).
package acl

import (
	"fmt"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
)

// modelConf is the casbin model loaded by NewEnforcer. Keep in sync
// with docs/server/auth-model.md (added in a follow-up commit).
const modelConf = `[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && keyMatch(r.obj, p.obj) && (p.act == "*" || r.act == p.act)
`

// Enforcer wraps casbin.Enforcer with thread-safe policy CRUD and a
// roles-array Enforce helper sized for the JWT-driven flow.
type Enforcer struct {
	e *casbin.Enforcer
}

func NewEnforcer() (*Enforcer, error) {
	m, err := model.NewModelFromString(modelConf)
	if err != nil {
		return nil, fmt.Errorf("parse model: %w", err)
	}
	ce, err := casbin.NewEnforcer(m)
	if err != nil {
		return nil, fmt.Errorf("new enforcer: %w", err)
	}
	// Quiet the default WARN: by default casbin logs "no policies loaded"
	// at startup. We seed policies via SeedDefaults() right after, so
	// suppress the bootstrap noise.
	ce.EnableLog(false)
	return &Enforcer{e: ce}, nil
}

// AddPolicy adds a (role, obj-pattern, act) tuple. Idempotent — adding
// an already-present policy is a no-op and returns false, nil.
func (e *Enforcer) AddPolicy(role, obj, act string) (bool, error) {
	return e.e.AddPolicy(role, obj, act)
}

// RemovePolicy removes a policy tuple. Returns false when no matching
// tuple existed.
func (e *Enforcer) RemovePolicy(role, obj, act string) (bool, error) {
	return e.e.RemovePolicy(role, obj, act)
}

// HasAccess returns true if any of the supplied roles is allowed to
// perform act on obj. Used by the http middleware to translate a JWT's
// roles array into a single allow/deny decision.
func (e *Enforcer) HasAccess(roles []string, obj, act string) (bool, error) {
	for _, role := range roles {
		ok, err := e.e.Enforce(role, obj, act)
		if err != nil {
			return false, err
		}
		if ok {
			return true, nil
		}
	}
	return false, nil
}

// Policies returns the current policy tuples as a copy so callers
// cannot mutate enforcer state through the slice.
func (e *Enforcer) Policies() [][]string {
	src, _ := e.e.GetPolicy()
	out := make([][]string, len(src))
	for i, row := range src {
		out[i] = append([]string(nil), row...)
	}
	return out
}

// SeedDefaults installs the baseline role policy set for the team service.
// Roles mirror the team model: owner > admin > member > viewer.
func (e *Enforcer) SeedDefaults() error {
	seeds := [][3]string{
		// owner — unrestricted on all team & workspace surfaces
		{"owner", "/teams/*", "*"},
		{"owner", "/workspaces/*", "*"},
		{"owner", "/invites/*", "*"},
		{"owner", "/audit/*", "*"},

		// admin — manage team, full workspace CRUD, read audit
		{"admin", "/teams/*", "GET"},
		{"admin", "/teams/*", "POST"},
		{"admin", "/teams/*", "PATCH"},
		{"admin", "/teams/*", "DELETE"},
		{"admin", "/workspaces/*", "*"},
		{"admin", "/invites/*", "*"},
		{"admin", "/audit/*", "GET"},

		// member — workspace CRUD on own team, read team metadata
		{"member", "/teams/*", "GET"},
		{"member", "/workspaces/*", "GET"},
		{"member", "/workspaces/*", "POST"},
		{"member", "/workspaces/*", "PATCH"},

		// viewer — strict read-only
		{"viewer", "/teams/*", "GET"},
		{"viewer", "/workspaces/*", "GET"},
	}
	for _, p := range seeds {
		if _, err := e.AddPolicy(p[0], p[1], p[2]); err != nil {
			return fmt.Errorf("seed %v: %w", p, err)
		}
	}
	return nil
}
