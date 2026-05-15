-- 0001_init.up.sql — collab team service schema (v1).
--
-- The model mirrors the team feature plan in
-- docs/architecture/collab-channels.md (studio) + the team-feature
-- plan tracked alongside this repo. Tables:
--
--   accounts        — persistent OAuth identities
--   teams           — top-level workspace owners
--   team_members    — many-to-many account↔team with a role
--   workspaces      — Spirefy models persisted in cloud storage
--   invites         — signed tokens that admit a recipient to a team
--   audit_log       — append-only event stream per team
--
-- All FK actions chosen to keep audit trails sane on user deletion:
--   accounts can't be deleted while they own a team (RESTRICT)
--   deleting a team cascades to members, workspaces, invites, audit
--   deleting an account nulls audit.account_id (retain action history)

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE accounts (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email           TEXT UNIQUE NOT NULL,
    oauth_provider  TEXT NOT NULL CHECK (oauth_provider IN ('google', 'github')),
    oauth_subject   TEXT NOT NULL,
    public_key      BYTEA NOT NULL,
    display_name    TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (oauth_provider, oauth_subject)
);

CREATE TABLE teams (
    id                      UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name                    TEXT NOT NULL,
    owner_account_id        UUID NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
    crypto_suite_required   TEXT NOT NULL DEFAULT 'aes-gcm-v1',
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TYPE team_role AS ENUM ('owner', 'admin', 'member', 'viewer');

CREATE TABLE team_members (
    team_id     UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    account_id  UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    role        team_role NOT NULL,
    joined_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (team_id, account_id)
);

CREATE INDEX idx_team_members_account ON team_members(account_id);

CREATE TABLE workspaces (
    id                      UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    team_id                 UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    name                    TEXT NOT NULL,
    snapshot_storage_url    TEXT,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_workspaces_team ON workspaces(team_id);

CREATE TABLE invites (
    id                      UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    team_id                 UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    issued_by_account_id    UUID NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
    target_email            TEXT NOT NULL,
    role                    team_role NOT NULL,
    token                   TEXT UNIQUE NOT NULL,
    expires_at              TIMESTAMPTZ NOT NULL,
    accepted_at             TIMESTAMPTZ,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_invites_target_email ON invites(target_email);
CREATE INDEX idx_invites_team ON invites(team_id);

CREATE TABLE audit_log (
    id              BIGSERIAL PRIMARY KEY,
    team_id         UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    workspace_id    UUID REFERENCES workspaces(id) ON DELETE SET NULL,
    account_id      UUID REFERENCES accounts(id) ON DELETE SET NULL,
    action          TEXT NOT NULL,
    metadata        JSONB,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_audit_log_team_time ON audit_log(team_id, created_at DESC);
