-- schema.sql
-- Fundi: Verifiable safety infrastructure for informal-economy manufacturing
-- Postgres 15+. All monetary/scoring values are integers (no floats), per standing convention.
-- This is the consolidated, final schema — the earlier incremental ALTER statements
-- are folded in here rather than kept as a migration history, since no production
-- data exists yet to migrate around.

CREATE EXTENSION IF NOT EXISTS "pgcrypto"; -- for gen_random_uuid()

-- ============================================================
-- USERS
-- ============================================================
CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email           TEXT NOT NULL UNIQUE,
    password_hash   TEXT NOT NULL,          -- argon2, never plaintext
    display_name    TEXT NOT NULL,
    role            TEXT NOT NULL DEFAULT 'owner'
                        CHECK (role IN ('owner', 'regulator', 'admin')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ============================================================
-- SITES
-- ============================================================
CREATE TABLE sites (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id        UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    name            TEXT NOT NULL,
    location_label  TEXT,
    archived_at     TIMESTAMPTZ,            -- soft-delete/retire, gap flagged earlier, now closed
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_sites_owner_id ON sites(owner_id);
CREATE INDEX idx_sites_active ON sites(owner_id) WHERE archived_at IS NULL;

-- Design note: ON DELETE RESTRICT — a site with historical incident/attestation
-- data must never be silently destroyed by deleting its owner. archived_at gives
-- owners a real way to retire a site without that RESTRICT becoming a dead end.

-- ============================================================
-- WORKERS
-- ============================================================
CREATE TABLE workers (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    display_name    TEXT NOT NULL,
    wallet_address  TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT wallet_address_format
        CHECK (wallet_address IS NULL OR wallet_address ~* '^0x[0-9a-f]{40}$')
);

CREATE UNIQUE INDEX idx_workers_wallet_address
    ON workers(wallet_address) WHERE wallet_address IS NOT NULL;

-- Invariant: worker is deliberately not a `users` row — the credential belongs
-- to the worker, not the employer login, which is the product's core thesis.

-- ============================================================
-- INCIDENTS
-- ============================================================
CREATE TABLE incidents (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    site_id                 UUID NOT NULL REFERENCES sites(id) ON DELETE RESTRICT,
    worker_id               UUID REFERENCES workers(id) ON DELETE SET NULL,
    rule_triggered          TEXT NOT NULL
                                CHECK (rule_triggered IN ('ppe_missing', 'zone_breach')),
    confidence_bp           INT NOT NULL
                                CHECK (confidence_bp >= 0 AND confidence_bp <= 10000),
    frame_ref               TEXT,            -- storage path/hash; raw video never stored here
    detected_at             TIMESTAMPTZ NOT NULL,
    attestation_status      TEXT NOT NULL DEFAULT 'pending'
                                CHECK (attestation_status IN ('pending', 'minted', 'failed', 'disputed')),
    attestation_tx_hash     TEXT,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT tx_hash_present_iff_minted_or_disputed CHECK (
        (attestation_status IN ('minted', 'disputed') AND attestation_tx_hash IS NOT NULL)
        OR (attestation_status IN ('pending', 'failed') AND attestation_tx_hash IS NULL)
    )
);

CREATE INDEX idx_incidents_site_id ON incidents(site_id);
CREATE INDEX idx_incidents_worker_id ON incidents(worker_id) WHERE worker_id IS NOT NULL;
CREATE INDEX idx_incidents_detected_at ON incidents(detected_at);
CREATE INDEX idx_incidents_pending_attestation
    ON incidents(attestation_status) WHERE attestation_status = 'pending';

-- Invariant: tx_hash is present iff status is minted OR disputed — a dispute
-- overlays a minted fact, it never erases the on-chain record's existence.
-- Partial index on 'pending' exists because the minter worker polls exactly
-- this subset in a loop; without it this becomes a full table scan at scale.

-- ============================================================
-- TRAINING EVENTS
-- ============================================================
CREATE TABLE training_events (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    worker_id           UUID NOT NULL REFERENCES workers(id) ON DELETE CASCADE,
    module              TEXT NOT NULL,
    completed_at        TIMESTAMPTZ,
    attestation_status  TEXT NOT NULL DEFAULT 'pending'
                            CHECK (attestation_status IN ('pending', 'minted', 'failed', 'disputed')),
    attestation_tx_hash TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT training_tx_hash_present_iff_minted_or_disputed CHECK (
        (attestation_status IN ('minted', 'disputed') AND attestation_tx_hash IS NOT NULL)
        OR (attestation_status IN ('pending', 'failed') AND attestation_tx_hash IS NULL)
    )
);

CREATE INDEX idx_training_events_worker_id ON training_events(worker_id);

-- Design note: ON DELETE CASCADE (unlike incidents) — a training_event has no
-- independent evidentiary value once its worker is gone, unlike a site-level
-- safety incident, which matters even without worker attribution. Deliberate asymmetry.

-- ============================================================
-- DISPUTES (off-chain overlay on an immutable on-chain fact)
-- ============================================================
CREATE TABLE disputes (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id         UUID REFERENCES incidents(id) ON DELETE RESTRICT,
    training_event_id   UUID REFERENCES training_events(id) ON DELETE RESTRICT,
    raised_by_user_id   UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    reason              TEXT NOT NULL CHECK (char_length(reason) > 0),
    status              TEXT NOT NULL DEFAULT 'open'
                            CHECK (status IN ('open', 'upheld', 'rejected')),
    resolution_note     TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at         TIMESTAMPTZ,

    CONSTRAINT exactly_one_target CHECK (
        (incident_id IS NOT NULL AND training_event_id IS NULL)
        OR (incident_id IS NULL AND training_event_id IS NOT NULL)
    ),
    CONSTRAINT resolved_at_iff_not_open CHECK (
        (status = 'open' AND resolved_at IS NULL)
        OR (status != 'open' AND resolved_at IS NOT NULL)
    ),
    CONSTRAINT resolution_note_required_when_resolved CHECK (
        (status = 'open')
        OR (status != 'open' AND resolution_note IS NOT NULL AND char_length(resolution_note) > 0)
    )
);

CREATE INDEX idx_disputes_incident_id ON disputes(incident_id) WHERE incident_id IS NOT NULL;
CREATE INDEX idx_disputes_training_event_id ON disputes(training_event_id) WHERE training_event_id IS NOT NULL;
CREATE INDEX idx_disputes_open_status ON disputes(status) WHERE status = 'open';

-- ============================================================
-- TRIGGER: opening a dispute flips the parent's attestation_status to 'disputed'
-- ============================================================
CREATE OR REPLACE FUNCTION fn_flag_disputed()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.incident_id IS NOT NULL THEN
        UPDATE incidents
        SET attestation_status = 'disputed'
        WHERE id = NEW.incident_id
          AND attestation_status = 'minted';
    ELSIF NEW.training_event_id IS NOT NULL THEN
        UPDATE training_events
        SET attestation_status = 'disputed'
        WHERE id = NEW.training_event_id
          AND attestation_status = 'minted';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_flag_disputed
    AFTER INSERT ON disputes
    FOR EACH ROW
    WHEN (NEW.status = 'open')
    EXECUTE FUNCTION fn_flag_disputed();

-- Note: no reverse trigger (disputed -> minted on resolution) — deliberate.
-- Resolving a dispute is a human judgment call requiring an explicit application-
-- layer transition with its own audit trail, not a silent auto-revert.

-- ============================================================
-- RISK SCORES (insurer-facing data product — computed aggregate, not raw)
-- ============================================================
CREATE TABLE risk_scores (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    site_id                 UUID NOT NULL REFERENCES sites(id) ON DELETE RESTRICT,
    period_start            DATE NOT NULL,
    period_end              DATE NOT NULL,
    incident_count          INT NOT NULL CHECK (incident_count >= 0),
    severity_weighted_score INT NOT NULL CHECK (severity_weighted_score >= 0),
    computed_at             TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT period_is_valid_range CHECK (period_end >= period_start)
);

CREATE UNIQUE INDEX idx_risk_scores_site_period
    ON risk_scores(site_id, period_start, period_end);

-- Invariant: one score row per (site, period) — prevents a retried scoring job
-- from double-inserting and corrupting the insurer-facing feed. This table has
-- no raw incident detail, keeping the SME-operational vs insurer-commercial
-- data boundary enforced at the schema level, not just by convention.
-- migrations/0001_init_users_sites_workers.sql
-- Foundational tables with no dependencies on anything created later.

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email           TEXT NOT NULL UNIQUE,
    password_hash   TEXT NOT NULL,
    display_name    TEXT NOT NULL,
    role            TEXT NOT NULL DEFAULT 'owner'
                        CHECK (role IN ('owner', 'regulator', 'admin')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE sites (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id        UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    name            TEXT NOT NULL,
    location_label  TEXT,
    archived_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_sites_owner_id ON sites(owner_id);
CREATE INDEX idx_sites_active ON sites(owner_id) WHERE archived_at IS NULL;

CREATE TABLE workers (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    display_name    TEXT NOT NULL,
    wallet_address  TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT wallet_address_format
        CHECK (wallet_address IS NULL OR wallet_address ~* '^0x[0-9a-f]{40}$')
);

CREATE UNIQUE INDEX idx_workers_wallet_address
    ON workers(wallet_address) WHERE wallet_address IS NOT NULL;
    -- migrations/0003_training_events.sql
-- Depends on workers from 0001. Same pre-dispute attestation_status shape
-- as 0002's incidents table, for the same reason.

CREATE TABLE training_events (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    worker_id           UUID NOT NULL REFERENCES workers(id) ON DELETE CASCADE,
    module              TEXT NOT NULL,
    completed_at        TIMESTAMPTZ,
    attestation_status  TEXT NOT NULL DEFAULT 'pending'
                            CHECK (attestation_status IN ('pending', 'minted', 'failed')),
    attestation_tx_hash TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT training_tx_hash_present_iff_minted CHECK (
        (attestation_status = 'minted' AND attestation_tx_hash IS NOT NULL)
        OR (attestation_status != 'minted' AND attestation_tx_hash IS NULL)
    )
);

CREATE INDEX idx_training_events_worker_id ON training_events(worker_id);
-- migrations/0004_disputes.sql
-- Adds the 'disputed' status to both existing tables' CHECK constraints,
-- adds the disputes table itself, and the trigger that flips a parent row
-- to 'disputed' when an open dispute is raised against it.
--
-- Postgres requires dropping and recreating a CHECK constraint to change
-- its condition — there is no ALTER CONSTRAINT for this. Each ALTER TABLE
-- pair below is a genuine schema change, not a no-op formality, and is
-- safe to run against a table that may already have rows (none of the
-- existing rows can have attestation_status = 'disputed' yet, so no
-- existing data is invalidated by loosening the constraint).

ALTER TABLE incidents
    DROP CONSTRAINT tx_hash_present_iff_minted;
ALTER TABLE incidents
    DROP CONSTRAINT incidents_attestation_status_check;
ALTER TABLE incidents
    ADD CONSTRAINT incidents_attestation_status_check
        CHECK (attestation_status IN ('pending', 'minted', 'failed', 'disputed'));
ALTER TABLE incidents
    ADD CONSTRAINT tx_hash_present_iff_minted_or_disputed CHECK (
        (attestation_status IN ('minted', 'disputed') AND attestation_tx_hash IS NOT NULL)
        OR (attestation_status IN ('pending', 'failed') AND attestation_tx_hash IS NULL)
    );

ALTER TABLE training_events
    DROP CONSTRAINT training_tx_hash_present_iff_minted;
ALTER TABLE training_events
    DROP CONSTRAINT training_events_attestation_status_check;
ALTER TABLE training_events
    ADD CONSTRAINT training_events_attestation_status_check
        CHECK (attestation_status IN ('pending', 'minted', 'failed', 'disputed'));
ALTER TABLE training_events
    ADD CONSTRAINT training_tx_hash_present_iff_minted_or_disputed CHECK (
        (attestation_status IN ('minted', 'disputed') AND attestation_tx_hash IS NOT NULL)
        OR (attestation_status IN ('pending', 'failed') AND attestation_tx_hash IS NULL)
    );

CREATE TABLE disputes (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id         UUID REFERENCES incidents(id) ON DELETE RESTRICT,
    training_event_id   UUID REFERENCES training_events(id) ON DELETE RESTRICT,
    raised_by_user_id   UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    reason              TEXT NOT NULL CHECK (char_length(reason) > 0),
    status              TEXT NOT NULL DEFAULT 'open'
                            CHECK (status IN ('open', 'upheld', 'rejected')),
    resolution_note     TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at         TIMESTAMPTZ,

    CONSTRAINT exactly_one_target CHECK (
        (incident_id IS NOT NULL AND training_event_id IS NULL)
        OR (incident_id IS NULL AND training_event_id IS NOT NULL)
    ),
    CONSTRAINT resolved_at_iff_not_open CHECK (
        (status = 'open' AND resolved_at IS NULL)
        OR (status != 'open' AND resolved_at IS NOT NULL)
    ),
    CONSTRAINT resolution_note_required_when_resolved CHECK (
        (status = 'open')
        OR (status != 'open' AND resolution_note IS NOT NULL AND char_length(resolution_note) > 0)
    )
);

CREATE INDEX idx_disputes_incident_id ON disputes(incident_id) WHERE incident_id IS NOT NULL;
CREATE INDEX idx_disputes_training_event_id ON disputes(training_event_id) WHERE training_event_id IS NOT NULL;
CREATE INDEX idx_disputes_open_status ON disputes(status) WHERE status = 'open';

CREATE OR REPLACE FUNCTION fn_flag_disputed()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.incident_id IS NOT NULL THEN
        UPDATE incidents
        SET attestation_status = 'disputed'
        WHERE id = NEW.incident_id
          AND attestation_status = 'minted';
    ELSIF NEW.training_event_id IS NOT NULL THEN
        UPDATE training_events
        SET attestation_status = 'disputed'
        WHERE id = NEW.training_event_id
          AND attestation_status = 'minted';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_flag_disputed
    AFTER INSERT ON disputes
    FOR EACH ROW
    WHEN (NEW.status = 'open')
    EXECUTE FUNCTION fn_flag_disputed();
    -- migrations/0005_risk_scores.sql
-- The insurer-facing aggregate table. Independent of the dispute machinery
-- added in 0004 — deliberately ordered last since it's the read-side data
-- product, not part of the core incident/attestation lifecycle.

CREATE TABLE risk_scores (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    site_id                 UUID NOT NULL REFERENCES sites(id) ON DELETE RESTRICT,
    period_start            DATE NOT NULL,
    period_end              DATE NOT NULL,
    incident_count          INT NOT NULL CHECK (incident_count >= 0),
    severity_weighted_score INT NOT NULL CHECK (severity_weighted_score >= 0),
    computed_at             TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT period_is_valid_range CHECK (period_end >= period_start)
);

CREATE UNIQUE INDEX idx_risk_scores_site_period
    ON risk_scores(site_id, period_start, period_end);