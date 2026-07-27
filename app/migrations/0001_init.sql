-- migrations/0001_init.sql
-- Fundi: Verifiable safety infrastructure for informal-economy manufacturing
-- Postgres 15+. All monetary/scoring values are integers (no floats), per standing convention.
-- Consolidated initial schema, mirroring schema.sql at the repository root.

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
    archived_at     TIMESTAMPTZ,            -- soft-delete/retire
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_sites_owner_id ON sites(owner_id);
CREATE INDEX idx_sites_active ON sites(owner_id) WHERE archived_at IS NULL;

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
