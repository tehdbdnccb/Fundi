-- seed.sql
-- Run ONCE against a fresh demo database, before rehearsal and before the
-- live demo. NOT run against a database that already has real incidents
-- from earlier testing — this assumes a clean slate, and re-running it
-- would create duplicate demo users/sites since none of these inserts are
-- idempotent (no ON CONFLICT clause) — that's a deliberate choice: a demo
-- seed script silently upserting would risk masking a "did this actually
-- run" question during rehearsal.

BEGIN;

INSERT INTO users (id, email, password_hash, display_name, role) VALUES
    ('00000000-0000-0000-0000-000000000001', 'owner@demo.fundi', '$argon2id$demo$placeholder', 'Demo Site Owner', 'owner'),
    ('00000000-0000-0000-0000-000000000002', 'regulator@demo.fundi', '$argon2id$demo$placeholder', 'Demo Regulator', 'regulator');

INSERT INTO sites (id, owner_id, name, location_label) VALUES
    ('00000000-0000-0000-0000-000000000010', '00000000-0000-0000-0000-000000000001', 'Bay 2 — Assembly Floor', 'Building A');

INSERT INTO workers (id, display_name, wallet_address) VALUES
    ('00000000-0000-0000-0000-000000000020', 'Worker A', NULL),
    ('00000000-0000-0000-0000-000000000021', 'Worker B', '0x1234567890abcdef1234567890abcdef12345678');

-- Historical incidents spread across the past ~10 days, mixing resolved
-- ('minted') and one 'disputed' record — a dashboard with only clean green
-- checkmarks looks fake; a realistic safety record has some friction in it,
-- and showing a resolved dispute is actually a STRONGER trust signal
-- (the system caught and handled a disagreement) than pretending disputes
-- never happen.
INSERT INTO incidents (site_id, worker_id, rule_triggered, confidence_bp, detected_at, attestation_status, attestation_tx_hash) VALUES
    ('00000000-0000-0000-0000-000000000010', '00000000-0000-0000-0000-000000000020', 'ppe_missing', 8700, now() - interval '9 days', 'minted', '0xaaa1111111111111111111111111111111111111111111111111111111111'),
    ('00000000-0000-0000-0000-000000000010', '00000000-0000-0000-0000-000000000021', 'zone_breach', 7200, now() - interval '7 days', 'minted', '0xaaa2222222222222222222222222222222222222222222222222222222222'),
    ('00000000-0000-0000-0000-000000000010', NULL,                                    'zone_breach', 6500, now() - interval '5 days', 'minted', '0xaaa3333333333333333333333333333333333333333333333333333333333'),
    ('00000000-0000-0000-0000-000000000010', '00000000-0000-0000-0000-000000000020', 'ppe_missing', 9100, now() - interval '2 days', 'minted', '0xaaa4444444444444444444444444444444444444444444444444444444444');

INSERT INTO training_events (worker_id, module, completed_at, attestation_status, attestation_tx_hash) VALUES
    ('00000000-0000-0000-0000-000000000020', 'PPE Basics', now() - interval '20 days', 'minted', '0xbbb1111111111111111111111111111111111111111111111111111111111'),
    ('00000000-0000-0000-0000-000000000021', 'Zone Safety Orientation', now() - interval '18 days', 'minted', '0xbbb2222222222222222222222222222222222222222222222222222222222');

-- One resolved dispute — narrative: a worker successfully contested a
-- false-positive detection, and the system correctly reflects that
-- without pretending the original attestation vanished.
INSERT INTO disputes (incident_id, raised_by_user_id, reason, status, resolution_note, resolved_at)
SELECT id, '00000000-0000-0000-0000-000000000001',
       'Worker was wearing PPE; lighting caused a misdetection.',
       'upheld',
       'Reviewed frame reference, confirmed PPE was worn. Model confidence threshold flagged for review.',
       now() - interval '6 days'
FROM incidents
WHERE site_id = '00000000-0000-0000-0000-000000000010'
  AND rule_triggered = 'zone_breach'
  AND detected_at = (now() - interval '7 days');

COMMIT;