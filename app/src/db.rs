// backend/src/db.rs
//
// Postgres access layer. This file is the only place in the codebase that
// issues SQL. Every function here maps 1:1 to a specific state transition
// already enforced by schema.sql's CHECK constraints and triggers — this
// file does NOT re-implement those invariants in Rust; it trusts the
// database to reject anything that would violate them, and surfaces that
// rejection as a typed error rather than a raw sqlx error leaking upward.

use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::rules::{IncidentCandidate, RuleType};

#[derive(Debug)]
pub enum DbError {
    ConnectionFailed(String),
    QueryFailed(String),
    /// Distinct from QueryFailed: this means the SQL executed fine but a
    /// CHECK constraint or trigger rejected the data — i.e. our own
    /// invariant caught something the Rust layer should have prevented
    /// upstream. Surfacing this distinctly matters because it's a signal
    /// of a bug in the calling code, not a transient infra failure, and
    /// should be logged/alerted differently.
    ConstraintViolation(String),
    NotFound,
}

impl std::fmt::Display for DbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DbError::ConnectionFailed(s) => write!(f, "db connection failed: {s}"),
            DbError::QueryFailed(s) => write!(f, "query failed: {s}"),
            DbError::ConstraintViolation(s) => write!(f, "constraint violation: {s}"),
            DbError::NotFound => write!(f, "row not found"),
        }
    }
}
impl std::error::Error for DbError {}

/// Postgres error code for check_violation, per the Postgres error codes
/// table. Hardcoded here rather than imported from a crate because it's a
/// stable, documented part of the Postgres wire protocol, not an
/// implementation detail likely to change.
const PG_CHECK_VIOLATION: &str = "23514";
const PG_UNIQUE_VIOLATION: &str = "23505";

fn classify_sqlx_error(e: sqlx::Error) -> DbError {
    if let sqlx::Error::Database(db_err) = &e {
        if let Some(code) = db_err.code() {
            if code == PG_CHECK_VIOLATION || code == PG_UNIQUE_VIOLATION {
                return DbError::ConstraintViolation(db_err.message().to_string());
            }
        }
    }
    DbError::QueryFailed(e.to_string())
}

/// A row read back from `incidents`, used by the minter poll loop and the
/// dashboard query layer. Deliberately a distinct type from
/// `rules::IncidentCandidate` — this one has an `id` and an
/// `attestation_status`, which are storage concerns the pure rules layer
/// must never know about.
#[derive(Debug, Clone)]
pub struct IncidentRow {
    pub id: Uuid,
    pub site_id: Uuid,
    pub worker_id: Option<Uuid>,
    pub rule_triggered: RuleType,
    pub confidence_bp: i32, // Postgres INT is i32; converted from rules::u16 at insert boundary
    pub detected_at: DateTime<Utc>,
    pub attestation_status: AttestationStatus,
    pub attestation_tx_hash: Option<String>,
}

/// Mirrors the Postgres CHECK constraint exactly — kept as an enum for the
/// same reason as RuleType: a typo here would otherwise silently become a
/// fourth, invalid status string that the DB would then also reject, but
/// only at runtime instead of at compile time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestationStatus {
    Pending,
    Minted,
    Failed,
    Disputed,
}

impl AttestationStatus {
    fn as_db_str(&self) -> &'static str {
        match self {
            AttestationStatus::Pending => "pending",
            AttestationStatus::Minted => "minted",
            AttestationStatus::Failed => "failed",
            AttestationStatus::Disputed => "disputed",
        }
    }

    /// Fallible parse from the DB's TEXT column. Returns an error rather
    /// than panicking — if this ever fails, it means the schema and this
    /// enum have drifted, which is a deployment bug, not a data bug, and
    /// should surface as a loud error rather than a silent default.
    fn from_db_str(s: &str) -> Result<Self, DbError> {
        match s {
            "pending" => Ok(AttestationStatus::Pending),
            "minted" => Ok(AttestationStatus::Minted),
            "failed" => Ok(AttestationStatus::Failed),
            "disputed" => Ok(AttestationStatus::Disputed),
            other => Err(DbError::QueryFailed(format!(
                "unrecognized attestation_status '{other}' — schema/enum drift"
            ))),
        }
    }
}

fn rule_type_from_db_str(s: &str) -> Result<RuleType, DbError> {
    match s {
        "ppe_missing" => Ok(RuleType::PpeMissing),
        "zone_breach" => Ok(RuleType::ZoneBreach),
        other => Err(DbError::QueryFailed(format!(
            "unrecognized rule_triggered '{other}' — schema/enum drift"
        ))),
    }
}

fn row_to_incident(row: sqlx::postgres::PgRow) -> Result<IncidentRow, DbError> {
    Ok(IncidentRow {
        id: row.try_get("id").map_err(|e| DbError::QueryFailed(e.to_string()))?,
        site_id: row.try_get("site_id").map_err(|e| DbError::QueryFailed(e.to_string()))?,
        worker_id: row.try_get("worker_id").map_err(|e| DbError::QueryFailed(e.to_string()))?,
        rule_triggered: rule_type_from_db_str(
            row.try_get::<String, _>("rule_triggered")
                .map_err(|e| DbError::QueryFailed(e.to_string()))?
                .as_str(),
        )?,
        confidence_bp: row.try_get("confidence_bp").map_err(|e| DbError::QueryFailed(e.to_string()))?,
        detected_at: row.try_get("detected_at").map_err(|e| DbError::QueryFailed(e.to_string()))?,
        attestation_status: AttestationStatus::from_db_str(
            row.try_get::<String, _>("attestation_status")
                .map_err(|e| DbError::QueryFailed(e.to_string()))?
                .as_str(),
        )?,
        attestation_tx_hash: row
            .try_get("attestation_tx_hash")
            .map_err(|e| DbError::QueryFailed(e.to_string()))?,
    })
}

/// Inserts a single incident candidate as a `pending` row. Takes ownership
/// of a `&PgPool` rather than a transaction handle — each incident insert
/// is independently atomic and has no reason to be batched into a larger
/// transaction with unrelated work, so keeping this simple is deliberate,
/// not an oversight.
pub async fn insert_incident(
    pool: &PgPool,
    candidate: &IncidentCandidate,
) -> Result<Uuid, DbError> {
    // confidence_bp is u16 in rules.rs but Postgres INT is i32 — the
    // conversion is infallible (u16 max is 65535, comfortably within i32
    // range) but made explicit here rather than relying on an implicit
    // `as` cast burying the reasoning.
    let confidence_bp_i32: i32 = candidate.confidence_bp.into();

    let row = sqlx::query(
        r#"
        INSERT INTO incidents (site_id, worker_id, rule_triggered, confidence_bp, detected_at)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING id
        "#,
    )
    .bind(candidate.site_id)
    .bind(candidate.worker_id)
    .bind(candidate.rule_triggered.as_db_str())
    .bind(confidence_bp_i32)
    .bind(candidate.detected_at)
    .fetch_one(pool)
    .await
    .map_err(classify_sqlx_error)?;

    row.try_get("id").map_err(|e| DbError::QueryFailed(e.to_string()))
}

/// Fetches all incidents currently `pending` attestation, ordered oldest
/// first. This is the exact query the minter poll loop runs — it relies on
/// `idx_incidents_pending_attestation` from schema.sql, and deliberately
/// caps the batch size so one poll cycle can never try to mint an unbounded
/// backlog in a single pass (the minter should make steady progress even
/// under load, not attempt everything at once and time out).
pub async fn fetch_pending_incidents(
    pool: &PgPool,
    limit: i64,
) -> Result<Vec<IncidentRow>, DbError> {
    let rows = sqlx::query(
        r#"
        SELECT id, site_id, worker_id, rule_triggered, confidence_bp,
               detected_at, attestation_status, attestation_tx_hash
        FROM incidents
        WHERE attestation_status = 'pending'
        ORDER BY detected_at ASC
        LIMIT $1
        "#,
    )
    .bind(limit)
    .fetch_all(pool)
    .await
    .map_err(classify_sqlx_error)?;

    rows.into_iter().map(row_to_incident).collect()
}

/// Marks an incident as successfully minted. Guarded by `WHERE
/// attestation_status = 'pending'` so this can never accidentally re-mint
/// or overwrite a row that's already `minted` or `disputed` — if the
/// minter's poll loop somehow processes the same row twice concurrently
/// (e.g. two worker instances racing), only the first UPDATE actually
/// matches a row, and the second becomes a harmless no-op rather than a
/// double-mint or a stomped tx_hash.
pub async fn mark_incident_minted(
    pool: &PgPool,
    incident_id: Uuid,
    tx_hash: &str,
) -> Result<bool, DbError> {
    let result = sqlx::query(
        r#"
        UPDATE incidents
        SET attestation_status = 'minted', attestation_tx_hash = $2
        WHERE id = $1 AND attestation_status = 'pending'
        "#,
    )
    .bind(incident_id)
    .bind(tx_hash)
    .execute(pool)
    .await
    .map_err(classify_sqlx_error)?;

    // rows_affected() == 0 is not an error — it means another process
    // already transitioned this row (or it never existed), and the caller
    // (attestation.rs) needs to know that distinction to decide whether to
    // log a warning.
    Ok(result.rows_affected() == 1)
}

/// Marks an incident's mint attempt as failed. Same pending-guard reasoning
/// as mark_incident_minted — a row that's already minted must never be
/// silently flipped to failed by a late-arriving error from a retry.
pub async fn mark_incident_failed(pool: &PgPool, incident_id: Uuid) -> Result<bool, DbError> {
    let result = sqlx::query(
        r#"
        UPDATE incidents
        SET attestation_status = 'failed'
        WHERE id = $1 AND attestation_status = 'pending'
        "#,
    )
    .bind(incident_id)
    .execute(pool)
    .await
    .map_err(classify_sqlx_error)?;

    Ok(result.rows_affected() == 1)
}

/// Fetches a single incident by id — used by the dashboard's detail view
/// and by dispute-raising, which needs to confirm the incident exists and
/// is currently `minted` before allowing a dispute to be opened (that
/// business-rule check belongs in routes.rs, not here — this function's
/// job is only to fetch, not to decide).
pub async fn get_incident(pool: &PgPool, incident_id: Uuid) -> Result<IncidentRow, DbError> {
    let row = sqlx::query(
        r#"
        SELECT id, site_id, worker_id, rule_triggered, confidence_bp,
               detected_at, attestation_status, attestation_tx_hash
        FROM incidents
        WHERE id = $1
        "#,
    )
    .bind(incident_id)
    .fetch_optional(pool)
    .await
    .map_err(classify_sqlx_error)?
    .ok_or(DbError::NotFound)?;

    row_to_incident(row)
}
// Add to db.rs:
pub async fn insert_dispute(
    pool: &PgPool,
    incident_id: Uuid,
    raised_by_user_id: Uuid,
    reason: &str,
) -> Result<Uuid, DbError> {
    let row = sqlx::query(
        r#"
        INSERT INTO disputes (incident_id, raised_by_user_id, reason)
        VALUES ($1, $2, $3)
        RETURNING id
        "#,
    )
    .bind(incident_id)
    .bind(raised_by_user_id)
    .bind(reason)
    .fetch_one(pool)
    .await
    .map_err(classify_sqlx_error)?;

    row.try_get("id").map_err(|e| DbError::QueryFailed(e.to_string()))
}

/// Lists incidents for a site's dashboard view, most recent first, paginated.
/// `before` supports keyset pagination (not OFFSET) — deliberate, since
/// OFFSET pagination degrades linearly with table size and this table is
/// exactly the one expected to grow fastest in a real pilot.
pub async fn list_incidents_for_site(
    pool: &PgPool,
    site_id: Uuid,
    before: Option<DateTime<Utc>>,
    limit: i64,
) -> Result<Vec<IncidentRow>, DbError> {
    let rows = sqlx::query(
        r#"
        SELECT id, site_id, worker_id, rule_triggered, confidence_bp,
               detected_at, attestation_status, attestation_tx_hash
        FROM incidents
        WHERE site_id = $1
          AND ($2::timestamptz IS NULL OR detected_at < $2)
        ORDER BY detected_at DESC
        LIMIT $3
        "#,
    )
    .bind(site_id)
    .bind(before)
    .bind(limit)
    .fetch_all(pool)
    .await
    .map_err(classify_sqlx_error)?;

    rows.into_iter().map(row_to_incident).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // These are unit tests of pure translation logic only — anything
    // touching an actual PgPool belongs in an integration test suite
    // against a real (or testcontainers-spun) Postgres instance, not here.
    // Listed as an explicit gap below rather than faked with a mock pool.

    #[test]
    fn attestation_status_round_trips_through_db_str() {
        for status in [
            AttestationStatus::Pending,
            AttestationStatus::Minted,
            AttestationStatus::Failed,
            AttestationStatus::Disputed,
        ] {
            let s = status.as_db_str();
            let parsed = AttestationStatus::from_db_str(s).unwrap();
            assert_eq!(status, parsed);
        }
    }

    #[test]
    fn attestation_status_rejects_unknown_string() {
        let result = AttestationStatus::from_db_str("something_else");
        assert!(result.is_err());
    }

    #[test]
    fn rule_type_round_trips_through_db_str() {
        for rule in [RuleType::PpeMissing, RuleType::ZoneBreach] {
            let s = rule.as_db_str();
            let parsed = rule_type_from_db_str(s).unwrap();
            assert_eq!(rule, parsed);
        }
    }
}