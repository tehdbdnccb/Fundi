// backend/src/routes.rs
//
// Axum HTTP layer. This file's only job is: parse requests, call into
// vision.rs / rules.rs / db.rs, map results to HTTP responses. No business
// logic lives here — if a handler is more than ~20 lines of actual logic
// (not counting error mapping), that's a signal the logic belongs in a
// lower layer instead.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::{get, post},
    Router,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;
use tower_http::cors::{Any, CorsLayer};

use crate::db::{self, AttestationStatus, IncidentRow};
use crate::rules::{Detection, RuleEngineError, RulesEngine};
use crate::vision::{self, VisionEngine};

/// Shared application state, constructed once in main.rs and cloned (cheap —
/// everything inside is Arc'd or Clone-cheap) into every request. The
/// RulesEngine is behind a Mutex because it has genuine internal mutable
/// state (debounce history, per rules.rs's own documentation of that
/// tradeoff) — everything else here is either immutable after construction
/// or already internally thread-safe (PgPool).
#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub vision: Arc<VisionEngine>,
    pub rules: Arc<Mutex<RulesEngine>>,
}

// router() function, updated:
pub fn router(state: AppState) -> Router {
    // Scoped deliberately permissive for hackathon demo purposes — Any
    // origin, Any method, Any header. This is a stated, documented scope
    // shortcut (same category as no-auth-middleware), not an oversight:
    // a real deployment would restrict origin to the actual dashboard
    // domain and would not need Any headers/methods. Noted explicitly in
    // the README's "known limitations" section alongside the auth gap,
    // so it reads as one deliberate, disclosed hackathon-scope decision
    // rather than two separate accidental holes.
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    Router::new()
        .route("/health", get(health))
        .route("/api/frames", post(ingest_frame))
        .route("/api/sites/:site_id/incidents", get(list_incidents))
        .route("/api/incidents/:incident_id", get(get_incident))
        .route("/api/incidents/:incident_id/disputes", post(raise_dispute))
        .layer(cors)
        .with_state(state)
}
// routes.rs — ingest_frame's response now includes raw per-frame
// detections for overlay purposes, separate from incidents_created.
// This is intentional: the overlay should show a box the instant a
// violation is visually detected, even on frames where the debounce
// window suppresses a new persisted incident — the worker should see
// immediate visual feedback, while the incident log stays deduplicated.

#[derive(Serialize)]
struct OverlayBox {
    rule: String,
    confidence_bp: u16,
    x1: f32,
    y1: f32,
    x2: f32,
    y2: f32,
}

#[derive(Serialize)]
struct IngestFrameResponse {
    incidents_created: Vec<Uuid>,
    overlay_boxes: Vec<OverlayBox>,
}

// Inside ingest_frame, after computing `raw_detections` and before the
// rules-engine mutex block, build the overlay list independently:
let overlay_boxes: Vec<OverlayBox> = raw_detections
    .iter()
    .filter_map(|raw| {
        vision::to_rule_confidence_bp(raw).map(|(rule_type, confidence_bp)| OverlayBox {
            rule: rule_type.as_db_str().to_string(),
            confidence_bp,
            x1: raw.bbox_original_xyxy[0],
            y1: raw.bbox_original_xyxy[1],
            x2: raw.bbox_original_xyxy[2],
            y2: raw.bbox_original_xyxy[3],
        })
    })
    .collect();

// ...existing candidate/insert logic unchanged...

Json(IngestFrameResponse {
    incidents_created: created_ids,
    overlay_boxes,
})
.into_response()

// ============================================================
// Shared error → HTTP mapping
// ============================================================

/// A single error shape returned to every client, regardless of which
/// lower layer produced the failure. Deliberately does not leak internal
/// error variants or messages that could reveal implementation details
/// (e.g. exact SQL, exact ONNX error text) — the `detail` field is a
/// deliberately generic, safe-to-display string; anything more specific
/// goes to server-side logs via eprintln, not to the client.
#[derive(Serialize)]
struct ApiError {
    error: String,
}

fn error_response(status: StatusCode, log_context: &str, detail: impl std::fmt::Display) -> axum::response::Response {
    eprintln!("[{log_context}] {detail}");
    (status, Json(ApiError { error: log_context.to_string() })).into_response()
}

// ============================================================
// GET /health
// ============================================================
async fn health() -> impl IntoResponse {
    StatusCode::OK
}

// ============================================================
// POST /api/frames — camera frame ingestion
// ============================================================

#[derive(Deserialize)]
struct IngestFrameRequest {
    site_id: Uuid,
    /// Nullable: the browser doesn't always know which worker is in frame —
    /// mirrors the schema's nullable worker_id, this is not an oversight.
    worker_id: Option<Uuid>,
    /// Base64-encoded JPEG/PNG frame from the browser's getUserMedia capture.
    frame_base64: String,
    /// Client-supplied capture timestamp — trusted here because this is a
    /// single-operator demo, not a multi-tenant system with adversarial
    /// clients. Documented explicitly as a scope limitation: a production
    /// version would use server-received time and treat client timestamps
    /// as advisory only, to prevent a malicious client from backdating
    /// incidents.
    captured_at: DateTime<Utc>,
}

#[derive(Serialize)]
struct IngestFrameResponse {
    /// Incidents that fired as a direct result of this frame — empty is
    /// the normal, expected case (most frames show no violation).
    incidents_created: Vec<Uuid>,
}

async fn ingest_frame(
    State(state): State<AppState>,
    Json(req): Json<IngestFrameRequest>,
) -> axum::response::Response {
    let image_bytes = match BASE64.decode(&req.frame_base64) {
        Ok(bytes) => bytes,
        Err(e) => return error_response(StatusCode::BAD_REQUEST, "invalid_base64_frame", e),
    };

    let image = match image::load_from_memory(&image_bytes) {
        Ok(img) => img,
        Err(e) => return error_response(StatusCode::BAD_REQUEST, "invalid_image_data", e),
    };

    let raw_detections = match state.vision.infer(&image) {
        Ok(d) => d,
        Err(e) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, "vision_inference_failed", e),
    };

    // Translate RawDetections into rules::Detection, dropping anything that
    // doesn't map to a known rule type — vision.rs's to_rule_confidence_bp
    // already documents this as the single conversion point, respected here.
    let detections: Vec<Detection> = raw_detections
        .iter()
        .filter_map(|raw| {
            vision::to_rule_confidence_bp(raw).map(|(rule_type, confidence_bp)| Detection {
                site_id: req.site_id,
                worker_id: req.worker_id,
                rule_type,
                confidence_bp,
                occurred_at: req.captured_at,
            })
        })
        .collect();

    let candidates = {
        // Mutex scope kept as tight as possible — released before any
        // await point below, so the debounce lock is never held across
        // network I/O (the Postgres insert). Holding a lock across an
        // await would serialize all frame ingestion behind whatever the
        // slowest DB write is, defeating the purpose of async handlers.
        let mut engine = state.rules.lock().await;
        match engine.evaluate(&detections) {
            Ok(c) => c,
            Err(RuleEngineError::ConfidenceOutOfRange(bp)) => {
                return error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "rules_engine_confidence_out_of_range",
                    format!("vision layer produced out-of-range confidence: {bp}"),
                )
            }
        }
    };

    let mut created_ids = Vec::with_capacity(candidates.len());
    for candidate in &candidates {
        match db::insert_incident(&state.pool, candidate).await {
            Ok(id) => created_ids.push(id),
            Err(e) => {
                // A single failed insert should not fail the whole request
                // if other candidates in this batch succeeded — logged
                // loudly, but the client still gets back the ones that did
                // persist, since those are real, valid incidents that
                // shouldn't be hidden by an unrelated insert failure.
                eprintln!("[incident_insert_failed] {e}");
            }
        }
    }

    Json(IngestFrameResponse {
        incidents_created: created_ids,
    })
    .into_response()
}

// ============================================================
// GET /api/sites/:site_id/incidents — dashboard list view
// ============================================================

#[derive(Deserialize)]
struct ListIncidentsQuery {
    before: Option<DateTime<Utc>>,
    #[serde(default = "default_limit")]
    limit: i64,
}

fn default_limit() -> i64 {
    50
}

#[derive(Serialize)]
struct IncidentDto {
    id: Uuid,
    site_id: Uuid,
    worker_id: Option<Uuid>,
    rule_triggered: String,
    confidence_bp: i32,
    detected_at: DateTime<Utc>,
    attestation_status: String,
    attestation_tx_hash: Option<String>,
}

impl From<IncidentRow> for IncidentDto {
    fn from(row: IncidentRow) -> Self {
        Self {
            id: row.id,
            site_id: row.site_id,
            worker_id: row.worker_id,
            rule_triggered: row.rule_triggered.as_db_str().to_string(),
            confidence_bp: row.confidence_bp,
            detected_at: row.detected_at,
            attestation_status: attestation_status_str(row.attestation_status),
            attestation_tx_hash: row.attestation_tx_hash,
        }
    }
}

fn attestation_status_str(s: AttestationStatus) -> String {
    match s {
        AttestationStatus::Pending => "pending",
        AttestationStatus::Minted => "minted",
        AttestationStatus::Failed => "failed",
        AttestationStatus::Disputed => "disputed",
    }
    .to_string()
}

async fn list_incidents(
    State(state): State<AppState>,
    Path(site_id): Path<Uuid>,
    Query(q): Query<ListIncidentsQuery>,
) -> axum::response::Response {
    // Clamp limit server-side — a client requesting limit=999999 should not
    // be able to force an unbounded query, regardless of what the query
    // param says. This is the enforcement point flagged as missing in
    // db.rs's self-critique.
    let safe_limit = q.limit.clamp(1, 200);

    match db::list_incidents_for_site(&state.pool, site_id, q.before, safe_limit).await {
        Ok(rows) => {
            let dtos: Vec<IncidentDto> = rows.into_iter().map(IncidentDto::from).collect();
            Json(dtos).into_response()
        }
        Err(e) => error_response(StatusCode::INTERNAL_SERVER_ERROR, "list_incidents_failed", e),
    }
}

// ============================================================
// GET /api/incidents/:incident_id — single incident detail
// ============================================================

async fn get_incident(
    State(state): State<AppState>,
    Path(incident_id): Path<Uuid>,
) -> axum::response::Response {
    match db::get_incident(&state.pool, incident_id).await {
        Ok(row) => Json(IncidentDto::from(row)).into_response(),
        Err(db::DbError::NotFound) => {
            (StatusCode::NOT_FOUND, Json(ApiError { error: "incident_not_found".to_string() }))
                .into_response()
        }
        Err(e) => error_response(StatusCode::INTERNAL_SERVER_ERROR, "get_incident_failed", e),
    }
}

// ============================================================
// POST /api/incidents/:incident_id/disputes — raise a dispute
// ============================================================

#[derive(Deserialize)]
struct RaiseDisputeRequest {
    raised_by_user_id: Uuid,
    reason: String,
}

#[derive(Serialize)]
struct DisputeCreatedResponse {
    dispute_id: Uuid,
}

async fn raise_dispute(
    State(state): State<AppState>,
    Path(incident_id): Path<Uuid>,
    Json(req): Json<RaiseDisputeRequest>,
) -> axum::response::Response {
    // Business rule enforced here (not in db.rs, per the separation
    // established in db.rs's own comments): a dispute can only be raised
    // against an incident currently in 'minted' status. Attempting to
    // dispute a 'pending' incident makes no sense (nothing has been
    // attested yet to dispute), and attempting to dispute an already-
    // 'disputed' one should go through a different "add evidence" flow,
    // not a second dispute row racing the trigger in schema.sql.
    let incident = match db::get_incident(&state.pool, incident_id).await {
        Ok(row) => row,
        Err(db::DbError::NotFound) => {
            return (StatusCode::NOT_FOUND, Json(ApiError { error: "incident_not_found".to_string() }))
                .into_response()
        }
        Err(e) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, "get_incident_failed", e),
    };

    if !matches!(incident.attestation_status, AttestationStatus::Minted) {
        return (
            StatusCode::CONFLICT,
            Json(ApiError {
                error: format!(
                    "incident must be 'minted' to dispute, currently '{}'",
                    attestation_status_str(incident.attestation_status)
                ),
            }),
        )
            .into_response();
    }

    if req.reason.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiError { error: "reason must not be empty".to_string() }),
        )
            .into_response();
    }

    let result = sqlx::query(
        r#"
        INSERT INTO disputes (incident_id, raised_by_user_id, reason)
        VALUES ($1, $2, $3)
        RETURNING id
        "#,
    )
    .bind(incident_id)
    .bind(req.raised_by_user_id)
    .bind(&req.reason)
    .fetch_one(&state.pool)
    .await;

    match result {
        Ok(row) => {
            let dispute_id: Uuid = match sqlx::Row::try_get(&row, "id") {
                Ok(id) => id,
                Err(e) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, "dispute_id_read_failed", e),
            };
            (StatusCode::CREATED, Json(DisputeCreatedResponse { dispute_id })).into_response()
        }
        Err(e) => error_response(StatusCode::INTERNAL_SERVER_ERROR, "raise_dispute_failed", e),
    }
}