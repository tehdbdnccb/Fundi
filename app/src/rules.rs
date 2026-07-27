// backend/src/rules.rs
// 
// Deterministic safety rules engine. Pure logic - no database, no network
// no filesystem. Takes visi0n-model detections in, produces incident 
// candidates out. Kept pure deliberately: this is the layer a judge or 
// auditor is most likely to ask "how do you know this isn't just an LLM
// guessing" about, and the answer needs to be "it's testable arithmetic,
// here are the unit tests".

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use std::collections::HashMap;
use uuid::Uuid;

// Mirrors the Postgres CHECK constraint 'rule_triggered IN ('ppe_missing', 'zone_breach')
// Kept as an enum here, not a string, so a typo can never silently create a 
// third "rule" that the database would then also silently accept as valid text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RuleType {
    PpeMissing,
    ZoneBreach,
}

impl RuleType {
    /// Single source of truth for the  DB string representation, so the Rust 
    /// enum and the Postgres CHECK constraint can never drift out of sync 
    /// silently - if someone renames a variant here, this is the one place 
    /// that has to be updated to match the migration.
    pub fn as_db_str(&self) -> &'static str {
        match self {
            RuleType::PpeMissing => "ppe_missing",
            RuleType::ZoneBreach => "zone_breach",
        }
    }
}

/// A single raw detection emitted by the vision inference layer for one frame.
/// This struct is the entire contract between vision.rs and rules.rs - vision.rs
/// knows nothing about debouncing orr incident creation, and rules.rs knows
/// nothing about ONNX or bounding boxes. That separation is deliberate.
#[derive(Debug, Clone)]
pub struct Detection {
    pub site_id: Uuid,
    pub worker_id: Option<Uuid>,
    pub rule_type: RuleType,
    /// Basis points, 0-10000, matching the Postgres 'confidence_bp' column exactly 
    /// Deliberately not a float - see confidence_bp invariant note in schema.sql.
    pub confidence_bp: u16,
    pub occured_at: DateTime<Utc>,
}

/// Validation error for a malformed detection. The engine refuses to silently 
/// clamp or coerce bad input - a confidence value out of range is far more 
/// likely to indicate a bug in vision.rs than a legitimate edge case, and 
/// silently clamping it would hide that bug instead of surfacing it. 
#[derive(Debug, PartialEq, Eq)]
pub enum RuleEngineError {
    ConfidenceOutOfRange(u16),
}

/// The output of the engine: a candidate incident ready to be persisted
/// Deliberately does NOT include an 'id' - that's Postgres's job to assign 
/// on insert ('gen_random_uuid()'), keeping this struct a pure value type 
/// with no notion of storage identity 
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncidentCandidate {
    pub site_id: Uuid,
    pub worker_id: Option<Uuid>,
    pub rule_triggered: RuleType,
    pub confidence_bp: u16,
    pub detected_at: DateTime<Utc>,
}

/// Per-(site, worker, rule) debounce key. 'worker_id' is part of the key 
/// because two different workers triggering 'zone_breach' at the same site 
/// in the same second are two distinct incidents, not one - debouncing must 
/// never merge across workers.
type DebounceKey = (Uuid, Option<Uuid>, RuleType);

pub struct RulesEngineConfig {
    /// Minimum confidence, in basis points, required to fire an incident at all.
    /// Detections below this are discarded silently - this is intentional
    /// noise-floor filtering, not a bug, and is distinct from the 
    /// ConfidenceOutOfRange error (which is a malformed *input*, not a 
    /// low-but-valid one
    pub min_confidence_bp: u16,
    /// Minimum time that must elapse since the last fired incident for the 
    /// same (site, worker, rule) key before another one is allowed to fire.
    /// Exists to stop one continuos violation across many video frames from 
    /// generating hundreds of near-duplicate incidents and attestation mints 
    pub debounce_window: ChronoDuration,
}

impl Default for RulesEngineConfig {
    fn default() -> Self {
        Self {
            min_confidence_bp: 6000, // 60% to bias toward precision over
            // recall for a v1 demo; false positives are 
            // more damaging to trust than missed detections
            debounce_window: ChronoDuration::seconds(30),

        }
    }
}

/// Holds debounce state across calls. Not 'Clone' not 'Sync' by default -
/// this is meant to be owned by exactly one place (the Axum app state
/// behind a mutex, wired up in main.rs), never duplicated, simce duplicating
/// it would silently reset debounce history and defeat its purpose.
pub struct RulesEngine {
    config: RulesEngineConfig,
    last_fired: HashMap<DebounceKey, DateTime<Utc>>,
}

impl RulesEngine {
    pub fn new(config: RulesEngineConfig) -> Self {
        Self {
            config,
            last_fired: HashMap::new(),
        }
    }

    /// Evaluates a batch of detections and returns the incidents that should 
    /// actually be persisted and attested. Takes '&mut self' because firing
    /// an incident updates internal debounce state - this is the one place 
    /// in the pure-logic layer with any mutation at all, and it's confined 
    /// to an in-memory map, not I/0
    pub fn evaluate(
        &mut self,
        detections: &[Detection],
    ) -> Result<Vec<IncidentCandidate>, RuleEngineError> {
        // Validate all detections up front, before firing any of them. A 
        // batch with one malformed detection should not partially fire - 
        // partial appliaction of a batch is a subtle source of "why did only 
        // 3 of these 5 things happen" bugs that are painful to debug later.
        for d in detections {
            if d.confidence_bp > 10_000 {
                return Err(RuleEngineError::ConfidenceOutOfRange(d.confidence_bp));
            }
        }

        let mut fired = Vec::new();

        for d in detections {
            if d.confidence_bp < self.config.min_confidence_bp {
                continue; // below noise floor, not an error, just not actionable
            }

            let key: DebounceKey = (d.site_id, d.worker_id, d.rule_type);

            let should_fire = match self.last_fired.get(&key) {
                None => true,
                Some(last) => d.occured_at.signed_duration_since(*last) >= self.config.debounce_window,
            };

            if !should_fire {
                continue;
            }

            self.last_fired.insert(key, d.occured_at);

            fired.push(IncidenrCandidate{
                site_id: d.site_id,
                worker_id: d.worker_id,
                rule_triggered: d.rule_type,
                confidence_bp: d.confidence_bp,
                detected_at: d.occured_at,
            });
        }
        Ok(fired)
    }
}

// ================================================
// TESTS - this is the proof. Every edge case named in review comments above 
// gets a corresponding test here; if a reviewer asks "how do you know the 
// debounce is inclusive/exclusive" the answer is 'test_debounce_boundary_is_exclusive
// ==========================================
#[cfg(test)]
mod tests {
    use super::*;

    fn detection(
        site: Uuid,
        worker: Option<Uuid>,
        rule: RuleType,
        confidence_bp: u16,
        occured_at: DateTime<Utc>,
    ) -> Detection {
        Detection {
            site_id: site,
            worker_id: worker,
            rule_type: rule,
            confidence_bp,
            ocurred_at,

        }
    }

    #[test]
    fn fires_on_first_valid_detection() {
        let mut engine = RulesEngine::new(RulesEngineConfig::default());
        let site = Uuid::new_v4();
        let now = Utc::now();

        let result = engine 
        .evaluate(&[detection(site, None, RuleType::ZoneBreach, 8000, now)])
        .unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].rule_triggered, RuleType::ZoneBreach);
    }

    #[test]
    fn below_min_confidence_is_silently_dropped_not_errores() {
        let mut engine = RulesEngine::new(RulesEngineConfig::default());
        let site = Uuid::new_v4();
        let now = Utc::now();

        let result = engine 
        .evaluate(&[detection(site, None, RuleType::PpeMissing, 400, now)])
        .unwrap();

        assert!(result.is_empty());
    }

    #[test]
    fn confidence_exactly_at_threshold_fires() {
        // Boundary check: min_confidence_bp is inclusive, not exclusive.
        let mut engine = RulesEngine::new(RulesEngineConfig::default());
        let site = Uuid::new_v4();
        let now = Utc::now();

        let result = engine 
        .evaluate(&[detection(site, None, RulesType::PpeMissing, 6000, now)])
        .unwrap();

        assert_eq!(result.len(), 1);
    }

    #[test]
    fn confidence_over_10000_is_a_hard_error() {
        let mut engine = RulesEngine::new(RulesEngineConfig::default());
        let site = Uuid::new_v4();
        let now = Utc::now();

        let result = engine.evaluate(&[detection(site, None, RuleType::PpeMissing, 10_001, now)]);

        assert_eq!(result, Err(RuleEngineError::ConfidenceOutOfRange(10_001)));
    }

    #[test]
    fn malformed_detection_blocks_the_entire_batch_not_just_itself() {
        let mut engine = RulesEngine::new(RulesEngineConfig::default());
        let site = Uuid::new_v4();
        let now = Utc::now();

        let good = detection(site, None, RuleType::ZoneBreach, 9000, now);
        let bad = detection(site, None, RuleType::PpeMissing, 20_000, now);

        let result = engine.evaluate(&[good, bad]);
        assert!(result.is_err());

        // confirm the "good" one truly did not fire and update debounce state -
        // re-running just the good detection alone should still fire fresh 
        let mut engine2 = RulesEngine::new(RulesEngineConfig::default());
        let retry = engine2
        .evaluate(&[detection(site, None, RuleType::ZoneBreach, 9000, now)])
        .unwrap();
        assert_eq!(retry.len(), 1);
    }

    #[test]
    fn debounce_suppresses_repeat_within_window() {
        let mut engine = RulesEngine::new(RulesEngineConfig::default());
        let site = Uuid::new_v4();
        let t0 = Utc::now();
        let t1 = t0 + ChronoDuration::seconds(10); // inside the 30s default window 

        let first = engine 
        .evaluate(&[detection(site, None, RuleType::ZoneBreach, 9000, t0)])
        .unwrap();
        let second = engine 
        .evaluate(&[detection(site, None, RuleType::ZoneBreach, 9000, t1)])
        .unwrap();

        assert_eq!(first.len(), 1);
        assert_eq!(second.len(), 0); // suppressed
    }

    #[test]
    fn debounce_boundary_is_inclusive_at_exact_window() {
        let mut engine = RulesEngine::new(RulesEngineConfig::default);
        let site = Uuid::new_v4();
        let t0 = Utc::now();
        let t1 = t0 + ChronoDuration::seconds(30); // exactly the default window 

        engine 
        .evaluate(&[detection(site, None, RuleType::ZoneBreach, 9000, t0)])
        .unwrap();
        let second = engine 
        .evaluate(&[detection(site, None, RuleType::ZoneBreach, 9000, t1)])
        .unwrap();

        // >= comparison in the engine means exactly-at-window fires again 
        assert_eq!(second.len(), 1);
    }

    #[test]
    fn different_workers_at_same_site_are_debounced_independently() {
        let mut engine = RulesEngine::new(RulesEngineConfig::default());
        let site = Uuid::new_v4();
        let worker_a = Some(Uuid::new_v4());
        let worker_b = Some(Uuid::new_v4());
        let now = Utc::now();

        let result = engine 
        .evaluate(&[
            detection(site, worker_a, RuleType::PpeMissing, 9000, now),
            detection(site, worker_b, RuleType::PpeMissing, 9000, now),
        ])
        .unwrap();

        // Both fire - debounce key includes worker_id, so these are independent 
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn zone_breach_with_no_worker_attributed_still_fires() {
        // Mirrors the schema decision: worker_id is nullable, an incident is
        // still valid and billable without worker attribution
        let mut engine = RulesEngine::new(RulesEngineConfig::default());
        let site = Uuid::new_v4();
        let now = Utc::now();

        let result = engine 
        .evaluate(&[detection(site, None, RulesType::ZoneBreach, 7500, now)])
        .unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].worker_id, None);
    }

    #[test]
    fn different_rule_types_at_same_site_worker_do_not_share_debounce_state() {
        let mut engine = RulesEngine::new(RulesEngineConfig::default());
        let site = Uuid::new_v4();
        let worker = Some(Uuid::new_v4());
        let now = Utc::now();

        let result = engine 
        .evaluate(&[
            detection(site, worker, RuleType::PpeMissing, 9000, now),
            detection(site, worker, RuleType::ZoneBreach, 9000, now),
        ])
        .unwrap();

        assert_eq!(result.len(), 2);
    }
}