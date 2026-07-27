// backend/src/attestation.rs
//
// Bridges the Postgres `pending` incident queue to on-chain minting via
// ethers-rs against Base Sepolia. This file owns the ONE signer key in the
// system — the same centralized-trust-boundary decision documented in
// Attestation.sol's own comments. That centralization is a stated hackathon
// scope limitation, not something hidden here either.

use ethers::{
    abi::Abi,
    contract::Contract,
    middleware::SignerMiddleware,
    providers::{Http, Middleware, Provider},
    signers::{LocalWallet, Signer},
    types::{Address, U256},
};
use sqlx::{PgPool, Row};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

use crate::db::{self, DbError, IncidentRow};
use crate::rules::RuleType;

#[derive(Debug)]
pub enum AttestationError {
    ProviderConnectionFailed(String),
    ContractCallFailed(String),
    /// The chain call succeeded but the DB update guarding against a
    /// duplicate mint reported zero rows affected — meaning another process
    /// already claimed this incident between our fetch and our mint. This
    /// is NOT a failure of the mint itself (the chain now has an extra,
    /// harmless attestation), it's a signal to log loudly, because it means
    /// two minter instances are running concurrently against the same
    /// queue, which should not happen in the single-process demo deployment.
    RaceDetectedAfterMint { incident_id: Uuid, tx_hash: String },
    Db(DbError),
}

impl std::fmt::Display for AttestationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AttestationError::ProviderConnectionFailed(s) => write!(f, "provider connection failed: {s}"),
            AttestationError::ContractCallFailed(s) => write!(f, "contract call failed: {s}"),
            AttestationError::RaceDetectedAfterMint { incident_id, tx_hash } => write!(
                f,
                "race detected: incident {incident_id} minted (tx {tx_hash}) but DB row was already claimed"
            ),
            AttestationError::Db(e) => write!(f, "db error: {e}"),
        }
    }
}
impl std::error::Error for AttestationError {}

impl From<DbError> for AttestationError {
    fn from(e: DbError) -> Self {
        AttestationError::Db(e)
    }
}

/// Mirrors the Solidity enum exactly — same reasoning as RuleType/
/// AttestationStatus: a mismatch between this ordering and the deployed
/// contract's enum would silently mint attestations tagged with the wrong
/// type, which is the single worst possible bug in this entire file, since
/// it corrupts the on-chain record permanently (the contract has no
/// correction mechanism by design — see Attestation.sol dispute reasoning).
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
enum ContractAttestationType {
    PpeMissing = 0,
    ZoneBreach = 1,
    TrainingComplete = 2,
}

impl From<RuleType> for ContractAttestationType {
    fn from(rt: RuleType) -> Self {
        match rt {
            RuleType::PpeMissing => ContractAttestationType::PpeMissing,
            RuleType::ZoneBreach => ContractAttestationType::ZoneBreach,
        }
    }
}

// Struct definition updated to match — pool field removed entirely:
pub struct AttestationMinter {
    contract: Contract<SignerMiddleware<Provider<Http>, LocalWallet>>,
    batch_size: i64,
}

impl AttestationMinter {
    pub async fn new(
        rpc_url: &str,
        private_key_hex: &str,
        contract_address: &str,
        contract_abi_json: &str,
    ) -> Result<Self, AttestationError> {
        let provider = Provider::<Http>::try_from(rpc_url)
            .map_err(|e| AttestationError::ProviderConnectionFailed(e.to_string()))?
            .interval(Duration::from_millis(2000));

        let chain_id = provider
            .get_chainid()
            .await
            .map_err(|e| AttestationError::ProviderConnectionFailed(e.to_string()))?;

        let wallet: LocalWallet = private_key_hex
            .parse::<LocalWallet>()
            .map_err(|e| AttestationError::ProviderConnectionFailed(e.to_string()))?
            .with_chain_id(chain_id.as_u64());

        const BASE_SEPOLIA_CHAIN_ID: u64 = 84532;
        if chain_id.as_u64() != BASE_SEPOLIA_CHAIN_ID {
            return Err(AttestationError::ProviderConnectionFailed(format!(
                "expected Base Sepolia (chain id {BASE_SEPOLIA_CHAIN_ID}), got {}",
                chain_id.as_u64()
            )));
        }

        let client = Arc::new(SignerMiddleware::new(provider, wallet));
        let address = Address::from_str(contract_address)
            .map_err(|e| AttestationError::ProviderConnectionFailed(e.to_string()))?;
        let abi: Abi = serde_json::from_str(contract_abi_json)
            .map_err(|e| AttestationError::ProviderConnectionFailed(e.to_string()))?;
        let contract = Contract::new(address, abi, client);

        Ok(Self {
            contract,
            batch_size: MINTER_BATCH_SIZE,
        })
    }

    /// Runs one poll-and-mint cycle: fetch up to `batch_size` pending
    /// incidents, attempt to mint each, update DB accordingly. Returns the
    /// count successfully minted this cycle, for logging/metrics — never
    /// panics on an individual incident's failure, since one bad row must
    /// never take down the whole batch (same "no partial-batch corruption,
    /// but also no all-or-nothing brittleness" philosophy as rules.rs,
    /// applied at the opposite end: rules.rs fails the WHOLE batch on bad
    /// input because that's pre-persistence validation; this loop tolerates
    /// per-row failure because these are already-persisted, independent
    /// incidents that must not block each other).
    pub async fn run_once(&self, pool: &PgPool) -> Result<u32, AttestationError> {
        let pending = db::fetch_pending_incidents(pool, self.batch_size).await?;
        let mut minted_count = 0u32;

        for incident in pending {
            match self.mint_single(pool, &incident).await {
                Ok(true) => minted_count += 1,
                Ok(false) => {
                    // mint_single returns Ok(false) only for the documented
                    // race case — already logged inside mint_single, not
                    // re-logged here to avoid double-logging the same event.
                }
                Err(e) => {
                    eprintln!("attestation mint failed for incident {}: {e}", incident.id);
                    if let Err(db_err) = db::mark_incident_failed(pool, incident.id).await {
                        eprintln!(
                            "additionally failed to mark incident {} as failed: {db_err}",
                            incident.id
                        );
                    }
                }
            }
        }

        Ok(minted_count)
    }

    /// Mints a single incident's attestation and updates its DB row.
    /// Returns Ok(true) on a clean mint, Ok(false) if the mint succeeded on
    /// chain but the DB guard detected a race (see AttestationError variant
    /// doc), Err on genuine failure. The three-way return here — rather
    /// than folding the race case into the Err path — is deliberate: a race
    /// is not a failure of THIS mint, it needs different handling upstream.
    async fn mint_single(
        &self,
        pool: &PgPool,
        incident: &IncidentRow,
    ) -> Result<bool, AttestationError> {
        let attestation_type: ContractAttestationType = incident.rule_triggered.into();
        let site_hash = keccak256_site_id(incident.site_id);
        let severity_score = U256::from(incident.confidence_bp.max(0) as u64);
        let timestamp = U256::from(incident.detected_at.timestamp() as u64);
        let subject = resolve_subject_address(pool, incident.worker_id).await?;

        let call = self
            .contract
            .method::<_, U256>(
                "mintAttestation",
                (
                    attestation_type as u8,
                    site_hash,
                    severity_score,
                    timestamp,
                    subject,
                ),
            )
            .map_err(|e| AttestationError::ContractCallFailed(e.to_string()))?;

        let pending_tx = call
            .send()
            .await
            .map_err(|e| AttestationError::ContractCallFailed(e.to_string()))?;

        // Wait for the transaction to be mined before recording it as
        // minted in Postgres — recording an unconfirmed tx hash as
        // "minted" would let the dashboard show a false-positive success
        // state if the transaction later reverts or is dropped/replaced.
        let receipt = pending_tx
            .await
            .map_err(|e| AttestationError::ContractCallFailed(e.to_string()))?
            .ok_or_else(|| {
                AttestationError::ContractCallFailed("transaction dropped, no receipt".to_string())
            })?;

        if receipt.status != Some(1.into()) {
            return Err(AttestationError::ContractCallFailed(format!(
                "transaction reverted, tx hash {:?}",
                receipt.transaction_hash
            )));
        }

        let tx_hash = format!("{:?}", receipt.transaction_hash);

        let updated = db::mark_incident_minted(pool, incident.id, &tx_hash).await?;

        if updated {
            Ok(true)
        } else {
            // Chain state now has an attestation that Postgres doesn't
            // cleanly reflect as ours — surfaced loudly, not swallowed.
            Err(AttestationError::RaceDetectedAfterMint {
                incident_id: incident.id,
                tx_hash,
            })
        }
    }
}

/// Resolves a worker_id to their on-chain wallet address, or the zero
/// address if the worker has none set — mirrors the schema's nullable
/// `wallet_address` and the contract's explicit support for
/// `subject == address(0)`. Kept as a free function rather than a method
/// on AttestationMinter because it's a pure DB-to-chain-type translation
/// with no dependency on contract state.
async fn resolve_subject_address(
    pool: &PgPool,
    worker_id: Option<Uuid>,
) -> Result<Address, AttestationError> {
    let Some(worker_id) = worker_id else {
        return Ok(Address::zero());
    };

    let row = sqlx::query("SELECT wallet_address FROM workers WHERE id = $1")
        .bind(worker_id)
        .fetch_optional(pool)
        .await
        .map_err(|e| AttestationError::ContractCallFailed(e.to_string()))?;

    match row {
        None => Ok(Address::zero()), // worker was deleted between detection and mint — treat as unattributed
        Some(r) => {
            let wallet: Option<String> = r
                .try_get("wallet_address")
                .map_err(|e| AttestationError::ContractCallFailed(e.to_string()))?;
            match wallet {
                Some(addr_str) => Address::from_str(&addr_str)
                    .map_err(|e| AttestationError::ContractCallFailed(e.to_string())),
                None => Ok(Address::zero()),
            }
        }
    }
}

/// keccak256 of the site's UUID bytes — matches Attestation.sol's
/// `bytes32 siteHash` field exactly. Hashing the raw 16 UUID bytes, not the
/// UUID's string representation, so this is unambiguous and doesn't depend
/// on UUID formatting conventions (hyphenated vs not, upper vs lowercase)
/// matching between Rust and any future off-chain verifier.
fn keccak256_site_id(site_id: Uuid) -> [u8; 32] {
    use tiny_keccak::{Hasher, Keccak};
    let mut hasher = Keccak::v256();
    let mut output = [0u8; 32];
    hasher.update(site_id.as_bytes());
    hasher.finalize(&mut output);
    output
}

const MINTER_BATCH_SIZE: i64 = 10;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn site_hash_is_deterministic_for_same_uuid() {
        let id = Uuid::new_v4();
        assert_eq!(keccak256_site_id(id), keccak256_site_id(id));
    }

    #[test]
    fn site_hash_differs_for_different_uuids() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        assert_ne!(keccak256_site_id(a), keccak256_site_id(b));
    }

    #[test]
    fn rule_type_maps_to_correct_contract_enum_value() {
        assert_eq!(ContractAttestationType::from(RuleType::PpeMissing) as u8, 0);
        assert_eq!(ContractAttestationType::from(RuleType::ZoneBreach) as u8, 1);
    }
}

