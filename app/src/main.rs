// backend/src/main.rs
//
// Service bootstrap. Loads config from environment, validates it fails
// loudly at startup (never lazily at first request), constructs shared
// state, spawns the attestation minter's background poll loop, and serves
// the Axum router. Kept deliberately thin — no business logic lives here,
// only wiring.

mod attestation;
mod db;
mod rules;
mod routes;
mod vision;

use routes::AppState;
use rules::{RulesEngine, RulesEngineConfig};
use sqlx::postgres::PgPoolOptions;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use vision::VisionEngine;

/// All required environment variables, read once at startup. Grouping them
/// into a struct rather than reading `env::var` scattered across the file
/// means a missing variable is caught in one place, at one time, with one
/// clear error — not discovered piecemeal as different code paths execute.
struct Config {
    database_url: String,
    server_port: u16,
    /// When true, vision.rs never loads a real ONNX model and instead
    /// returns deterministic synthetic detections — see vision.rs's loud
    /// startup warning. Defaults to false: mock mode must be explicitly
    /// opted into, never silently defaulted to, since accidentally demoing
    /// on fake data would be a serious credibility failure in front of judges.
    mock_vision: bool,
    onnx_model_path: PathBuf,
    /// When true, the attestation minter never calls the real chain — logs
    /// what it WOULD have minted and marks incidents as 'minted' with a
    /// synthetic tx hash prefixed 'MOCK-'. Exists for local development
    /// without spending testnet gas on every frame; must be off during the
    /// actual demo, and the synthetic hash prefix makes it visually obvious
    /// in the dashboard if it's accidentally left on.
    mock_attestation: bool,
    base_sepolia_rpc_url: String,
    attestation_signer_private_key: String,
    attestation_contract_address: String,
    attestation_contract_abi_path: PathBuf,
    minter_poll_interval_seconds: u64,
}

#[derive(Debug)]
enum ConfigError {
    MissingEnvVar(&'static str),
    InvalidValue { var: &'static str, reason: String },
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::MissingEnvVar(name) => write!(f, "missing required env var: {name}"),
            ConfigError::InvalidValue { var, reason } => {
                write!(f, "invalid value for {var}: {reason}")
            }
        }
    }
}
impl std::error::Error for ConfigError {}

impl Config {
    fn load() -> Result<Self, ConfigError> {
        let mock_vision = parse_bool_env("FUNDI_MOCK_VISION", false)?;
        let mock_attestation = parse_bool_env("FUNDI_MOCK_ATTESTATION", false)?;

        let database_url = require_env("DATABASE_URL")?;

        let server_port: u16 = std::env::var("SERVER_PORT")
            .unwrap_or_else(|_| "8080".to_string())
            .parse()
            .map_err(|e| ConfigError::InvalidValue {
                var: "SERVER_PORT",
                reason: format!("{e}"),
            })?;

        let onnx_model_path = PathBuf::from(
            std::env::var("ONNX_MODEL_PATH").unwrap_or_else(|_| "models/fundi_detector.onnx".to_string()),
        );

        // Fail fast: if we're NOT in mock mode, the model file must exist
        // right now, before we accept a single HTTP request — discovering
        // a missing model file on the first camera frame of a live demo
        // would be the single worst possible failure mode in this project.
        if !mock_vision && !onnx_model_path.exists() {
            return Err(ConfigError::InvalidValue {
                var: "ONNX_MODEL_PATH",
                reason: format!(
                    "file does not exist at {:?} and FUNDI_MOCK_VISION is not set — \
                     set FUNDI_MOCK_VISION=1 for local dev without a trained model, \
                     or fix the path",
                    onnx_model_path
                ),
            });
        }

        // Same fail-fast principle for the chain signer: if we're not
        // mocking attestation, every piece of on-chain config must be
        // present now, not discovered missing on the first incident.
        let (rpc_url, private_key, contract_address, contract_abi_path) = if mock_attestation {
            (String::new(), String::new(), String::new(), PathBuf::new())
        } else {
            (
                require_env("BASE_SEPOLIA_RPC_URL")?,
                require_env("ATTESTATION_SIGNER_PRIVATE_KEY")?,
                require_env("ATTESTATION_CONTRACT_ADDRESS")?,
                PathBuf::from(require_env("ATTESTATION_CONTRACT_ABI_PATH")?),
            )
        };

        if !mock_attestation && !contract_abi_path.exists() {
            return Err(ConfigError::InvalidValue {
                var: "ATTESTATION_CONTRACT_ABI_PATH",
                reason: format!("ABI file does not exist at {:?}", contract_abi_path),
            });
        }

        let minter_poll_interval_seconds: u64 = std::env::var("MINTER_POLL_INTERVAL_SECONDS")
            .unwrap_or_else(|_| "5".to_string())
            .parse()
            .map_err(|e| ConfigError::InvalidValue {
                var: "MINTER_POLL_INTERVAL_SECONDS",
                reason: format!("{e}"),
            })?;

        Ok(Self {
            database_url,
            server_port,
            mock_vision,
            onnx_model_path,
            mock_attestation,
            base_sepolia_rpc_url: rpc_url,
            attestation_signer_private_key: private_key,
            attestation_contract_address: contract_address,
            attestation_contract_abi_path: contract_abi_path,
            minter_poll_interval_seconds,
        })
    }
}

fn require_env(name: &'static str) -> Result<String, ConfigError> {
    std::env::var(name).map_err(|_| ConfigError::MissingEnvVar(name))
}

fn parse_bool_env(name: &'static str, default: bool) -> Result<bool, ConfigError> {
    match std::env::var(name) {
        Err(_) => Ok(default),
        Ok(s) => match s.as_str() {
            "1" | "true" | "TRUE" => Ok(true),
            "0" | "false" | "FALSE" => Ok(false),
            other => Err(ConfigError::InvalidValue {
                var: name,
                reason: format!("expected 1/0/true/false, got '{other}'"),
            }),
        },
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::load().map_err(|e| {
        eprintln!("FATAL: configuration error — {e}");
        e
    })?;

    // Connection pool sized for a single-camera demo, not a production
    // fleet — max_connections chosen deliberately small (5) so a bug that
    // leaks connections fails fast and loudly (pool exhaustion errors)
    // rather than silently degrading under a much larger, hidden limit.
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .acquire_timeout(Duration::from_secs(10))
        .connect(&config.database_url)
        .await
        .map_err(|e| {
            eprintln!("FATAL: failed to connect to Postgres — {e}");
            e
        })?;

    // Run migrations at startup rather than requiring a manual step before
    // every deploy — for a solo hackathon build, "the binary starting
    // successfully means the schema is correct" is a valuable invariant
    // that removes an entire category of demo-day surprise.
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .map_err(|e| {
            eprintln!("FATAL: database migration failed — {e}");
            e
        })?;

    // Initialize vision engine with mock or real ONNX model
    let vision_engine = Arc::new(VisionEngine::new(
        if config.mock_vision {
            &String::new()
        } else {
            config.onnx_model_path.to_str().unwrap_or("")
        }
    ).map_err(|e| {
        eprintln!("FATAL: vision engine failed to load — {e}");
        e
    })?);

    let rules_engine = Arc::new(Mutex::new(RulesEngine::new(RulesEngineConfig::default())));

    let state = AppState {
        pool: pool.clone(),
        vision: vision_engine,
        rules: rules_engine,
    };

    // Spawn the attestation minter's poll loop as a background task,
    // independent of the HTTP server. If it panics, the HTTP server keeps
    // serving the dashboard and camera ingestion — a stalled minter should
    // degrade the demo (incidents pile up as 'pending') rather than take
    // down the entire service, since a partially-working demo is always
    // recoverable but a crashed process mid-demo is not.
    if config.mock_attestation {
        eprintln!(
            "\n\
             ================================================================\n\
             FUNDI_MOCK_ATTESTATION IS ENABLED. No real chain calls will be made.\n\
             Incidents will be marked 'minted' with synthetic MOCK- tx hashes.\n\
             This MUST be disabled for the live demo.\n\
             ================================================================\n"
        );
        tokio::spawn(mock_minter_loop(pool.clone(), config.minter_poll_interval_seconds));
    } else {
        let abi_json = std::fs::read_to_string(&config.attestation_contract_abi_path)?;
        let minter = attestation::AttestationMinter::new(
            &config.base_sepolia_rpc_url,
            &config.attestation_signer_private_key,
            &config.attestation_contract_address,
            &abi_json,
        )
        .await
        .map_err(|e| {
            eprintln!("FATAL: attestation minter failed to initialize — {e}");
            e
        })?;

        tokio::spawn(real_minter_loop(minter, pool.clone(), config.minter_poll_interval_seconds));
    }

    let app = routes::router(state);
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", config.server_port)).await?;

    println!("Fundi backend listening on port {}", config.server_port);

    // Use hyper::Server for axum 0.6 compatibility (axum 0.7+ has axum::serve)
    hyper::Server::from_tcp(listener.into_std()?)?
        .serve(app.into_make_service_with_connect_info::<std::net::SocketAddr>())
        .await?;

    Ok(())
}

/// Background loop calling the real minter on a fixed interval. A crash
/// inside one iteration (caught via the Result returned by run_once) is
/// logged and the loop continues — a single bad cycle must never kill the
/// entire background task, since that would silently stop all future
/// attestations with no visible symptom except a slowly growing 'pending' count.
async fn real_minter_loop(minter: attestation::AttestationMinter, pool: sqlx::PgPool, interval_secs: u64) {
    let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs));
    loop {
        ticker.tick().await;
        match minter.run_once(&pool).await {
            Ok(count) if count > 0 => println!("minter cycle: {count} incident(s) minted"),
            Ok(_) => {} // nothing pending this cycle, not worth logging every tick
            Err(e) => eprintln!("minter cycle failed: {e}"),
        }
    }
}

/// Mock-mode equivalent: marks pending incidents as minted with a synthetic
/// tx hash, without any chain interaction. Reuses db::fetch_pending_incidents
/// and db::mark_incident_minted directly so the state-machine guarantees
/// (guarded UPDATE, race-safety) are exercised identically to the real path
/// — this is deliberately NOT a separate, simpler code path, because a bug
/// in the guarded-update logic should be caught in mock-mode testing too,
/// not only in a real-chain integration test.
async fn mock_minter_loop(pool: sqlx::PgPool, interval_secs: u64) {
    let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs));
    let mut counter: u64 = 0;
    loop {
        ticker.tick().await;
        match db::fetch_pending_incidents(&pool, 10).await {
            Ok(pending) => {
                for incident in pending {
                    counter += 1;
                    let fake_hash = format!("MOCK-{:016x}", counter);
                    if let Err(e) = db::mark_incident_minted(&pool, incident.id, &fake_hash).await {
                        eprintln!("mock minter: failed to mark {} minted: {e}", incident.id);
                    }
                }
            }
            Err(e) => eprintln!("mock minter: fetch_pending_incidents failed: {e}"),
        }
    }
}

