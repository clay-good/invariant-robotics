use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::Utc;
use clap::Args;
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use invariant_core::authority::crypto::sign_pca;
use invariant_core::models::authority::Pca;
use invariant_core::models::command::Command;
use invariant_core::validator::ValidatorConfig;
use invariant_core::watchdog::{Watchdog, WatchdogState};

#[derive(Args)]
pub struct ServeArgs {
    #[arg(long, value_name = "PROFILE_FILE")]
    pub profile: PathBuf,
    #[arg(long, value_name = "KEY_FILE")]
    pub key: PathBuf,
    /// TCP port for the embedded Trust Plane. Ports below 1024 require elevated
    /// privileges; use values >= 1024 for unprivileged operation (P3-10).
    #[arg(long, default_value = "8080", value_parser = clap::value_parser!(u16).range(1024..))]
    pub port: u16,
    #[arg(long)]
    pub trust_plane: bool,
    /// Watchdog heartbeat timeout in milliseconds. 0 disables the watchdog.
    #[arg(long, default_value = "500")]
    pub watchdog_timeout_ms: u64,
}

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

struct AppState {
    config: ValidatorConfig,
    trust_plane: bool,
    /// Signing key bytes (for creating ephemeral SigningKey copies).
    signing_key_bytes: [u8; 32],
    kid: String,
    watchdog: Option<Mutex<WatchdogInner>>,
    boot_instant: Instant,
}

struct WatchdogInner {
    watchdog: Watchdog,
    boot_instant: Instant,
}

impl WatchdogInner {
    fn now_ms(&self) -> u64 {
        self.boot_instant.elapsed().as_millis() as u64
    }
}

// ---------------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct ValidateRequest {
    command: Command,
}

#[derive(Serialize, Deserialize)]
struct ValidateResponse {
    verdict: invariant_core::models::verdict::SignedVerdict,
    #[serde(skip_serializing_if = "Option::is_none")]
    actuation_command: Option<invariant_core::models::actuation::SignedActuationCommand>,
}

#[derive(Serialize, Deserialize)]
struct HeartbeatResponse {
    status: String,
    watchdog_state: String,
}

#[derive(Serialize, Deserialize)]
struct HealthResponse {
    status: String,
    profile_name: String,
    trust_plane: bool,
    watchdog_enabled: bool,
    watchdog_state: Option<String>,
    uptime_ms: u64,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn handle_validate(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ValidateRequest>,
) -> Result<Json<ValidateResponse>, (StatusCode, Json<ErrorResponse>)> {
    let mut cmd = req.command;

    // In trust-plane mode, auto-issue a self-signed PCA chain.
    if state.trust_plane {
        let sk = SigningKey::from_bytes(&state.signing_key_bytes);
        forge_authority(&mut cmd, &sk, &state.kid).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("trust-plane PCA generation failed: {e}"),
                }),
            )
        })?;
    }

    let now = Utc::now();
    match state.config.validate(&cmd, now, None) {
        Ok(result) => {
            Ok(Json(ValidateResponse {
                verdict: result.signed_verdict,
                actuation_command: result.actuation_command,
            }))
        }
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("validation error: {e}"),
            }),
        )),
    }
}

async fn handle_heartbeat(
    State(state): State<Arc<AppState>>,
) -> Result<Json<HeartbeatResponse>, (StatusCode, Json<ErrorResponse>)> {
    let watchdog_mutex = state.watchdog.as_ref().ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "watchdog is disabled".to_string(),
            }),
        )
    })?;

    let mut inner = watchdog_mutex.lock().await;
    let now_ms = inner.now_ms();
    match inner.watchdog.heartbeat(now_ms) {
        Ok(()) => Ok(Json(HeartbeatResponse {
            status: "ok".to_string(),
            watchdog_state: "armed".to_string(),
        })),
        Err(e) => Err((
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )),
    }
}

async fn handle_health(State(state): State<Arc<AppState>>) -> Json<HealthResponse> {
    let uptime_ms = state.boot_instant.elapsed().as_millis() as u64;

    let (watchdog_enabled, watchdog_state) = if let Some(ref wd) = state.watchdog {
        let inner = wd.lock().await;
        let state_str = match inner.watchdog.state() {
            WatchdogState::Armed => "armed",
            WatchdogState::Triggered => "triggered",
        };
        (true, Some(state_str.to_string()))
    } else {
        (false, None)
    };

    Json(HealthResponse {
        status: "ok".to_string(),
        profile_name: state.config.profile().name.clone(),
        trust_plane: state.trust_plane,
        watchdog_enabled,
        watchdog_state,
        uptime_ms,
    })
}

// ---------------------------------------------------------------------------
// Forge helper (mirrors validate.rs logic)
// ---------------------------------------------------------------------------

fn forge_authority(cmd: &mut Command, signing_key: &SigningKey, kid: &str) -> Result<(), String> {
    let ops = cmd.authority.required_ops.iter().cloned().collect();

    let pca = Pca {
        p_0: "trust-plane".to_string(),
        ops,
        kid: kid.to_string(),
        exp: None,
        nbf: None,
    };

    let signed = sign_pca(&pca, signing_key).map_err(|e| e.to_string())?;
    let chain = vec![signed];
    let chain_json = serde_json::to_vec(&chain).map_err(|e| e.to_string())?;
    cmd.authority.pca_chain = STANDARD.encode(&chain_json);

    Ok(())
}

// ---------------------------------------------------------------------------
// Server entry point
// ---------------------------------------------------------------------------

pub fn run(args: &ServeArgs) -> i32 {
    // Build a tokio runtime and block on the async server.
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("error: failed to create tokio runtime: {e}");
            return 2;
        }
    };

    rt.block_on(async { run_server(args).await })
}

async fn run_server(args: &ServeArgs) -> i32 {
    // Load profile.
    let profile_json = match std::fs::read_to_string(&args.profile) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: failed to read profile {:?}: {e}", args.profile);
            return 2;
        }
    };
    let profile = match invariant_core::profiles::load_from_json(&profile_json) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: invalid profile: {e}");
            return 2;
        }
    };

    // Load key file.
    let kf = match crate::key_file::load_key_file(&args.key) {
        Ok(kf) => kf,
        Err(e) => {
            eprintln!("error: {e}");
            return 2;
        }
    };
    let (signing_key, verifying_key, kid) = match crate::key_file::load_signing_key(&kf) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: {e}");
            return 2;
        }
    };

    let signing_key_bytes = signing_key.to_bytes();

    // Build trusted keys.
    let mut trusted_keys = HashMap::new();
    trusted_keys.insert(kid.clone(), verifying_key);

    // Build validator config.
    let config = match ValidatorConfig::new(profile, trusted_keys, signing_key, kid.clone()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return 2;
        }
    };

    let boot_instant = Instant::now();

    // Optionally create watchdog.
    let watchdog = if args.watchdog_timeout_ms > 0 {
        let safe_stop = config.profile().safe_stop_profile.clone();
        let wd_sk = SigningKey::from_bytes(&signing_key_bytes);
        let wd = Watchdog::new(
            args.watchdog_timeout_ms,
            safe_stop,
            wd_sk,
            kid.clone(),
            0,
        );
        Some(Mutex::new(WatchdogInner {
            watchdog: wd,
            boot_instant,
        }))
    } else {
        None
    };

    let state = Arc::new(AppState {
        config,
        trust_plane: args.trust_plane,
        signing_key_bytes,
        kid,
        watchdog,
        boot_instant,
    });

    let app = Router::new()
        .route("/validate", post(handle_validate))
        .route("/heartbeat", post(handle_heartbeat))
        .route("/health", get(handle_health))
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], args.port));
    eprintln!(
        "invariant serve: listening on http://{}:{} (trust_plane={})",
        addr.ip(),
        addr.port(),
        args.trust_plane
    );

    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("error: failed to bind to {addr}: {e}");
            return 2;
        }
    };

    if let Err(e) = axum::serve(listener, app).await {
        eprintln!("error: server error: {e}");
        return 2;
    }

    0
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use ed25519_dalek::SigningKey;
    use invariant_core::models::authority::Operation;
    use invariant_core::models::command::{CommandAuthority, JointState};
    use rand::rngs::OsRng;
    use tower::ServiceExt;

    fn make_test_state(trust_plane: bool, watchdog_timeout_ms: u64) -> Arc<AppState> {
        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();
        let kid = "test-serve-kid".to_string();
        let signing_key_bytes = sk.to_bytes();

        let profile_json = invariant_core::profiles::list_builtins()
            .first()
            .map(|name| {
                let p = invariant_core::profiles::load_builtin(name).unwrap();
                serde_json::to_string(&p).unwrap()
            })
            .unwrap();
        let profile = invariant_core::profiles::load_from_json(&profile_json).unwrap();

        let mut trusted_keys = HashMap::new();
        trusted_keys.insert(kid.clone(), vk);

        let config =
            ValidatorConfig::new(profile, trusted_keys, sk, kid.clone()).unwrap();

        let boot_instant = Instant::now();

        let watchdog = if watchdog_timeout_ms > 0 {
            let safe_stop = config.profile().safe_stop_profile.clone();
            let wd_sk = SigningKey::from_bytes(&signing_key_bytes);
            let wd = Watchdog::new(
                watchdog_timeout_ms,
                safe_stop,
                wd_sk,
                kid.clone(),
                0,
            );
            Some(Mutex::new(WatchdogInner {
                watchdog: wd,
                boot_instant,
            }))
        } else {
            None
        };

        Arc::new(AppState {
            config,
            trust_plane,
            signing_key_bytes,
            kid,
            watchdog,
            boot_instant,
        })
    }

    fn make_app(state: Arc<AppState>) -> Router {
        Router::new()
            .route("/validate", post(handle_validate))
            .route("/heartbeat", post(handle_heartbeat))
            .route("/health", get(handle_health))
            .with_state(state)
    }

    fn make_test_command() -> Command {
        Command {
            timestamp: Utc::now(),
            source: "test".to_string(),
            sequence: 1,
            joint_states: vec![JointState {
                name: "joint_0".to_string(),
                position: 0.0,
                velocity: 0.0,
                effort: 0.0,
            }],
            delta_time: 0.01,
            end_effector_positions: vec![],
            center_of_mass: None,
            authority: CommandAuthority {
                pca_chain: String::new(),
                required_ops: vec![Operation::new("actuate:humanoid_28dof:joint_0:position").unwrap()],
            },
            metadata: HashMap::new(),
        }
    }

    // --- Health endpoint ---

    #[tokio::test]
    async fn health_returns_ok() {
        let state = make_test_state(false, 0);
        let app = make_app(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
        let health: HealthResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(health.status, "ok");
        assert!(!health.trust_plane);
        assert!(!health.watchdog_enabled);
    }

    #[tokio::test]
    async fn health_shows_trust_plane_and_watchdog() {
        let state = make_test_state(true, 500);
        let app = make_app(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
        let health: HealthResponse = serde_json::from_slice(&body).unwrap();
        assert!(health.trust_plane);
        assert!(health.watchdog_enabled);
        assert_eq!(health.watchdog_state, Some("armed".to_string()));
    }

    // --- Validate endpoint ---

    #[tokio::test]
    async fn validate_with_trust_plane_returns_verdict() {
        let state = make_test_state(true, 0);
        let app = make_app(state);

        let cmd = make_test_command();
        let body = serde_json::to_string(&ValidateRequest { command: cmd }).unwrap();

        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/validate")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
        let result: ValidateResponse = serde_json::from_slice(&body).unwrap();
        // Trust-plane auto-signs PCA, so authority should pass.
        // The verdict may still be rejected due to physics checks depending on
        // the profile, but we should at least get a well-formed response.
        assert!(!result.verdict.verdict.command_hash.is_empty());
    }

    #[tokio::test]
    async fn validate_without_trust_plane_and_no_chain_rejects() {
        let state = make_test_state(false, 0);
        let app = make_app(state);

        let cmd = make_test_command();
        let body = serde_json::to_string(&ValidateRequest { command: cmd }).unwrap();

        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/validate")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
        let result: ValidateResponse = serde_json::from_slice(&body).unwrap();
        // No PCA chain provided, should be rejected.
        assert!(!result.verdict.verdict.approved);
    }

    #[tokio::test]
    async fn validate_invalid_json_returns_error() {
        let state = make_test_state(true, 0);
        let app = make_app(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/validate")
                    .header("content-type", "application/json")
                    .body(Body::from("{not valid json}"))
                    .unwrap(),
            )
            .await
            .unwrap();

        // axum returns 4xx for JSON parse errors.
        assert!(resp.status().is_client_error());
    }

    // --- Heartbeat endpoint ---

    #[tokio::test]
    async fn heartbeat_with_watchdog_returns_ok() {
        let state = make_test_state(false, 5000);
        let app = make_app(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/heartbeat")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
        let hb: HeartbeatResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(hb.status, "ok");
        assert_eq!(hb.watchdog_state, "armed");
    }

    #[tokio::test]
    async fn heartbeat_without_watchdog_returns_error() {
        let state = make_test_state(false, 0);
        let app = make_app(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/heartbeat")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    // --- Request body size ---

    #[tokio::test]
    async fn validate_empty_body_returns_error() {
        let state = make_test_state(true, 0);
        let app = make_app(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/validate")
                    .header("content-type", "application/json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Empty body should fail JSON parsing.
        assert!(resp.status().is_client_error());
    }
}
