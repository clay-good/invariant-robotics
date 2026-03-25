use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::Utc;
use clap::Args;
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use invariant_core::models::actuation::SignedActuationCommand;
use invariant_core::models::command::{Command, JointState};
use invariant_core::models::profile::RobotProfile;
use invariant_core::models::verdict::SignedVerdict;
use invariant_core::validator::ValidatorConfig;
use invariant_core::watchdog::{Watchdog, WatchdogConfig, WatchdogState, WatchdogStatus};

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
}

// ---------------------------------------------------------------------------
// Shared server state
// ---------------------------------------------------------------------------

struct ServerState {
    config: ValidatorConfig,
    watchdog: Mutex<Watchdog>,
    previous_joints: Mutex<Option<Vec<JointState>>>,
    signing_key: SigningKey,
    signer_kid: String,
}

// ---------------------------------------------------------------------------
// Request/response types
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct ValidateResponse {
    signed_verdict: SignedVerdict,
    #[serde(skip_serializing_if = "Option::is_none")]
    signed_actuation_command: Option<SignedActuationCommand>,
}

#[derive(Serialize, Deserialize)]
struct HeartbeatResponse {
    status: String,
}

#[derive(Serialize, Deserialize)]
struct HealthResponse {
    status: String,
    watchdog_state: String,
    watchdog_triggers: u64,
    profile_name: String,
    signer_kid: String,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

// ---------------------------------------------------------------------------
// Key file
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct KeyFile {
    kid: String,
    signing_key: String,
    verifying_key: String,
}

fn decode_signing_key(b64: &str) -> Result<SigningKey, String> {
    let bytes = STANDARD
        .decode(b64)
        .map_err(|e| format!("failed to base64-decode signing_key: {e}"))?;
    let array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "signing_key must be exactly 32 bytes".to_string())?;
    Ok(SigningKey::from_bytes(&array))
}

fn decode_verifying_key(b64: &str) -> Result<VerifyingKey, String> {
    let bytes = STANDARD
        .decode(b64)
        .map_err(|e| format!("failed to base64-decode verifying_key: {e}"))?;
    let array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "verifying_key must be exactly 32 bytes".to_string())?;
    VerifyingKey::from_bytes(&array).map_err(|e| format!("invalid verifying key: {e}"))
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn handle_validate(
    State(state): State<Arc<ServerState>>,
    Json(command): Json<Command>,
) -> Result<Json<ValidateResponse>, (StatusCode, Json<ErrorResponse>)> {
    let now = Utc::now();

    // Get previous joints for delta checks.
    let previous_joints = {
        let guard = state.previous_joints.lock().unwrap();
        guard.clone()
    };

    let result = state
        .config
        .validate(&command, now, previous_joints.as_deref())
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: e.to_string(),
                }),
            )
        })?;

    // Update previous joints for next call.
    {
        let mut guard = state.previous_joints.lock().unwrap();
        *guard = Some(command.joint_states.clone());
    }

    // Feed watchdog heartbeat on successful validation (command received).
    {
        let mut wd = state.watchdog.lock().unwrap();
        wd.heartbeat();
    }

    Ok(Json(ValidateResponse {
        signed_verdict: result.signed_verdict,
        signed_actuation_command: result.actuation_command,
    }))
}

async fn handle_heartbeat(
    State(state): State<Arc<ServerState>>,
) -> Json<HeartbeatResponse> {
    let mut wd = state.watchdog.lock().unwrap();
    wd.heartbeat();
    let status = match wd.state() {
        WatchdogState::Active => "ok",
        WatchdogState::SafeStopTriggered => "safe_stop_triggered",
        WatchdogState::ManuallyReset => "manually_reset",
    };
    Json(HeartbeatResponse {
        status: status.to_string(),
    })
}

async fn handle_health(
    State(state): State<Arc<ServerState>>,
) -> Json<HealthResponse> {
    let wd = state.watchdog.lock().unwrap();
    let watchdog_state = match wd.state() {
        WatchdogState::Active => "active",
        WatchdogState::SafeStopTriggered => "safe_stop_triggered",
        WatchdogState::ManuallyReset => "manually_reset",
    };
    Json(HealthResponse {
        status: "ok".to_string(),
        watchdog_state: watchdog_state.to_string(),
        watchdog_triggers: wd.trigger_count(),
        profile_name: state.config.profile().name.clone(),
        signer_kid: state.config.signer_kid().to_string(),
    })
}

async fn handle_watchdog_status(
    State(state): State<Arc<ServerState>>,
) -> Json<WatchdogStatusResponse> {
    let mut wd = state.watchdog.lock().unwrap();
    let check = wd.check();
    let (status, safe_stop_command) = match check {
        WatchdogStatus::Ok => ("ok".to_string(), None),
        WatchdogStatus::SafeStopRequired { safe_stop_profile } => {
            // Build safe-stop command.
            let cmd = invariant_core::watchdog::build_safe_stop_command(
                &safe_stop_profile,
                wd.trigger_count(),
                &state.signing_key,
                &state.signer_kid,
                Utc::now(),
            )
            .ok();
            ("safe_stop_required".to_string(), cmd)
        }
        WatchdogStatus::AlreadyTriggered => ("already_triggered".to_string(), None),
    };
    Json(WatchdogStatusResponse {
        status,
        trigger_count: wd.trigger_count(),
        safe_stop_command,
    })
}

#[derive(Serialize, Deserialize)]
struct WatchdogStatusResponse {
    status: String,
    trigger_count: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    safe_stop_command: Option<SignedActuationCommand>,
}

// ---------------------------------------------------------------------------
// Server entry point
// ---------------------------------------------------------------------------

pub fn run(args: &ServeArgs) -> i32 {
    // Load key file.
    let key_data = match std::fs::read_to_string(&args.key) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("invariant serve: failed to read key file: {e}");
            return 2;
        }
    };
    let key_file: KeyFile = match serde_json::from_str(&key_data) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("invariant serve: failed to parse key file: {e}");
            return 2;
        }
    };

    let signing_key = match decode_signing_key(&key_file.signing_key) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("invariant serve: {e}");
            return 2;
        }
    };
    let verifying_key = match decode_verifying_key(&key_file.verifying_key) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("invariant serve: {e}");
            return 2;
        }
    };

    let mut trusted_keys = HashMap::new();
    trusted_keys.insert(key_file.kid.clone(), verifying_key);

    // Load profile.
    let profile: RobotProfile = match invariant_core::profiles::load_from_file(&args.profile) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("invariant serve: failed to load profile: {e}");
            return 2;
        }
    };

    // Build watchdog config from profile.
    let watchdog_config = WatchdogConfig {
        timeout: Duration::from_millis(profile.watchdog_timeout_ms),
        safe_stop_profile: profile.safe_stop_profile.clone(),
    };

    // Build validator config.
    let signer_kid = key_file.kid.clone();
    let config =
        match ValidatorConfig::new(profile, trusted_keys, signing_key.clone(), signer_kid.clone()) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("invariant serve: {e}");
                return 2;
            }
        };

    let state = Arc::new(ServerState {
        config,
        watchdog: Mutex::new(Watchdog::new(watchdog_config)),
        previous_joints: Mutex::new(None),
        signing_key,
        signer_kid,
    });

    let app = Router::new()
        .route("/validate", post(handle_validate))
        .route("/heartbeat", post(handle_heartbeat))
        .route("/health", get(handle_health))
        .route("/watchdog", get(handle_watchdog_status))
        .with_state(state);

    let addr = format!("0.0.0.0:{}", args.port);
    eprintln!(
        "invariant serve: listening on {addr}{}",
        if args.trust_plane {
            " (trust-plane mode)"
        } else {
            ""
        }
    );

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let listener = match tokio::net::TcpListener::bind(&addr).await {
            Ok(l) => l,
            Err(e) => {
                eprintln!("invariant serve: failed to bind {addr}: {e}");
                return;
            }
        };
        if let Err(e) = axum::serve(listener, app).await {
            eprintln!("invariant serve: server error: {e}");
        }
    });

    0
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{self, Request};
    use ed25519_dalek::SigningKey;
    use invariant_core::models::command::{Command, CommandAuthority, JointState};
    use invariant_core::models::profile::RobotProfile;
    use rand::rngs::OsRng;
    use std::collections::HashMap;
    use tower::ServiceExt; // for `oneshot`

    fn test_state() -> Arc<ServerState> {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let kid = "test-key".to_string();

        let mut trusted_keys = HashMap::new();
        trusted_keys.insert(kid.clone(), verifying_key);

        let profile: RobotProfile =
            serde_json::from_str(invariant_core::profiles::builtin_json("franka_panda").unwrap())
                .unwrap();

        let watchdog_config = WatchdogConfig {
            timeout: Duration::from_millis(profile.watchdog_timeout_ms),
            safe_stop_profile: profile.safe_stop_profile.clone(),
        };

        let config =
            ValidatorConfig::new(profile, trusted_keys, signing_key.clone(), kid.clone()).unwrap();

        Arc::new(ServerState {
            config,
            watchdog: Mutex::new(Watchdog::new(watchdog_config)),
            previous_joints: Mutex::new(None),
            signing_key,
            signer_kid: kid,
        })
    }

    fn test_app() -> Router {
        let state = test_state();
        Router::new()
            .route("/validate", post(handle_validate))
            .route("/heartbeat", post(handle_heartbeat))
            .route("/health", get(handle_health))
            .route("/watchdog", get(handle_watchdog_status))
            .with_state(state)
    }

    #[tokio::test]
    async fn health_endpoint_returns_ok() {
        let app = test_app();
        let req = Request::builder()
            .uri("/health")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), 1024 * 64)
            .await
            .unwrap();
        let health: HealthResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(health.status, "ok");
        assert_eq!(health.watchdog_state, "active");
        assert_eq!(health.watchdog_triggers, 0);
    }

    #[tokio::test]
    async fn heartbeat_endpoint_returns_ok() {
        let app = test_app();
        let req = Request::builder()
            .method(http::Method::POST)
            .uri("/heartbeat")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), 1024 * 64)
            .await
            .unwrap();
        let hb: HeartbeatResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(hb.status, "ok");
    }

    #[tokio::test]
    async fn validate_endpoint_rejects_invalid_command() {
        let app = test_app();

        // Build a minimal command that will fail authority (no valid PCA chain).
        let command = Command {
            timestamp: Utc::now(),
            source: "test".to_string(),
            sequence: 1,
            joint_states: vec![JointState {
                name: "panda_joint1".to_string(),
                position: 0.0,
                velocity: 0.0,
                effort: 0.0,
            }],
            delta_time: 0.01,
            end_effector_positions: vec![],
            center_of_mass: None,
            authority: CommandAuthority {
                pca_chain: "invalid-base64".to_string(),
                required_ops: vec![],
            },
            metadata: HashMap::new(),
        };

        let body = serde_json::to_string(&command).unwrap();
        let req = Request::builder()
            .method(http::Method::POST)
            .uri("/validate")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(resp.into_body(), 1024 * 64)
            .await
            .unwrap();
        let result: ValidateResponse = serde_json::from_slice(&body_bytes).unwrap();
        // Should be rejected (invalid authority chain).
        assert!(!result.signed_verdict.verdict.approved);
        assert!(result.signed_actuation_command.is_none());
    }

    #[tokio::test]
    async fn watchdog_endpoint_returns_ok() {
        let app = test_app();
        let req = Request::builder()
            .uri("/watchdog")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), 1024 * 64)
            .await
            .unwrap();
        let status: WatchdogStatusResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(status.status, "ok");
        assert_eq!(status.trigger_count, 0);
    }

    #[tokio::test]
    async fn validate_with_invalid_json_returns_error() {
        let app = test_app();
        let req = Request::builder()
            .method(http::Method::POST)
            .uri("/validate")
            .header("content-type", "application/json")
            .body(Body::from("{invalid json}"))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert!(resp.status().is_client_error());
    }
}
