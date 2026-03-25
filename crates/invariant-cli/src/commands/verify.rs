use base64::{engine::general_purpose::STANDARD, Engine};
use clap::Args;
use ed25519_dalek::VerifyingKey;
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Args)]
pub struct VerifyArgs {
    #[arg(long, value_name = "LOG_FILE")]
    pub log: PathBuf,
    #[arg(long, value_name = "PUBKEY_FILE")]
    pub pubkey: PathBuf,
}

#[derive(Deserialize)]
struct KeyFile {
    verifying_key: String,
}

pub fn run(args: &VerifyArgs) -> i32 {
    // Read and parse the public key file.
    let pubkey_data = match std::fs::read_to_string(&args.pubkey) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "invariant verify: failed to read pubkey file {}: {e}",
                args.pubkey.display()
            );
            return 1;
        }
    };

    let key_file: KeyFile = match serde_json::from_str(&pubkey_data) {
        Ok(k) => k,
        Err(e) => {
            eprintln!(
                "invariant verify: failed to parse pubkey file {}: {e}",
                args.pubkey.display()
            );
            return 1;
        }
    };

    let vk_bytes = match STANDARD.decode(&key_file.verifying_key) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("invariant verify: failed to base64-decode verifying_key: {e}");
            return 1;
        }
    };

    let vk_array: [u8; 32] = match vk_bytes.try_into() {
        Ok(a) => a,
        Err(_) => {
            eprintln!("invariant verify: verifying_key must be exactly 32 bytes");
            return 1;
        }
    };

    let verifying_key = match VerifyingKey::from_bytes(&vk_array) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("invariant verify: invalid verifying key: {e}");
            return 1;
        }
    };

    // Read the audit log file.
    let log_content = match std::fs::read_to_string(&args.log) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "invariant verify: failed to read log file {}: {e}",
                args.log.display()
            );
            return 1;
        }
    };

    // Verify the audit log.
    match invariant_core::audit::verify_log(&log_content, &verifying_key) {
        Ok(n) => {
            println!(
                "Audit log verified: {n} entries, hash chain intact, all signatures valid."
            );
            0
        }
        Err(e) => {
            eprintln!("invariant verify: {e}");
            1
        }
    }
}
