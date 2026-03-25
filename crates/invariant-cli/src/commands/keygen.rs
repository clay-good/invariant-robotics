use base64::{engine::general_purpose::STANDARD, Engine};
use clap::Args;
use rand::rngs::OsRng;
use serde::Serialize;
use std::path::PathBuf;

#[derive(Args)]
pub struct KeygenArgs {
    #[arg(long)]
    pub kid: String,
    /// Output path for the key file. Validated at the OS level via PathBuf (P3-8, P3-9).
    #[arg(long, value_name = "OUTPUT_FILE")]
    pub output: PathBuf,
}

/// Serialization format for the generated key file.
#[derive(Serialize)]
struct KeyFile {
    kid: String,
    algorithm: String,
    signing_key: String,
    verifying_key: String,
}

pub fn run(args: &KeygenArgs) -> i32 {
    // Refuse to overwrite an existing file.
    if args.output.exists() {
        eprintln!(
            "invariant keygen: output file already exists: {}",
            args.output.display()
        );
        return 2;
    }

    // Generate a new Ed25519 keypair.
    let signing_key =
        invariant_core::authority::crypto::generate_keypair(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    let key_file = KeyFile {
        kid: args.kid.clone(),
        algorithm: "Ed25519".into(),
        signing_key: STANDARD.encode(signing_key.to_bytes()),
        verifying_key: STANDARD.encode(verifying_key.to_bytes()),
    };

    let json = match serde_json::to_string_pretty(&key_file) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("invariant keygen: serialization error: {e}");
            return 2;
        }
    };

    if let Err(e) = std::fs::write(&args.output, json) {
        eprintln!(
            "invariant keygen: failed to write {}: {e}",
            args.output.display()
        );
        return 2;
    }

    println!(
        "Generated key pair \"{}\" -> {}",
        args.kid,
        args.output.display()
    );
    0
}
