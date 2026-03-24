// Append-only signed JSONL audit logger.
//
// Enforces four invariants:
//   L1 Completeness  — every command produces a signed verdict entry.
//   L2 Ordering      — SHA-256 hash chain links each entry to its predecessor.
//   L3 Authenticity  — each entry is Ed25519-signed by the Invariant instance.
//   L4 Immutability  — append-only; no seek, no truncate.

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::Path;

use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::models::audit::{AuditEntry, SignedAuditEntry};
use crate::models::command::Command;
use crate::models::verdict::SignedVerdict;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors from audit log operations.
#[derive(Debug, Error, PartialEq)]
pub enum AuditError {
    #[error("serialization failed: {reason}")]
    Serialization { reason: String },

    #[error("I/O error: {0}")]
    IoError(String),

    #[error("verification failed at sequence {sequence}: {reason}")]
    VerificationFailed { sequence: u64, reason: String },
}

// ---------------------------------------------------------------------------
// Internal helper: hash payload struct (AuditEntry without entry_hash)
// ---------------------------------------------------------------------------

/// Serializable payload for computing entry_hash.
///
/// Contains all `AuditEntry` fields **except** `entry_hash`. We hash this to
/// avoid a circularity (you cannot include the hash inside what you hash).
#[derive(Serialize)]
struct AuditEntryPayload<'a> {
    sequence: u64,
    previous_hash: &'a str,
    command: &'a Command,
    verdict: &'a SignedVerdict,
}

// ---------------------------------------------------------------------------
// sha256_hex helper (mirrors the private helper in validator.rs)
// ---------------------------------------------------------------------------

fn sha256_hex(data: &[u8]) -> String {
    let hash = Sha256::digest(data);
    let hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
    format!("sha256:{hex}")
}

// ---------------------------------------------------------------------------
// AuditLogger
// ---------------------------------------------------------------------------

/// Append-only signed JSONL audit logger.
///
/// Each `log()` call writes exactly one JSONL line (one JSON object followed
/// by `\n`). The file is opened with `O_APPEND` so concurrent writers or
/// crashes cannot corrupt existing entries (L4).
pub struct AuditLogger {
    signing_key: SigningKey,
    signer_kid: String,
    next_sequence: u64,
    previous_hash: String,
    writer: BufWriter<File>,
}

impl AuditLogger {
    /// Create (or reopen and append to) the audit log at `path`.
    ///
    /// The first entry will have `sequence: 0` and `previous_hash: ""` (the
    /// genesis sentinel). If the file already exists its content is preserved
    /// and new entries are appended.
    pub fn new(
        path: impl AsRef<Path>,
        signing_key: SigningKey,
        signer_kid: String,
    ) -> Result<Self, AuditError> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| AuditError::IoError(e.to_string()))?;

        Ok(Self {
            signing_key,
            signer_kid,
            next_sequence: 0,
            previous_hash: String::new(),
            writer: BufWriter::new(file),
        })
    }

    // -----------------------------------------------------------------------
    // Getters (used by tests)
    // -----------------------------------------------------------------------

    /// Current sequence number that will be used for the *next* entry.
    pub fn sequence(&self) -> u64 {
        self.next_sequence
    }

    /// Hash of the most recently written entry (`""` before any entries).
    pub fn previous_hash(&self) -> &str {
        &self.previous_hash
    }

    // -----------------------------------------------------------------------
    // Core operation
    // -----------------------------------------------------------------------

    /// Append one signed audit entry for the given command and verdict.
    ///
    /// Steps (per spec data-flow 7):
    /// 1. Build an `AuditEntryPayload` (no `entry_hash`) and compute its
    ///    SHA-256 hash — this becomes `entry_hash`.
    /// 2. Build the full `AuditEntry` including `entry_hash`.
    /// 3. Ed25519-sign the canonical JSON of the full `AuditEntry`.
    /// 4. Write one JSONL line and flush.
    /// 5. Advance `next_sequence` and `previous_hash`.
    pub fn log(
        &mut self,
        command: &Command,
        verdict: &SignedVerdict,
    ) -> Result<(), AuditError> {
        let sequence = self.next_sequence;
        let previous_hash = self.previous_hash.clone();

        // Step 1 — compute entry_hash over payload (without entry_hash field).
        let payload = AuditEntryPayload {
            sequence,
            previous_hash: &previous_hash,
            command,
            verdict,
        };
        let payload_json = serde_json::to_vec(&payload).map_err(|e| AuditError::Serialization {
            reason: e.to_string(),
        })?;
        let entry_hash = sha256_hex(&payload_json);

        // Step 2 — build the full AuditEntry.
        let entry = AuditEntry {
            sequence,
            previous_hash,
            command: command.clone(),
            verdict: verdict.clone(),
            entry_hash: entry_hash.clone(),
        };

        // Step 3 — sign the full AuditEntry (including entry_hash).
        let entry_json = serde_json::to_vec(&entry).map_err(|e| AuditError::Serialization {
            reason: e.to_string(),
        })?;
        let signature = self.signing_key.sign(&entry_json);
        let entry_signature = STANDARD.encode(signature.to_bytes());

        // Step 4 — build SignedAuditEntry, serialize to JSONL, flush.
        let signed = SignedAuditEntry {
            entry,
            entry_signature,
            signer_kid: self.signer_kid.clone(),
        };
        let line = serde_json::to_vec(&signed).map_err(|e| AuditError::Serialization {
            reason: e.to_string(),
        })?;
        self.writer
            .write_all(&line)
            .map_err(|e| AuditError::IoError(e.to_string()))?;
        self.writer
            .write_all(b"\n")
            .map_err(|e| AuditError::IoError(e.to_string()))?;
        self.writer
            .flush()
            .map_err(|e| AuditError::IoError(e.to_string()))?;

        // Step 5 — advance state.
        self.next_sequence += 1;
        self.previous_hash = entry_hash;

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// verify_audit_log
// ---------------------------------------------------------------------------

/// Verify every entry in a JSONL audit log file.
///
/// Checks (in order for each entry):
/// - Sequence numbers start at 0 and are strictly sequential.
/// - First entry has `previous_hash == ""`.
/// - Each entry's `previous_hash` matches the prior entry's `entry_hash`.
/// - `entry_hash` is the correct SHA-256 of the entry payload.
/// - `entry_signature` is a valid Ed25519 signature over the `AuditEntry`.
///
/// Returns `Ok(n)` where `n` is the number of verified entries, or
/// `Err(AuditError::VerificationFailed { sequence, reason })` on the first
/// failing entry.
pub fn verify_audit_log(
    path: impl AsRef<Path>,
    verifying_key: &ed25519_dalek::VerifyingKey,
) -> Result<u64, AuditError> {
    use std::io::{BufRead, BufReader};

    let file = File::open(path).map_err(|e| AuditError::IoError(e.to_string()))?;
    let reader = BufReader::new(file);

    let mut expected_sequence: u64 = 0;
    let mut expected_previous_hash = String::new();
    let mut count: u64 = 0;

    for line in reader.lines() {
        let line = line.map_err(|e| AuditError::IoError(e.to_string()))?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // Parse the signed entry.
        let signed: SignedAuditEntry =
            serde_json::from_str(trimmed).map_err(|e| AuditError::VerificationFailed {
                sequence: expected_sequence,
                reason: format!("JSON parse failed: {e}"),
            })?;

        let seq = signed.entry.sequence;

        // Check sequence number.
        if seq != expected_sequence {
            return Err(AuditError::VerificationFailed {
                sequence: seq,
                reason: format!(
                    "expected sequence {expected_sequence}, got {seq}"
                ),
            });
        }

        // Check previous_hash (genesis must be empty).
        if signed.entry.previous_hash != expected_previous_hash {
            return Err(AuditError::VerificationFailed {
                sequence: seq,
                reason: format!(
                    "previous_hash mismatch: expected '{}', got '{}'",
                    expected_previous_hash, signed.entry.previous_hash
                ),
            });
        }

        // Recompute entry_hash from the payload (without entry_hash field).
        let payload = AuditEntryPayload {
            sequence: signed.entry.sequence,
            previous_hash: &signed.entry.previous_hash,
            command: &signed.entry.command,
            verdict: &signed.entry.verdict,
        };
        let payload_json =
            serde_json::to_vec(&payload).map_err(|e| AuditError::VerificationFailed {
                sequence: seq,
                reason: format!("payload serialization failed: {e}"),
            })?;
        let expected_hash = sha256_hex(&payload_json);

        if signed.entry.entry_hash != expected_hash {
            return Err(AuditError::VerificationFailed {
                sequence: seq,
                reason: format!(
                    "entry_hash mismatch: expected '{expected_hash}', got '{}'",
                    signed.entry.entry_hash
                ),
            });
        }

        // Verify Ed25519 signature over the full AuditEntry (including entry_hash).
        let entry_json =
            serde_json::to_vec(&signed.entry).map_err(|e| AuditError::VerificationFailed {
                sequence: seq,
                reason: format!("entry serialization failed: {e}"),
            })?;
        let sig_bytes =
            STANDARD
                .decode(&signed.entry_signature)
                .map_err(|e| AuditError::VerificationFailed {
                    sequence: seq,
                    reason: format!("base64 decode of signature failed: {e}"),
                })?;
        let signature = ed25519_dalek::Signature::from_slice(&sig_bytes).map_err(|e| {
            AuditError::VerificationFailed {
                sequence: seq,
                reason: format!("invalid signature bytes: {e}"),
            }
        })?;

        verifying_key
            .verify_strict(&entry_json, &signature)
            .map_err(|e| AuditError::VerificationFailed {
                sequence: seq,
                reason: format!("Ed25519 signature invalid: {e}"),
            })?;

        // Advance expected state.
        expected_previous_hash = signed.entry.entry_hash.clone();
        expected_sequence += 1;
        count += 1;
    }

    Ok(count)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::HashMap;
    use std::io::Write as IoWrite;

    use crate::authority::crypto::generate_keypair;
    use crate::models::authority::Operation;
    use crate::models::command::{Command, CommandAuthority, JointState};
    use crate::models::verdict::{AuthoritySummary, CheckResult, SignedVerdict, Verdict};
    use chrono::Utc;
    use ed25519_dalek::VerifyingKey;
    use rand::rngs::OsRng;
    use tempfile::NamedTempFile;

    // -----------------------------------------------------------------------
    // Test helpers
    // -----------------------------------------------------------------------

    fn make_signing_key() -> (SigningKey, VerifyingKey) {
        let sk = generate_keypair(&mut OsRng);
        let vk = sk.verifying_key();
        (sk, vk)
    }

    fn test_command(sequence: u64) -> Command {
        Command {
            timestamp: Utc::now(),
            source: "test-source".into(),
            sequence,
            joint_states: vec![JointState {
                name: "j1".into(),
                position: 0.1,
                velocity: 0.5,
                effort: 5.0,
            }],
            delta_time: 0.01,
            end_effector_positions: vec![],
            center_of_mass: None,
            authority: CommandAuthority {
                pca_chain: "dGVzdA==".into(), // base64("test")
                required_ops: vec![Operation::new("actuate:j1").unwrap()],
            },
            metadata: HashMap::new(),
        }
    }

    fn test_verdict(sequence: u64, signing_key: &SigningKey) -> SignedVerdict {
        let verdict = Verdict {
            approved: true,
            command_hash: format!("sha256:{:064x}", sequence),
            command_sequence: sequence,
            timestamp: Utc::now(),
            checks: vec![CheckResult {
                name: "authority".into(),
                category: "authority".into(),
                passed: true,
                details: "ok".into(),
            }],
            profile_name: "test_robot".into(),
            profile_hash: "sha256:abc".into(),
            authority_summary: AuthoritySummary {
                origin_principal: "alice".into(),
                hop_count: 1,
                operations_granted: vec!["actuate:*".into()],
                operations_required: vec!["actuate:j1".into()],
            },
        };
        let verdict_json = serde_json::to_vec(&verdict).unwrap();
        let sig = signing_key.sign(&verdict_json);
        SignedVerdict {
            verdict,
            verdict_signature: STANDARD.encode(sig.to_bytes()),
            signer_kid: "test-kid".into(),
        }
    }

    fn write_n_entries(
        logger: &mut AuditLogger,
        signing_key: &SigningKey,
        n: u64,
    ) {
        for i in 0..n {
            let cmd = test_command(i);
            let v = test_verdict(i, signing_key);
            logger.log(&cmd, &v).expect("log should succeed");
        }
    }

    // -----------------------------------------------------------------------
    // Tests
    // -----------------------------------------------------------------------

    #[test]
    fn genesis_entry_has_empty_previous_hash() {
        let (sk, _) = make_signing_key();
        let tmp = NamedTempFile::new().unwrap();
        let mut logger = AuditLogger::new(tmp.path(), sk.clone(), "kid-1".into()).unwrap();

        assert_eq!(logger.sequence(), 0);
        assert_eq!(logger.previous_hash(), "");

        let cmd = test_command(0);
        let v = test_verdict(0, &sk);
        logger.log(&cmd, &v).unwrap();

        // Read the single line back.
        let content = std::fs::read_to_string(tmp.path()).unwrap();
        let signed: SignedAuditEntry =
            serde_json::from_str(content.trim()).unwrap();

        assert_eq!(signed.entry.sequence, 0);
        assert_eq!(signed.entry.previous_hash, "");
    }

    #[test]
    fn sequence_increments() {
        let (sk, _) = make_signing_key();
        let tmp = NamedTempFile::new().unwrap();
        let mut logger = AuditLogger::new(tmp.path(), sk.clone(), "kid-1".into()).unwrap();

        write_n_entries(&mut logger, &sk, 3);

        assert_eq!(logger.sequence(), 3);

        let content = std::fs::read_to_string(tmp.path()).unwrap();
        let entries: Vec<SignedAuditEntry> = content
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();

        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].entry.sequence, 0);
        assert_eq!(entries[1].entry.sequence, 1);
        assert_eq!(entries[2].entry.sequence, 2);
    }

    #[test]
    fn hash_chain_links_entries() {
        let (sk, _) = make_signing_key();
        let tmp = NamedTempFile::new().unwrap();
        let mut logger = AuditLogger::new(tmp.path(), sk.clone(), "kid-1".into()).unwrap();

        write_n_entries(&mut logger, &sk, 3);

        let content = std::fs::read_to_string(tmp.path()).unwrap();
        let entries: Vec<SignedAuditEntry> = content
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();

        // Entry 0: genesis.
        assert_eq!(entries[0].entry.previous_hash, "");
        // Entry 1: previous_hash == entry 0's entry_hash.
        assert_eq!(entries[1].entry.previous_hash, entries[0].entry.entry_hash);
        // Entry 2: previous_hash == entry 1's entry_hash.
        assert_eq!(entries[2].entry.previous_hash, entries[1].entry.entry_hash);
    }

    #[test]
    fn entry_signatures_are_verifiable() {
        let (sk, vk) = make_signing_key();
        let tmp = NamedTempFile::new().unwrap();
        let mut logger = AuditLogger::new(tmp.path(), sk.clone(), "kid-1".into()).unwrap();

        write_n_entries(&mut logger, &sk, 3);

        let content = std::fs::read_to_string(tmp.path()).unwrap();
        let entries: Vec<SignedAuditEntry> = content
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();

        for signed in &entries {
            let entry_json = serde_json::to_vec(&signed.entry).unwrap();
            let sig_bytes = STANDARD.decode(&signed.entry_signature).unwrap();
            let signature = ed25519_dalek::Signature::from_slice(&sig_bytes).unwrap();
            assert!(
                vk.verify_strict(&entry_json, &signature).is_ok(),
                "signature invalid for sequence {}",
                signed.entry.sequence
            );
        }
    }

    #[test]
    fn verify_audit_log_succeeds() {
        let (sk, vk) = make_signing_key();
        let tmp = NamedTempFile::new().unwrap();
        let mut logger = AuditLogger::new(tmp.path(), sk.clone(), "kid-1".into()).unwrap();

        write_n_entries(&mut logger, &sk, 5);

        let count = verify_audit_log(tmp.path(), &vk).expect("verify should succeed");
        assert_eq!(count, 5);
    }

    #[test]
    fn tampered_entry_fails_verification() {
        let (sk, vk) = make_signing_key();
        let tmp = NamedTempFile::new().unwrap();
        let mut logger = AuditLogger::new(tmp.path(), sk.clone(), "kid-1".into()).unwrap();

        write_n_entries(&mut logger, &sk, 3);

        // Read all lines, tamper with the second entry's entry_hash.
        let content = std::fs::read_to_string(tmp.path()).unwrap();
        let mut lines: Vec<String> = content
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| l.to_string())
            .collect();

        // Tamper: replace entry_hash in line 1 with a bogus value.
        let mut entry: SignedAuditEntry = serde_json::from_str(&lines[1]).unwrap();
        entry.entry.entry_hash = "sha256:0000000000000000000000000000000000000000000000000000000000000000".into();
        lines[1] = serde_json::to_string(&entry).unwrap();

        // Write tampered content to a new temp file.
        let mut tampered = NamedTempFile::new().unwrap();
        for l in &lines {
            writeln!(tampered, "{}", l).unwrap();
        }
        tampered.flush().unwrap();

        let result = verify_audit_log(tampered.path(), &vk);
        assert!(
            result.is_err(),
            "tampered log should fail verification"
        );
    }

    #[test]
    fn deterministic_hashes() {
        // The same command + verdict at the same sequence must produce the
        // same entry_hash regardless of how many times we compute it.
        let (sk, _) = make_signing_key();

        let cmd = test_command(0);
        let v = test_verdict(0, &sk);

        let payload = AuditEntryPayload {
            sequence: 0,
            previous_hash: "",
            command: &cmd,
            verdict: &v,
        };

        let json1 = serde_json::to_vec(&payload).unwrap();
        let json2 = serde_json::to_vec(&payload).unwrap();

        assert_eq!(json1, json2);
        assert_eq!(sha256_hex(&json1), sha256_hex(&json2));
    }
}
