use clap::Args;
use std::fs;
use std::io::{self, BufRead};
use std::path::PathBuf;

use invariant_core::models::audit::SignedAuditEntry;

#[derive(Args)]
pub struct AuditArgs {
    #[arg(long, value_name = "LOG_FILE")]
    pub log: PathBuf,
    #[arg(long)]
    pub last: Option<usize>,
}

pub fn run(args: &AuditArgs) -> i32 {
    let file = match fs::File::open(&args.log) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("invariant audit: failed to open log file '{}': {}", args.log.display(), e);
            return 2;
        }
    };

    let reader = io::BufReader::new(file);
    let mut entries: Vec<SignedAuditEntry> = Vec::new();

    for (line_no, line_result) in reader.lines().enumerate() {
        let line = match line_result {
            Ok(l) => l,
            Err(e) => {
                eprintln!("invariant audit: error reading line {}: {}", line_no + 1, e);
                return 2;
            }
        };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        match serde_json::from_str::<SignedAuditEntry>(trimmed) {
            Ok(entry) => entries.push(entry),
            Err(e) => {
                eprintln!("invariant audit: failed to parse line {}: {}", line_no + 1, e);
                return 2;
            }
        }
    }

    let total = entries.len();

    let display_entries: &[SignedAuditEntry] = match args.last {
        Some(n) => {
            let start = total.saturating_sub(n);
            &entries[start..]
        }
        None => &entries,
    };

    for (display_idx, signed_entry) in display_entries.iter().enumerate() {
        let entry = &signed_entry.entry;
        let approved = entry.verdict.verdict.approved;
        let cmd_seq = entry.command.sequence;
        let source = &entry.command.source;

        // Truncate hash to "sha256:" prefix + first 16 hex chars of the digest portion.
        let hash_display = format_hash(&entry.entry_hash);

        println!(
            "[{display_idx}] seq={seq} approved={approved:<5} cmd_seq={cmd_seq} source=\"{source}\" hash={hash}",
            display_idx = display_idx,
            seq = entry.sequence,
            approved = approved,
            cmd_seq = cmd_seq,
            source = source,
            hash = hash_display,
        );
    }

    let displayed = display_entries.len();
    println!("{displayed} entries displayed ({total} total)");

    0
}

/// Format the entry hash for display. If it starts with "sha256:" the digest
/// portion is truncated to 16 hex characters followed by "...". Otherwise the
/// full string is returned unchanged.
fn format_hash(raw: &str) -> String {
    const PREFIX: &str = "sha256:";
    const DISPLAY_LEN: usize = 16;

    if let Some(digest) = raw.strip_prefix(PREFIX) {
        let truncated = &digest[..digest.len().min(DISPLAY_LEN)];
        if digest.len() > DISPLAY_LEN {
            format!("{PREFIX}{truncated}...")
        } else {
            format!("{PREFIX}{truncated}")
        }
    } else {
        raw.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_hash_truncates_long_digest() {
        let hash = "sha256:abcdef1234567890deadbeef";
        let result = format_hash(hash);
        // First 16 hex chars of the digest are "abcdef1234567890"
        assert_eq!(result, "sha256:abcdef1234567890...");
    }

    #[test]
    fn format_hash_keeps_short_digest() {
        let hash = "sha256:abcd";
        let result = format_hash(hash);
        assert_eq!(result, "sha256:abcd");
    }

    #[test]
    fn format_hash_exactly_16_chars() {
        let hash = "sha256:1234567890abcdef";
        let result = format_hash(hash);
        assert_eq!(result, "sha256:1234567890abcdef");
    }

    #[test]
    fn format_hash_no_prefix_returned_as_is() {
        let hash = "md5:abc123";
        let result = format_hash(hash);
        assert_eq!(result, "md5:abc123");
    }
}
