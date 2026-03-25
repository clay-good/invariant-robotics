// Deterministic eval presets: safety-check, completeness-check, regression-check.
//
// Each preset evaluates a Trace and returns an EvalReport containing per-step
// findings and an overall pass/fail verdict. Presets are pure functions — no I/O.

use invariant_core::models::trace::Trace;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum EvalError {
    #[error("unknown preset: {0}")]
    UnknownPreset(String),
}

// ---------------------------------------------------------------------------
// Preset names
// ---------------------------------------------------------------------------

/// Known preset names.
pub const PRESET_SAFETY_CHECK: &str = "safety-check";
pub const PRESET_COMPLETENESS_CHECK: &str = "completeness-check";
pub const PRESET_REGRESSION_CHECK: &str = "regression-check";

/// Returns the list of available preset names.
pub fn list_presets() -> &'static [&'static str] {
    &[
        PRESET_SAFETY_CHECK,
        PRESET_COMPLETENESS_CHECK,
        PRESET_REGRESSION_CHECK,
    ]
}

// ---------------------------------------------------------------------------
// Report types
// ---------------------------------------------------------------------------

/// A single finding from an eval preset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvalFinding {
    pub step: u64,
    pub severity: Severity,
    pub message: String,
}

/// Finding severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Error,
    Warning,
    Info,
}

/// Result of running an eval preset on a trace.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvalReport {
    pub preset: String,
    pub trace_id: String,
    pub passed: bool,
    pub findings: Vec<EvalFinding>,
    pub summary: String,
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

/// Run a named preset against a trace. Returns an error for unknown presets.
pub fn run_preset(name: &str, trace: &Trace) -> Result<EvalReport, EvalError> {
    match name {
        PRESET_SAFETY_CHECK => Ok(safety_check(trace)),
        PRESET_COMPLETENESS_CHECK => Ok(completeness_check(trace)),
        PRESET_REGRESSION_CHECK => Ok(regression_check_single(trace)),
        _ => Err(EvalError::UnknownPreset(name.to_string())),
    }
}

/// Run a regression check comparing two traces.
pub fn run_regression(baseline: &Trace, candidate: &Trace) -> EvalReport {
    regression_check(baseline, candidate)
}

// ---------------------------------------------------------------------------
// safety-check
// ---------------------------------------------------------------------------

/// Verifies that every step in the trace has all checks passing.
///
/// Findings:
/// - ERROR for any step where `verdict.approved == false`
/// - ERROR for any individual check that failed
/// - WARNING for steps with empty check vectors
fn safety_check(trace: &Trace) -> EvalReport {
    let mut findings = Vec::new();
    let mut all_passed = true;

    if trace.steps.is_empty() {
        findings.push(EvalFinding {
            step: 0,
            severity: Severity::Warning,
            message: "trace contains no steps".into(),
        });
    }

    for step in &trace.steps {
        let verdict = &step.verdict.verdict;

        if verdict.checks.is_empty() {
            findings.push(EvalFinding {
                step: step.step,
                severity: Severity::Warning,
                message: "verdict has no checks".into(),
            });
        }

        if !verdict.approved {
            all_passed = false;
            // Collect failed check names
            let failed: Vec<&str> = verdict
                .checks
                .iter()
                .filter(|c| !c.passed)
                .map(|c| c.name.as_str())
                .collect();

            if failed.is_empty() {
                findings.push(EvalFinding {
                    step: step.step,
                    severity: Severity::Error,
                    message: "verdict rejected but no individual check failed".into(),
                });
            } else {
                for check in &verdict.checks {
                    if !check.passed {
                        findings.push(EvalFinding {
                            step: step.step,
                            severity: Severity::Error,
                            message: format!(
                                "check '{}' ({}) failed: {}",
                                check.name, check.category, check.details
                            ),
                        });
                    }
                }
            }
        }
    }

    let total = trace.steps.len();
    let rejected = trace
        .steps
        .iter()
        .filter(|s| !s.verdict.verdict.approved)
        .count();

    EvalReport {
        preset: PRESET_SAFETY_CHECK.into(),
        trace_id: trace.id.clone(),
        passed: all_passed,
        findings,
        summary: format!(
            "{}/{} steps approved, {} rejected",
            total - rejected,
            total,
            rejected,
        ),
    }
}

// ---------------------------------------------------------------------------
// completeness-check
// ---------------------------------------------------------------------------

/// Verifies trace completeness:
/// - Steps are present (non-empty trace)
/// - Step sequence numbers are monotonically increasing with no gaps
/// - Step sequence starts at 0
/// - Timestamps are non-decreasing
/// - All 11 expected checks (1 authority + 10 physics) are present per verdict
fn completeness_check(trace: &Trace) -> EvalReport {
    const EXPECTED_CHECKS: &[&str] = &[
        "authority",
        "joint_limits",
        "velocity_limits",
        "torque_limits",
        "acceleration_limits",
        "workspace_bounds",
        "exclusion_zones",
        "self_collision",
        "delta_time",
        "stability",
        "proximity_velocity",
    ];

    let mut findings = Vec::new();
    let mut all_passed = true;

    if trace.steps.is_empty() {
        findings.push(EvalFinding {
            step: 0,
            severity: Severity::Error,
            message: "trace contains no steps".into(),
        });
        return EvalReport {
            preset: PRESET_COMPLETENESS_CHECK.into(),
            trace_id: trace.id.clone(),
            passed: false,
            findings,
            summary: "empty trace".into(),
        };
    }

    // Check step 0 exists
    if trace.steps[0].step != 0 {
        all_passed = false;
        findings.push(EvalFinding {
            step: trace.steps[0].step,
            severity: Severity::Error,
            message: format!(
                "first step has sequence {}, expected 0",
                trace.steps[0].step
            ),
        });
    }

    // Check monotonic step numbers and no gaps
    for window in trace.steps.windows(2) {
        let prev = &window[0];
        let curr = &window[1];

        if curr.step != prev.step + 1 {
            all_passed = false;
            findings.push(EvalFinding {
                step: curr.step,
                severity: Severity::Error,
                message: format!(
                    "step sequence gap: {} -> {} (expected {})",
                    prev.step,
                    curr.step,
                    prev.step + 1
                ),
            });
        }

        // Timestamps must be non-decreasing
        if curr.timestamp < prev.timestamp {
            all_passed = false;
            findings.push(EvalFinding {
                step: curr.step,
                severity: Severity::Error,
                message: format!(
                    "timestamp regression: step {} ({}) < step {} ({})",
                    curr.step, curr.timestamp, prev.step, prev.timestamp
                ),
            });
        }
    }

    // Check that every verdict has the expected 11 checks
    for step in &trace.steps {
        let check_names: Vec<&str> = step
            .verdict
            .verdict
            .checks
            .iter()
            .map(|c| c.name.as_str())
            .collect();

        for &expected in EXPECTED_CHECKS {
            if !check_names.contains(&expected) {
                all_passed = false;
                findings.push(EvalFinding {
                    step: step.step,
                    severity: Severity::Error,
                    message: format!("missing check '{}'", expected),
                });
            }
        }
    }

    let gap_count = findings
        .iter()
        .filter(|f| f.message.starts_with("step sequence gap"))
        .count();
    let missing_count = findings
        .iter()
        .filter(|f| f.message.starts_with("missing check"))
        .count();

    EvalReport {
        preset: PRESET_COMPLETENESS_CHECK.into(),
        trace_id: trace.id.clone(),
        passed: all_passed,
        findings,
        summary: format!(
            "{} steps, {} sequence gaps, {} missing checks",
            trace.steps.len(),
            gap_count,
            missing_count,
        ),
    }
}

// ---------------------------------------------------------------------------
// regression-check (single trace)
// ---------------------------------------------------------------------------

/// When run on a single trace, regression-check verifies internal consistency:
/// - `verdict.approved` matches whether all checks passed
/// - Command sequence numbers match step sequence numbers
fn regression_check_single(trace: &Trace) -> EvalReport {
    let mut findings = Vec::new();
    let mut all_passed = true;

    for step in &trace.steps {
        let verdict = &step.verdict.verdict;
        let all_checks_pass = verdict.checks.iter().all(|c| c.passed);

        if verdict.approved != all_checks_pass {
            all_passed = false;
            findings.push(EvalFinding {
                step: step.step,
                severity: Severity::Error,
                message: format!(
                    "verdict.approved={} but check results imply {}",
                    verdict.approved, all_checks_pass,
                ),
            });
        }

        if verdict.command_sequence != step.step {
            findings.push(EvalFinding {
                step: step.step,
                severity: Severity::Warning,
                message: format!(
                    "command_sequence ({}) does not match step ({})",
                    verdict.command_sequence, step.step,
                ),
            });
        }
    }

    EvalReport {
        preset: PRESET_REGRESSION_CHECK.into(),
        trace_id: trace.id.clone(),
        passed: all_passed,
        findings,
        summary: format!("{} steps checked for internal consistency", trace.steps.len()),
    }
}

// ---------------------------------------------------------------------------
// regression-check (two traces)
// ---------------------------------------------------------------------------

/// Compares two traces for verdict consistency: for each step present in both
/// traces, the approval outcome must match. Differences are reported as errors.
fn regression_check(baseline: &Trace, candidate: &Trace) -> EvalReport {
    let mut findings = Vec::new();
    let mut all_passed = true;

    let max_steps = baseline.steps.len().max(candidate.steps.len());

    if baseline.steps.len() != candidate.steps.len() {
        findings.push(EvalFinding {
            step: 0,
            severity: Severity::Warning,
            message: format!(
                "trace length mismatch: baseline has {} steps, candidate has {}",
                baseline.steps.len(),
                candidate.steps.len()
            ),
        });
    }

    for i in 0..baseline.steps.len().min(candidate.steps.len()) {
        let base_step = &baseline.steps[i];
        let cand_step = &candidate.steps[i];
        let base_approved = base_step.verdict.verdict.approved;
        let cand_approved = cand_step.verdict.verdict.approved;

        if base_approved != cand_approved {
            all_passed = false;
            findings.push(EvalFinding {
                step: base_step.step,
                severity: Severity::Error,
                message: format!(
                    "verdict regression: baseline={}, candidate={}",
                    base_approved, cand_approved
                ),
            });
        }

        // Check per-check result differences
        let base_checks: Vec<(&str, bool)> = base_step
            .verdict
            .verdict
            .checks
            .iter()
            .map(|c| (c.name.as_str(), c.passed))
            .collect();
        let cand_checks: Vec<(&str, bool)> = cand_step
            .verdict
            .verdict
            .checks
            .iter()
            .map(|c| (c.name.as_str(), c.passed))
            .collect();

        for (name, base_pass) in &base_checks {
            if let Some((_, cand_pass)) = cand_checks.iter().find(|(n, _)| n == name) {
                if base_pass != cand_pass {
                    findings.push(EvalFinding {
                        step: base_step.step,
                        severity: Severity::Error,
                        message: format!(
                            "check '{}' changed: baseline={}, candidate={}",
                            name, base_pass, cand_pass
                        ),
                    });
                }
            }
        }
    }

    let regressions = findings
        .iter()
        .filter(|f| f.severity == Severity::Error)
        .count();

    EvalReport {
        preset: PRESET_REGRESSION_CHECK.into(),
        trace_id: format!("{}..{}", baseline.id, candidate.id),
        passed: all_passed,
        findings,
        summary: format!(
            "compared {} steps, {} regressions found",
            max_steps, regressions,
        ),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use invariant_core::models::command::{Command, CommandAuthority, JointState};
    use invariant_core::models::trace::{Trace, TraceStep};
    use invariant_core::models::verdict::{
        AuthoritySummary, CheckResult, SignedVerdict, Verdict,
    };
    use std::collections::HashMap;

    fn make_check(name: &str, category: &str, passed: bool) -> CheckResult {
        CheckResult {
            name: name.into(),
            category: category.into(),
            passed,
            details: if passed {
                "ok".into()
            } else {
                format!("{} failed", name)
            },
        }
    }

    fn all_checks(passed: bool) -> Vec<CheckResult> {
        vec![
            make_check("authority", "authority", passed),
            make_check("joint_limits", "physics", passed),
            make_check("velocity_limits", "physics", passed),
            make_check("torque_limits", "physics", passed),
            make_check("acceleration_limits", "physics", passed),
            make_check("workspace_bounds", "physics", passed),
            make_check("exclusion_zones", "physics", passed),
            make_check("self_collision", "physics", passed),
            make_check("delta_time", "physics", passed),
            make_check("stability", "physics", passed),
            make_check("proximity_velocity", "physics", passed),
        ]
    }

    fn make_command(seq: u64) -> Command {
        Command {
            timestamp: Utc::now(),
            source: "test".into(),
            sequence: seq,
            joint_states: vec![JointState {
                name: "j0".into(),
                position: 0.0,
                velocity: 0.0,
                effort: 0.0,
            }],
            delta_time: 0.01,
            end_effector_positions: vec![],
            center_of_mass: None,
            authority: CommandAuthority {
                pca_chain: "".into(),
                required_ops: vec![],
            },
            metadata: HashMap::new(),
        }
    }

    fn make_verdict(seq: u64, approved: bool) -> SignedVerdict {
        SignedVerdict {
            verdict: Verdict {
                approved,
                command_hash: format!("hash_{}", seq),
                command_sequence: seq,
                timestamp: Utc::now(),
                checks: all_checks(approved),
                profile_name: "test_profile".into(),
                profile_hash: "profile_hash".into(),
                authority_summary: AuthoritySummary {
                    origin_principal: "operator".into(),
                    hop_count: 1,
                    operations_granted: vec!["actuate:*".into()],
                    operations_required: vec!["actuate:j0".into()],
                },
            },
            verdict_signature: "sig".into(),
            signer_kid: "kid".into(),
        }
    }

    fn make_step(seq: u64, approved: bool) -> TraceStep {
        TraceStep {
            step: seq,
            timestamp: Utc::now(),
            command: make_command(seq),
            verdict: make_verdict(seq, approved),
            simulation_state: None,
        }
    }

    fn make_trace(steps: Vec<TraceStep>) -> Trace {
        Trace {
            id: "trace-001".into(),
            episode: 0,
            environment_id: 0,
            scenario: "test".into(),
            profile_name: "test_profile".into(),
            steps,
            metadata: HashMap::new(),
        }
    }

    // --- list_presets ---

    #[test]
    fn test_list_presets() {
        let presets = list_presets();
        assert_eq!(presets.len(), 3);
        assert!(presets.contains(&"safety-check"));
        assert!(presets.contains(&"completeness-check"));
        assert!(presets.contains(&"regression-check"));
    }

    // --- run_preset dispatch ---

    #[test]
    fn test_unknown_preset() {
        let trace = make_trace(vec![]);
        let err = run_preset("nonexistent", &trace).unwrap_err();
        assert!(err.to_string().contains("nonexistent"));
    }

    #[test]
    fn test_dispatch_safety_check() {
        let trace = make_trace(vec![make_step(0, true)]);
        let report = run_preset("safety-check", &trace).unwrap();
        assert_eq!(report.preset, "safety-check");
        assert!(report.passed);
    }

    #[test]
    fn test_dispatch_completeness_check() {
        let trace = make_trace(vec![make_step(0, true)]);
        let report = run_preset("completeness-check", &trace).unwrap();
        assert_eq!(report.preset, "completeness-check");
    }

    #[test]
    fn test_dispatch_regression_check() {
        let trace = make_trace(vec![make_step(0, true)]);
        let report = run_preset("regression-check", &trace).unwrap();
        assert_eq!(report.preset, "regression-check");
    }

    // --- safety-check ---

    #[test]
    fn test_safety_all_approved() {
        let trace = make_trace(vec![make_step(0, true), make_step(1, true)]);
        let report = safety_check(&trace);
        assert!(report.passed);
        assert!(report.findings.is_empty());
        assert!(report.summary.contains("2/2 steps approved"));
    }

    #[test]
    fn test_safety_one_rejected() {
        let trace = make_trace(vec![make_step(0, true), make_step(1, false)]);
        let report = safety_check(&trace);
        assert!(!report.passed);
        assert!(!report.findings.is_empty());
        assert!(report.summary.contains("1 rejected"));
    }

    #[test]
    fn test_safety_empty_trace() {
        let trace = make_trace(vec![]);
        let report = safety_check(&trace);
        assert!(report.passed); // no rejections
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].severity, Severity::Warning);
    }

    #[test]
    fn test_safety_rejected_reports_failed_checks() {
        let trace = make_trace(vec![make_step(0, false)]);
        let report = safety_check(&trace);
        // All 11 checks fail in our test helper when approved=false
        let error_findings: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Error)
            .collect();
        assert_eq!(error_findings.len(), 11);
        assert!(error_findings[0].message.contains("authority"));
    }

    // --- completeness-check ---

    #[test]
    fn test_completeness_empty_trace() {
        let trace = make_trace(vec![]);
        let report = completeness_check(&trace);
        assert!(!report.passed);
        assert!(report.summary.contains("empty trace"));
    }

    #[test]
    fn test_completeness_good_trace() {
        let trace = make_trace(vec![make_step(0, true), make_step(1, true)]);
        let report = completeness_check(&trace);
        assert!(report.passed);
        assert!(report.findings.is_empty());
    }

    #[test]
    fn test_completeness_bad_start() {
        let trace = make_trace(vec![make_step(1, true)]);
        let report = completeness_check(&trace);
        assert!(!report.passed);
        assert!(report.findings[0].message.contains("expected 0"));
    }

    #[test]
    fn test_completeness_gap_in_steps() {
        let trace = make_trace(vec![make_step(0, true), make_step(2, true)]);
        let report = completeness_check(&trace);
        assert!(!report.passed);
        let gap_findings: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.message.contains("gap"))
            .collect();
        assert_eq!(gap_findings.len(), 1);
    }

    #[test]
    fn test_completeness_timestamp_regression() {
        use chrono::Duration;
        let mut trace = make_trace(vec![make_step(0, true), make_step(1, true)]);
        trace.steps[1].timestamp = trace.steps[0].timestamp - Duration::seconds(10);
        let report = completeness_check(&trace);
        assert!(!report.passed);
        assert!(report
            .findings
            .iter()
            .any(|f| f.message.contains("timestamp regression")));
    }

    #[test]
    fn test_completeness_missing_check() {
        let mut trace = make_trace(vec![make_step(0, true)]);
        // Remove the last check (proximity_velocity)
        trace.steps[0].verdict.verdict.checks.pop();
        let report = completeness_check(&trace);
        assert!(!report.passed);
        assert!(report
            .findings
            .iter()
            .any(|f| f.message.contains("missing check 'proximity_velocity'")));
    }

    // --- regression-check (single) ---

    #[test]
    fn test_regression_single_consistent() {
        let trace = make_trace(vec![make_step(0, true), make_step(1, true)]);
        let report = regression_check_single(&trace);
        assert!(report.passed);
        assert!(report.findings.is_empty());
    }

    #[test]
    fn test_regression_single_inconsistent_verdict() {
        let mut trace = make_trace(vec![make_step(0, true)]);
        // Say approved=true but a check failed — inconsistency
        trace.steps[0].verdict.verdict.checks[0].passed = false;
        let report = regression_check_single(&trace);
        assert!(!report.passed);
        assert!(report.findings[0].message.contains("verdict.approved=true"));
    }

    #[test]
    fn test_regression_single_sequence_mismatch() {
        let mut trace = make_trace(vec![make_step(0, true)]);
        trace.steps[0].verdict.verdict.command_sequence = 99;
        let report = regression_check_single(&trace);
        assert!(report.passed); // warnings don't cause failure
        assert_eq!(report.findings[0].severity, Severity::Warning);
    }

    // --- regression-check (two traces) ---

    #[test]
    fn test_regression_two_traces_match() {
        let baseline = make_trace(vec![make_step(0, true), make_step(1, true)]);
        let candidate = make_trace(vec![make_step(0, true), make_step(1, true)]);
        let report = run_regression(&baseline, &candidate);
        assert!(report.passed);
        assert_eq!(report.findings.len(), 0);
    }

    #[test]
    fn test_regression_two_traces_verdict_change() {
        let baseline = make_trace(vec![make_step(0, true), make_step(1, true)]);
        let candidate = make_trace(vec![make_step(0, true), make_step(1, false)]);
        let report = run_regression(&baseline, &candidate);
        assert!(!report.passed);
        assert!(report
            .findings
            .iter()
            .any(|f| f.message.contains("verdict regression")));
    }

    #[test]
    fn test_regression_two_traces_length_mismatch() {
        let baseline = make_trace(vec![make_step(0, true)]);
        let candidate = make_trace(vec![make_step(0, true), make_step(1, true)]);
        let report = run_regression(&baseline, &candidate);
        assert!(report.passed); // length mismatch is a warning, not failure
        assert!(report
            .findings
            .iter()
            .any(|f| f.message.contains("length mismatch")));
    }

    #[test]
    fn test_regression_check_level_diff() {
        let baseline = make_trace(vec![make_step(0, true)]);
        let mut candidate = make_trace(vec![make_step(0, true)]);
        // Both approved=true overall, but flip one check in candidate
        candidate.steps[0].verdict.verdict.checks[1].passed = false;
        candidate.steps[0].verdict.verdict.approved = false;
        let report = run_regression(&baseline, &candidate);
        assert!(!report.passed);
        assert!(report
            .findings
            .iter()
            .any(|f| f.message.contains("check 'joint_limits' changed")));
    }

    // --- EvalReport serialization ---

    #[test]
    fn test_eval_report_serialization() {
        let report = EvalReport {
            preset: "safety-check".into(),
            trace_id: "t1".into(),
            passed: true,
            findings: vec![EvalFinding {
                step: 0,
                severity: Severity::Info,
                message: "test".into(),
            }],
            summary: "ok".into(),
        };
        let json = serde_json::to_string(&report).unwrap();
        let deser: EvalReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report, deser);
    }
}
