use clap::Args;
use std::path::PathBuf;

use invariant_core::models::trace::Trace;
use invariant_eval::presets;

#[derive(Args)]
pub struct EvalArgs {
    /// Path to the trace JSON file to evaluate (P2-12: explicit value_name).
    #[arg(value_name = "TRACE_FILE")]
    pub trace: PathBuf,

    /// Eval preset to run (safety-check, completeness-check, regression-check)
    #[arg(long)]
    pub preset: Option<String>,

    /// Path to a custom rubric YAML/JSON file
    #[arg(long, value_name = "RUBRIC_FILE")]
    pub rubric: Option<PathBuf>,

    /// List available presets and exit
    #[arg(long)]
    pub list_presets: bool,
}

pub fn run(args: &EvalArgs) -> i32 {
    if args.list_presets {
        println!("Available presets:");
        for name in presets::list_presets() {
            println!("  {}", name);
        }
        return 0;
    }

    if args.rubric.is_some() {
        eprintln!("invariant eval: --rubric not yet implemented (Step 13)");
        return 2;
    }

    let preset_name = match &args.preset {
        Some(name) => name.as_str(),
        None => {
            eprintln!("invariant eval: specify --preset or --rubric");
            eprintln!("Available presets: {}", presets::list_presets().join(", "));
            return 2;
        }
    };

    // Read trace file
    let trace_data = match std::fs::read_to_string(&args.trace) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("error: could not read trace file: {}", e);
            return 2;
        }
    };

    let trace: Trace = match serde_json::from_str(&trace_data) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("error: could not parse trace file: {}", e);
            return 2;
        }
    };

    // Run the preset
    let report = match presets::run_preset(preset_name, &trace) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {}", e);
            return 2;
        }
    };

    // Output as JSON
    match serde_json::to_string_pretty(&report) {
        Ok(json) => println!("{}", json),
        Err(e) => {
            eprintln!("error: could not serialize report: {}", e);
            return 2;
        }
    }

    if report.passed {
        0
    } else {
        1
    }
}
