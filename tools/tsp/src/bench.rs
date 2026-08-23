use crate::fixtures::{
    FIXTURE_MAX_BYTES, fixture_case_paths, load_case, read_bounded_file, read_fixture_input,
    resolve_case_path, validate_case_expectation,
};
use crate::manifest::{ResolvedPlugin, ValidationError};
use crate::protocol::{OptimizeAction, OptimizeRequest, run_fixture_with_activation};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::Instant;

pub const DEFAULT_ITERATIONS: u32 = 10;
pub const MAX_ITERATIONS: u32 = 100;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LatencySummary {
    pub minimum_us: u128,
    pub p50_us: u128,
    pub p95_us: u128,
    pub p99_us: u128,
    pub maximum_us: u128,
    pub mean_us: u128,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BenchCaseReport {
    pub name: String,
    pub path: String,
    pub iterations: u32,
    pub input_bytes: usize,
    pub output_bytes: usize,
    pub saved_bytes: usize,
    pub savings_percent: f64,
    pub action: OptimizeAction,
    pub activation_attempt_ids: Vec<String>,
    pub latency_us: LatencySummary,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BenchTotals {
    pub samples: usize,
    pub input_bytes: usize,
    pub output_bytes: usize,
    pub saved_bytes: usize,
    pub savings_percent: f64,
    pub pass_samples: usize,
    pub optimize_samples: usize,
    pub latency_us: LatencySummary,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BenchReport {
    pub schema_version: u32,
    pub ok: bool,
    pub plugin_id: String,
    pub version: String,
    pub platform: String,
    pub release_id: String,
    pub artifact_digest: String,
    pub fixture_directory: String,
    pub iterations: u32,
    pub cases: Vec<BenchCaseReport>,
    pub totals: BenchTotals,
    pub duration_ms: u128,
}

pub fn bench_plugin(
    plugin: &ResolvedPlugin,
    fixture_directory: &Path,
    iterations: u32,
) -> Result<BenchReport, ValidationError> {
    if !(1..=MAX_ITERATIONS).contains(&iterations) {
        return Err(ValidationError::new(
            "bench.iterations",
            format!("iterations must be between 1 and {MAX_ITERATIONS}"),
            "Pass --iterations with a bounded positive integer.",
        ));
    }
    let started = Instant::now();
    let paths = fixture_case_paths(fixture_directory)?;
    let mut cases = Vec::with_capacity(paths.len());
    let mut all_latencies = Vec::with_capacity(paths.len() * iterations as usize);
    let mut total_input = 0usize;
    let mut total_output = 0usize;
    let mut pass_samples = 0usize;
    let mut optimize_samples = 0usize;

    for path in paths {
        let case = load_case(&path)?;
        let base = path.parent().unwrap_or(fixture_directory);
        let input = read_fixture_input(&resolve_case_path(base, &case.input)?)?;
        let expected = match &case.expected_output {
            Some(relative) => Some(read_bounded_file(
                &resolve_case_path(base, relative)?,
                FIXTURE_MAX_BYTES,
                "bench.expected",
                "Use a regular UTF-8 golden output no larger than 16 MiB.",
            )?),
            None => None,
        };
        validate_case_expectation(&case, expected.as_deref())?;

        let mut latencies = Vec::with_capacity(iterations as usize);
        let mut activation_attempt_ids = Vec::with_capacity(iterations as usize);
        let mut stable_action = None;
        let mut stable_output = None;
        for _ in 0..iterations {
            let request = OptimizeRequest {
                kind: case.kind.clone(),
                program: case.program.clone(),
                exit_code: case.exit_code,
                content: input.clone(),
            };
            crate::protocol::validate_fixture_request(plugin, &request)?;
            let activation_attempt_id = crate::identity::new_activation_attempt_id()?;
            let sample_started = Instant::now();
            let run = run_fixture_with_activation(plugin, request, activation_attempt_id.clone())?;
            activation_attempt_ids.push(activation_attempt_id);
            let elapsed_us = sample_started.elapsed().as_micros();
            let expected_output = expected.as_deref().unwrap_or(&input);
            if run.action != case.expected_action || run.output.as_bytes() != expected_output {
                return Err(ValidationError::new(
                    "bench.golden",
                    format!(
                        "fixture {:?} did not match its golden action and output",
                        case.name
                    ),
                    "Run `tsp test` and fix every golden fixture before benchmarking.",
                ));
            }
            if stable_action
                .as_ref()
                .is_some_and(|action| action != &run.action)
                || stable_output
                    .as_ref()
                    .is_some_and(|output: &String| output != &run.output)
            {
                return Err(ValidationError::new(
                    "bench.nondeterministic",
                    format!(
                        "fixture {:?} produced different repeated results",
                        case.name
                    ),
                    "Make plugin output deterministic for identical fixture requests.",
                ));
            }
            stable_action = Some(run.action.clone());
            stable_output = Some(run.output.clone());
            latencies.push(elapsed_us);
            all_latencies.push(elapsed_us);
            total_input = total_input.saturating_add(run.input_bytes);
            total_output = total_output.saturating_add(run.output_bytes);
            match run.action {
                OptimizeAction::Pass => pass_samples += 1,
                OptimizeAction::Optimize => optimize_samples += 1,
            }
        }
        let output = stable_output.expect("positive iteration count");
        let output_bytes = output.len();
        let saved_bytes = input.len().saturating_sub(output_bytes);
        cases.push(BenchCaseReport {
            name: case.name,
            path: path.display().to_string(),
            iterations,
            input_bytes: input.len(),
            output_bytes,
            saved_bytes,
            savings_percent: percentage(saved_bytes, input.len()),
            action: stable_action.expect("positive iteration count"),
            activation_attempt_ids,
            latency_us: summarize_latency(&latencies),
        });
    }

    let saved_bytes = total_input.saturating_sub(total_output);
    Ok(BenchReport {
        schema_version: 1,
        ok: true,
        plugin_id: plugin.manifest.id.clone(),
        version: plugin.manifest.version.clone(),
        platform: plugin.platform.clone(),
        release_id: plugin.release_id.clone(),
        artifact_digest: plugin.artifact_digest.clone(),
        fixture_directory: fixture_directory.display().to_string(),
        iterations,
        cases,
        totals: BenchTotals {
            samples: all_latencies.len(),
            input_bytes: total_input,
            output_bytes: total_output,
            saved_bytes,
            savings_percent: percentage(saved_bytes, total_input),
            pass_samples,
            optimize_samples,
            latency_us: summarize_latency(&all_latencies),
        },
        duration_ms: started.elapsed().as_millis(),
    })
}

fn percentage(saved: usize, input: usize) -> f64 {
    if input == 0 {
        0.0
    } else {
        saved as f64 * 100.0 / input as f64
    }
}

fn summarize_latency(samples: &[u128]) -> LatencySummary {
    debug_assert!(!samples.is_empty());
    let mut ordered = samples.to_vec();
    ordered.sort_unstable();
    let sum = ordered.iter().copied().sum::<u128>();
    LatencySummary {
        minimum_us: ordered[0],
        p50_us: percentile(&ordered, 50),
        p95_us: percentile(&ordered, 95),
        p99_us: percentile(&ordered, 99),
        maximum_us: ordered[ordered.len() - 1],
        mean_us: sum / ordered.len() as u128,
    }
}

fn percentile(ordered: &[u128], percentile: usize) -> u128 {
    let rank = (percentile * ordered.len()).div_ceil(100);
    ordered[rank.saturating_sub(1)]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn latency_summary_uses_nearest_rank_percentiles() {
        let summary = summarize_latency(&[50, 10, 40, 20, 30]);
        assert_eq!(summary.minimum_us, 10);
        assert_eq!(summary.p50_us, 30);
        assert_eq!(summary.p95_us, 50);
        assert_eq!(summary.p99_us, 50);
        assert_eq!(summary.maximum_us, 50);
        assert_eq!(summary.mean_us, 30);
    }
}
