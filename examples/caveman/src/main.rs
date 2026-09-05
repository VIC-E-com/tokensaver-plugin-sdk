use std::collections::VecDeque;
use std::fmt::Write as _;

use tokensaver_plugin::{Action, Optimizer, Request, run};

const HEAD_LINES: usize = 10;
const TAIL_LINES: usize = 16;
const SUCCESS_CONTEXT: usize = 1;
const FAILURE_CONTEXT: usize = 3;
const MIN_INPUT_BYTES: usize = 2 * 1024;
const MIN_INPUT_LINES: usize = HEAD_LINES + TAIL_LINES + 8;
const REQUIRED_REDUCTION_PERCENT: usize = 20;

struct CavemanOptimizer;

impl Optimizer for CavemanOptimizer {
    const PLUGIN_ID: &'static str = "com.vic-e.tokensaver.caveman";
    const VERSION: &'static str = "0.1.3";

    fn optimize(&self, request: Request) -> Action {
        if !eligible_request(request.kind(), request.program(), request.text()) {
            return Action::Pass;
        }
        optimize_eligible_output(request.exit_code(), request.text())
    }
}

fn eligible_request(kind: &str, program: &str, text: &str) -> bool {
    if kind.eq_ignore_ascii_case("status")
        || text.len() < MIN_INPUT_BYTES
        || text.split_inclusive('\n').take(MIN_INPUT_LINES + 1).count() <= MIN_INPUT_LINES
        || is_machine_readable(text)
        || is_already_compacted(text)
    {
        return false;
    }

    let basename = program.rsplit(['/', '\\']).next().unwrap_or(program);
    let basename = [".exe", ".cmd", ".bat"]
        .iter()
        .find_map(|suffix| strip_suffix_ascii_case(basename, suffix))
        .unwrap_or(basename);
    if basename.eq_ignore_ascii_case("caveman") {
        return true;
    }

    let wrapper = ["npm", "npx", "pnpm", "bun", "node", "deno"]
        .iter()
        .any(|candidate| basename.eq_ignore_ascii_case(candidate));
    wrapper
        && (contains_ascii_case_insensitive(text, "caveman:")
            || contains_ascii_case_insensitive(text, "caveman diagnostic")
            || contains_ascii_case_insensitive(text, "caveman log"))
}

fn strip_suffix_ascii_case<'a>(value: &'a str, suffix: &str) -> Option<&'a str> {
    let start = value.len().checked_sub(suffix.len())?;
    value
        .get(start..)?
        .eq_ignore_ascii_case(suffix)
        .then(|| value.get(..start))?
}

fn is_already_compacted(text: &str) -> bool {
    contains_ascii_case_insensitive(text, "‹caveman:")
        || contains_ascii_case_insensitive(text, "caveman retrieve")
}

fn is_machine_readable(text: &str) -> bool {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return false;
    }
    if (trimmed.starts_with('{') && trimmed.ends_with('}'))
        || (trimmed.starts_with('[') && trimmed.ends_with(']'))
    {
        return true;
    }

    let mut records = 0usize;
    for line in trimmed.lines().filter(|line| !line.trim().is_empty()) {
        let line = line.trim();
        if !(line.starts_with('{') && line.ends_with('}')) {
            return false;
        }
        records += 1;
    }
    records > 1
}

#[cfg(test)]
fn optimize_caveman_output(exit_code: i32, text: &str) -> Action {
    if text.len() < MIN_INPUT_BYTES
        || text.split_inclusive('\n').take(MIN_INPUT_LINES + 1).count() <= MIN_INPUT_LINES
        || is_machine_readable(text)
        || is_already_compacted(text)
    {
        return Action::Pass;
    }

    optimize_eligible_output(exit_code, text)
}

fn optimize_eligible_output(exit_code: i32, text: &str) -> Action {
    let newline = preferred_newline(text);
    let diagnostic_context = if exit_code == 0 {
        SUCCESS_CONTEXT
    } else {
        FAILURE_CONTEXT
    };
    let mut pending = VecDeque::with_capacity(TAIL_LINES + 1);
    let mut output = String::new();
    let mut omitted = 0usize;
    let mut keep_through = 0usize;

    for (index, segment) in text.split_inclusive('\n').enumerate() {
        let without_newline = segment.strip_suffix('\n').unwrap_or(segment);
        let line = without_newline
            .strip_suffix('\r')
            .unwrap_or(without_newline);
        let importance = line_importance(line);
        let context = match importance {
            Importance::Diagnostic => diagnostic_context,
            Importance::Evidence => SUCCESS_CONTEXT,
            Importance::Routine => 0,
        };
        let keep = index < HEAD_LINES || index <= keep_through || importance != Importance::Routine;
        pending.push_back(PendingLine { segment, keep });

        if importance != Importance::Routine {
            for previous in pending.iter_mut().rev().take(context + 1) {
                previous.keep = true;
            }
            keep_through = keep_through.max(index.saturating_add(context));
        }

        if pending.len() > TAIL_LINES {
            let Some(line) = pending.pop_front() else {
                return Action::Pass;
            };
            if !emit_line(&mut output, line, &mut omitted, newline, text.len()) {
                return Action::Pass;
            }
        }
    }

    for mut line in pending {
        line.keep = true;
        if !emit_line(&mut output, line, &mut omitted, newline, text.len()) {
            return Action::Pass;
        }
    }

    let maximum_percent = 100usize.saturating_sub(REQUIRED_REDUCTION_PERCENT);
    if output.len().saturating_mul(100) > text.len().saturating_mul(maximum_percent) {
        return Action::Pass;
    }
    Action::optimized(output).unwrap_or(Action::Pass)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Importance {
    Routine,
    Evidence,
    Diagnostic,
}

#[derive(Clone, Copy)]
struct PendingLine<'a> {
    segment: &'a str,
    keep: bool,
}

fn emit_line(
    output: &mut String,
    line: PendingLine<'_>,
    omitted: &mut usize,
    newline: &str,
    maximum: usize,
) -> bool {
    if !line.keep {
        *omitted = omitted.saturating_add(1);
        return true;
    }
    if *omitted > 0 {
        const PREFIX: &str = "... ";
        const SUFFIX: &str = " routine Caveman diagnostic lines omitted by TokenSaver ...";
        let maximum_digits = 20;
        let reserve = PREFIX.len() + maximum_digits + SUFFIX.len() + newline.len();
        if !reserve_output(output, reserve, maximum) {
            return false;
        }
        let _ = write!(output, "{PREFIX}{}{SUFFIX}{newline}", *omitted);
        *omitted = 0;
    }
    if !reserve_output(output, line.segment.len(), maximum) {
        return false;
    }
    output.push_str(line.segment);
    true
}

fn reserve_output(output: &mut String, additional: usize, maximum: usize) -> bool {
    let Some(required) = output.len().checked_add(additional) else {
        return false;
    };
    if required > maximum {
        return false;
    }
    if required <= output.capacity() {
        return true;
    }
    output
        .try_reserve_exact(required.saturating_sub(output.len()))
        .is_ok()
}

fn preferred_newline(text: &str) -> &'static str {
    match text.as_bytes().iter().position(|byte| *byte == b'\n') {
        Some(index) if index > 0 && text.as_bytes()[index - 1] == b'\r' => "\r\n",
        _ => "\n",
    }
}

fn line_importance(line: &str) -> Importance {
    let visible = line.trim_start_matches(|character: char| {
        character.is_whitespace() || matches!(character, '│' | '┃' | '┆' | '┊')
    });
    if visible.starts_with(['✖', '×', '❌', '⚠']) {
        return Importance::Diagnostic;
    }

    let mut importance = Importance::Routine;
    for word in line.split(|character: char| {
        !character.is_ascii_alphanumeric() && character != '_' && character != '-'
    }) {
        if word.is_empty() {
            continue;
        }
        if is_diagnostic_word(word) {
            return Importance::Diagnostic;
        }
        if is_evidence_word(word) {
            importance = Importance::Evidence;
        }
    }
    importance
}

fn is_diagnostic_word(word: &str) -> bool {
    match word.as_bytes().first().map(u8::to_ascii_lowercase) {
        Some(b'a') => matches_word(word, &["abort", "aborted"]),
        Some(b'c') => matches_word(word, &["crash", "crashed"]),
        Some(b'd') => matches_word(word, &["denied"]),
        Some(b'e') => matches_word(word, &["error", "errors", "exception"]),
        Some(b'f') => matches_word(word, &["failed", "failure", "failures", "fatal"]),
        Some(b'i') => matches_word(word, &["invalid"]),
        Some(b'n') => matches_word(word, &["next"]),
        Some(b'p') => matches_word(word, &["panic", "panicked"]),
        Some(b'r') => matches_word(word, &["retrieve", "retry", "retries"]),
        Some(b't') => matches_word(word, &["timed", "timeout", "timeouts"]),
        Some(b'u') => matches_word(word, &["unauthorized"]),
        Some(b'w') => matches_word(word, &["warn", "warning", "warnings"]),
        _ => false,
    }
}

fn is_evidence_word(word: &str) -> bool {
    match word.as_bytes().first().map(u8::to_ascii_lowercase) {
        Some(b'a') => matches_word(word, &["accounting"]),
        Some(b'b') => matches_word(word, &["basis", "billed", "billing"]),
        Some(b'c') => matches_word(word, &["cache", "cached", "confidence", "cost"]),
        Some(b'd') => matches_word(word, &["duration"]),
        Some(b'e') => matches_word(word, &["elapsed"]),
        Some(b'h') => matches_word(word, &["handle"]),
        Some(b'l') => matches_word(word, &["latency", "login"]),
        Some(b'm') => matches_word(word, &["mode", "model"]),
        Some(b'p') => matches_word(word, &["passed", "provider"]),
        Some(b'r') => matches_word(
            word,
            &["recover", "remediation", "request", "requests", "rerun"],
        ),
        Some(b's') => matches_word(
            word,
            &["saved", "savings", "setup", "span", "spans", "summary"],
        ),
        Some(b't') => matches_word(
            word,
            &["telemetry", "tldr", "token", "tokens", "total", "totals"],
        ),
        Some(b'u') => matches_word(word, &["usage"]),
        _ => false,
    }
}

fn matches_word(word: &str, candidates: &[&str]) -> bool {
    candidates
        .iter()
        .any(|candidate| word.eq_ignore_ascii_case(candidate))
}

fn contains_ascii_case_insensitive(haystack: &str, needle: &str) -> bool {
    let needle = needle.as_bytes();
    if needle.is_empty() {
        return true;
    }
    haystack.as_bytes().windows(needle.len()).any(|window| {
        window
            .iter()
            .zip(needle)
            .all(|(left, right)| left.eq_ignore_ascii_case(right))
    })
}

fn main() {
    run(CavemanOptimizer);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verbose_output(lines: usize, replacements: &[(usize, &str)], newline: &str) -> String {
        let mut output = String::new();
        for index in 0..lines {
            let line = replacements
                .iter()
                .find_map(|(replacement_index, value)| {
                    (*replacement_index == index).then_some(*value)
                })
                .map(str::to_owned)
                .unwrap_or_else(|| format!("caveman diagnostic routine event {index}"));
            output.push_str(&line);
            output.push_str(newline);
        }
        output
    }

    fn optimized(action: Action) -> String {
        match action {
            Action::Optimize(content) => content,
            Action::Pass => panic!("expected optimized action"),
        }
    }

    #[test]
    fn identity_matches_manifest() {
        assert_eq!(
            <CavemanOptimizer as Optimizer>::PLUGIN_ID,
            "com.vic-e.tokensaver.caveman"
        );
        assert_eq!(<CavemanOptimizer as Optimizer>::VERSION, "0.1.3");
    }

    #[test]
    fn request_eligibility_is_narrow_and_case_insensitive() {
        let long = verbose_output(100, &[], "\n");
        assert!(eligible_request("log", "CAVEMAN.EXE", &long));
        assert!(eligible_request(
            "build",
            "pnpm.cmd",
            &format!("Caveman: diagnostics\n{long}")
        ));
        assert!(!eligible_request("log", "cargo", &long));
        assert!(!eligible_request(
            "log",
            "node",
            &"unrelated routine output\n".repeat(100)
        ));
        assert!(!eligible_request("status", "caveman", &long));
        assert!(!eligible_request("log", "éx", &long));
    }

    #[test]
    fn already_compacted_recovery_output_passes_byte_for_byte() {
        let compacted = format!(
            "{}\n‹caveman: shrank 12000 to 2100 tokens; recover: caveman retrieve cvm_abc123›\n",
            "original evidence\n".repeat(200)
        );
        assert_eq!(optimize_caveman_output(0, &compacted), Action::Pass);
        assert!(!eligible_request("log", "caveman", &compacted));
    }

    #[test]
    fn json_ndjson_status_and_short_output_pass_exactly() {
        let json = format!("{{\"records\":[{}]}}", "1,".repeat(2_000));
        let ndjson = format!(
            "{{\"provider\":\"openai\",\"tokens\":10}}\n{}",
            "{\"provider\":\"anthropic\",\"tokens\":20}\n".repeat(100)
        );
        let status = verbose_output(100, &[(50, "tokens: 200")], "\n");
        assert_eq!(optimize_caveman_output(0, &json), Action::Pass);
        assert_eq!(optimize_caveman_output(0, &ndjson), Action::Pass);
        assert!(!eligible_request("status", "caveman", &status));
        assert_eq!(
            optimize_caveman_output(0, "Caveman is ready\n"),
            Action::Pass
        );
    }

    #[test]
    fn successful_log_preserves_boundaries_evidence_and_warning_context() {
        let input = verbose_output(
            180,
            &[
                (70, "caveman diagnostic routine before warning"),
                (71, "WARNING: optional telemetry sink unavailable"),
                (72, "caveman diagnostic routine after warning"),
                (120, "provider=openai tokens=8420 savings=38% latency=14ms"),
                (150, "Summary: 42 requests passed; cache mode=explicit"),
            ],
            "\n",
        );
        let output = optimized(optimize_caveman_output(0, &input));
        assert!(output.starts_with("caveman diagnostic routine event 0\n"));
        assert!(output.contains(
            "caveman diagnostic routine before warning\nWARNING: optional telemetry sink unavailable\ncaveman diagnostic routine after warning"
        ));
        assert!(output.contains("provider=openai tokens=8420 savings=38% latency=14ms"));
        assert!(output.contains("Summary: 42 requests passed; cache mode=explicit"));
        assert!(output.contains("routine Caveman diagnostic lines omitted by TokenSaver"));
        assert!(output.ends_with("caveman diagnostic routine event 179\n"));
        assert!(output.len() * 100 <= input.len() * 80);
    }

    #[test]
    fn failed_log_keeps_extended_diagnostics_and_remediation_in_order() {
        let input = verbose_output(
            220,
            &[
                (80, "caveman diagnostic context minus three"),
                (83, "ERROR: provider request failed"),
                (86, "caveman diagnostic context plus three"),
                (160, "next: caveman login --provider anthropic"),
                (190, "billing basis: provider tokens and cache spans"),
            ],
            "\n",
        );
        let output = optimized(optimize_caveman_output(1, &input));
        for expected in [
            "context minus three",
            "ERROR: provider request failed",
            "context plus three",
            "next: caveman login --provider anthropic",
            "billing basis: provider tokens and cache spans",
        ] {
            assert!(output.contains(expected), "missing {expected}");
        }
        assert!(output.find("request failed").unwrap() < output.find("next:").unwrap());
    }

    #[test]
    fn crlf_and_missing_final_newline_are_preserved() {
        let with_crlf = verbose_output(120, &[(60, "warning: keep this")], "\r\n");
        let output = optimized(optimize_caveman_output(0, &with_crlf));
        assert!(!output.replace("\r\n", "").contains('\n'));
        assert!(output.ends_with("\r\n"));

        let without_newline = with_crlf.trim_end_matches("\r\n");
        let output = optimized(optimize_caveman_output(0, without_newline));
        assert!(!output.ends_with(['\r', '\n']));
    }

    #[test]
    fn deterministic_newline_heavy_input_stays_bounded() {
        let input = format!(
            "Caveman: diagnostic stream\n{}",
            "routine\n".repeat(200_000)
        );
        let first = optimize_caveman_output(0, &input);
        assert_eq!(first, optimize_caveman_output(0, &input));
        let output = optimized(first);
        assert!(output.len() < input.len() / 100);
        assert!(output.contains("199975 routine Caveman diagnostic lines omitted"));
    }

    #[test]
    fn symbolic_and_text_diagnostics_are_never_routine() {
        for line in [
            "│ ✖ provider disconnected",
            "⚠ degraded cache",
            "request timed out",
            "worker crashed",
            "process aborted",
            "TLDR: measured summary",
        ] {
            assert_ne!(line_importance(line), Importance::Routine, "{line}");
        }
    }

    #[test]
    fn maximum_manifest_sized_routine_stream_is_processed_safely() {
        const MAX_INPUT: usize = 16 << 20;
        let line = "caveman routine verbose internal trace\n";
        let mut input = String::with_capacity(MAX_INPUT);
        while input.len() + line.len() <= MAX_INPUT {
            input.push_str(line);
        }
        input.extend(std::iter::repeat_n('x', MAX_INPUT - input.len()));
        assert_eq!(input.len(), MAX_INPUT);

        let output = optimized(optimize_caveman_output(0, &input));
        assert!(output.len() < input.len() / 100);
        assert!(output.starts_with("caveman routine verbose internal trace\n"));
        assert!(output.ends_with('x'));
    }

    #[test]
    fn optimizer_is_send_sync_stateless_and_concurrently_deterministic() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<CavemanOptimizer>();

        let input = verbose_output(200, &[(100, "warning: deterministic")], "\n");
        let expected = optimize_caveman_output(0, &input);
        std::thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| {
                    for _ in 0..50 {
                        assert_eq!(optimize_caveman_output(0, &input), expected);
                    }
                });
            }
        });
    }

    #[test]
    fn reduction_below_required_threshold_fails_open() {
        let input = verbose_output(
            42,
            &[
                (15, "warning: preserve"),
                (20, "tokens: 10"),
                (25, "provider: local"),
            ],
            "\n",
        );
        assert_eq!(optimize_caveman_output(0, &input), Action::Pass);
    }

    #[test]
    fn checked_in_golden_outputs_match_optimizer_exactly() {
        for (exit_code, input, golden) in [
            (
                0,
                include_str!("../fixtures/success.input.txt"),
                include_str!("../fixtures/success.golden.txt"),
            ),
            (
                1,
                include_str!("../fixtures/failure.input.txt"),
                include_str!("../fixtures/failure.golden.txt"),
            ),
        ] {
            let actual = optimized(optimize_caveman_output(exit_code, input));
            let actual_lines = actual.lines().collect::<Vec<_>>();
            let expected_lines = golden.lines().collect::<Vec<_>>();
            assert_eq!(actual_lines, expected_lines);
            assert_eq!(actual.ends_with('\n'), golden.ends_with('\n'));
        }
    }
}
