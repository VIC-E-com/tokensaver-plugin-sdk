use tokensaver_plugin::{Action, Optimizer, Request, run};

const HEAD_LINES: usize = 12;
const TAIL_LINES: usize = 20;

struct DeepSeekHarnessOptimizer;

impl Optimizer for DeepSeekHarnessOptimizer {
    const PLUGIN_ID: &'static str = "com.tokensaver.deepseek-harness";
    const VERSION: &'static str = "0.1.0";

    fn optimize(&self, request: Request) -> Action {
        if !eligible_request(request.program(), request.text()) {
            return Action::Pass;
        }
        optimize_harness_output(request.exit_code(), request.text())
    }
}

fn eligible_request(program: &str, text: &str) -> bool {
    let program = program
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(program)
        .to_ascii_lowercase();
    let program = program
        .strip_suffix(".exe")
        .or_else(|| program.strip_suffix(".cmd"))
        .or_else(|| program.strip_suffix(".bat"))
        .unwrap_or(&program);
    if program == "dsh" {
        return true;
    }
    if !matches!(program, "pnpm" | "npm" | "npx" | "bun" | "node") {
        return false;
    }
    let lower = text.to_ascii_lowercase();
    lower.contains("@deepseek-ai/dsh-") || lower.contains("deepseek harness")
}

fn optimize_harness_output(exit_code: i32, text: &str) -> Action {
    let lines: Vec<&str> = text.lines().collect();
    if lines.len() <= HEAD_LINES + TAIL_LINES + 1 {
        return Action::Pass;
    }

    let mut keep = vec![false; lines.len()];
    mark_range(&mut keep, 0, HEAD_LINES);
    mark_range(
        &mut keep,
        lines.len().saturating_sub(TAIL_LINES),
        lines.len(),
    );

    for (index, line) in lines.iter().enumerate() {
        if is_summary(line) {
            mark_range(
                &mut keep,
                index.saturating_sub(1),
                (index + 2).min(lines.len()),
            );
        }
        if is_diagnostic(line, exit_code != 0) {
            let context = if exit_code == 0 { 1 } else { 3 };
            mark_range(
                &mut keep,
                index.saturating_sub(context),
                (index + context + 1).min(lines.len()),
            );
        }
    }

    let mut compact = String::with_capacity(text.len().min(16 << 10));
    let mut index = 0;
    while index < lines.len() {
        if keep[index] {
            push_line(&mut compact, lines[index]);
            index += 1;
            continue;
        }
        let start = index;
        while index < lines.len() && !keep[index] {
            index += 1;
        }
        push_line(
            &mut compact,
            &format!(
                "... {} routine DeepSeek Harness lines omitted by TokenSaver ...",
                index - start
            ),
        );
    }
    if !text.ends_with('\n') {
        compact.pop();
    }
    if compact.len().saturating_mul(100) >= text.len().saturating_mul(80) {
        return Action::Pass;
    }
    Action::optimized(compact).unwrap_or(Action::Pass)
}

fn mark_range(keep: &mut [bool], start: usize, end: usize) {
    for value in &mut keep[start..end] {
        *value = true;
    }
}

fn push_line(output: &mut String, line: &str) {
    output.push_str(line);
    output.push('\n');
}

fn is_summary(line: &str) -> bool {
    let line =
        line.trim_start_matches(|character: char| character.is_whitespace() || character == '│');
    let lower = line.to_ascii_lowercase();
    [
        "test files",
        "tests ",
        "duration ",
        "tasks:",
        "cached:",
        "time:",
        "packages:",
        "lint summary",
        "typecheck summary",
    ]
    .iter()
    .any(|prefix| lower.starts_with(prefix))
        || lower.contains("elifecycle")
        || lower.contains("err_pnpm_")
}

fn is_diagnostic(line: &str, failed_command: bool) -> bool {
    let lower = line.to_ascii_lowercase();
    let strong = lower.contains("error:")
        || lower.contains(" error ")
        || lower.contains("exception")
        || lower.contains("panic")
        || lower.contains("failed:")
        || lower.contains("failure:")
        || lower.contains("warning:")
        || lower.contains("warn ")
        || lower.trim_start().starts_with(['✖', '×']);
    strong
        || failed_command
            && (lower.contains("assertionerror")
                || lower.contains("expected:")
                || lower.contains("received:")
                || lower.contains("caused by:"))
}

fn main() {
    run(DeepSeekHarnessOptimizer);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn harness_output(lines: usize, diagnostics: &[(usize, &str)]) -> String {
        let mut output = (0..lines)
            .map(|index| format!("@deepseek-ai/dsh-package task output {index}"))
            .collect::<Vec<_>>();
        for (index, value) in diagnostics {
            output[*index] = (*value).to_owned();
        }
        output.join("\n") + "\n"
    }

    fn optimized(action: Action) -> String {
        match action {
            Action::Optimize(content) => content,
            Action::Pass => panic!("expected optimized action"),
        }
    }

    #[test]
    fn request_eligibility_is_narrow_and_case_insensitive() {
        assert!(eligible_request("dsh.cmd", "anything"));
        assert!(eligible_request("PNPM.CMD", "scope @deepseek-ai/dsh-core"));
        assert!(eligible_request("node", "DeepSeek Harness started"));
        assert!(!eligible_request("pnpm", "unrelated workspace"));
        assert!(!eligible_request("cargo", "@deepseek-ai/dsh-core"));
    }

    #[test]
    fn short_and_barely_reducible_output_passes() {
        assert_eq!(optimize_harness_output(0, "short\noutput\n"), Action::Pass);
        let text = harness_output(34, &[(15, "warning: keep")]);
        assert_eq!(optimize_harness_output(0, &text), Action::Pass);
    }

    #[test]
    fn successful_run_preserves_boundaries_warnings_and_summaries() {
        let input = harness_output(
            160,
            &[
                (70, "warning: optional adapter unavailable"),
                (120, "Test Files  42 passed (42)"),
                (121, "Tests  900 passed (900)"),
                (122, "Duration  12.4s"),
            ],
        );
        let output = optimized(optimize_harness_output(0, &input));
        assert!(output.starts_with("@deepseek-ai/dsh-package task output 0\n"));
        assert!(output.contains(
            "@deepseek-ai/dsh-package task output 69\nwarning: optional adapter unavailable\n@deepseek-ai/dsh-package task output 71"
        ));
        assert!(output.contains("Test Files  42 passed (42)"));
        assert!(output.contains("Tests  900 passed (900)"));
        assert!(output.contains("Duration  12.4s"));
        assert!(output.contains("routine DeepSeek Harness lines omitted by TokenSaver"));
        assert!(output.ends_with("@deepseek-ai/dsh-package task output 159\n"));
        assert!(output.len() * 100 < input.len() * 80);
    }

    #[test]
    fn failed_run_keeps_each_diagnostic_context_without_reordering() {
        let input = harness_output(
            180,
            &[
                (60, "ERROR: build graph invariant failed"),
                (130, "AssertionError: expected event pair"),
                (131, "Expected: tool/call before tool/result"),
                (132, "Received: tool/result"),
            ],
        );
        let output = optimized(optimize_harness_output(1, &input));
        for retained in [57, 63, 127, 135] {
            assert!(
                output.contains(&format!("task output {retained}")),
                "missing retained line {retained}"
            );
        }
        for diagnostic in [
            "ERROR: build graph invariant failed",
            "AssertionError: expected event pair",
            "Expected: tool/call before tool/result",
            "Received: tool/result",
        ] {
            assert!(output.contains(diagnostic), "missing {diagnostic}");
        }
        assert!(output.find("invariant failed").unwrap() < output.find("AssertionError").unwrap());
    }

    #[test]
    fn output_is_deterministic_and_preserves_final_newline_shape() {
        let with_newline = harness_output(100, &[]);
        let first = optimize_harness_output(0, &with_newline);
        assert_eq!(first, optimize_harness_output(0, &with_newline));
        assert!(optimized(first).ends_with('\n'));

        let without_newline = with_newline.trim_end_matches('\n');
        assert!(!optimized(optimize_harness_output(0, without_newline)).ends_with('\n'));
    }
}
