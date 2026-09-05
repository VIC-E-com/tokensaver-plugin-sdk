use tokensaver_plugin::{Action, Optimizer, Request, run};

struct Ponytails;

impl Optimizer for Ponytails {
    const PLUGIN_ID: &'static str = "com.vic-e.tokensaver.ponytails";
    const VERSION: &'static str = "0.1.3";

    fn optimize(&self, request: Request) -> Action {
        optimize_text(request.exit_code(), request.text())
    }
}

fn optimize_text(exit_code: i32, text: &str) -> Action {
    let lines: Vec<&str> = text.lines().collect();
    if lines.len() < 40 {
        return Action::Pass;
    }

    let tail_start = lines.len() - 20;
    let last_error = (exit_code != 0)
        .then(|| last_error_line(&lines))
        .flatten()
        .filter(|index| *index >= 10 && *index < tail_start);
    let compact = match last_error {
        Some(error) => {
            let error_start = error.saturating_sub(5).max(10);
            let error_end = (error_start + 10).min(tail_start);
            format!(
                "{}\n... {} lines omitted ...\n{}\n... {} lines omitted ...\n{}",
                lines[..10].join("\n"),
                error_start - 10,
                lines[error_start..error_end].join("\n"),
                tail_start - error_end,
                lines[tail_start..].join("\n")
            )
        }
        None => format!(
            "{}\n... {} lines omitted ...\n{}",
            lines[..10].join("\n"),
            tail_start - 10,
            lines[tail_start..].join("\n")
        ),
    };
    Action::optimized(compact).unwrap_or(Action::Pass)
}

fn last_error_line(lines: &[&str]) -> Option<usize> {
    lines.iter().rposition(|line| {
        let line = line.to_ascii_lowercase();
        line.contains("error") || line.contains("failed") || line.contains("panic")
    })
}

fn main() {
    run(Ponytails);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_anchor_preserves_failure_context_and_final_status() {
        let mut lines: Vec<String> = (0..100).map(|index| format!("line {index}")).collect();
        lines[52] = "ERROR important failure".into();
        let Action::Optimize(output) = optimize_text(1, &lines.join("\n")) else {
            panic!("failure output should be optimized");
        };
        assert!(output.contains("ERROR important failure"));
        assert!(output.contains("line 47"));
        assert!(output.ends_with("line 99"));
        assert!(!output.contains("line 46\n"));
    }

    #[test]
    fn missing_error_falls_back_to_standard_head_and_tail() {
        let lines: Vec<String> = (0..100).map(|index| format!("line {index}")).collect();
        assert_eq!(
            optimize_text(1, &lines.join("\n")),
            optimize_text(0, &lines.join("\n"))
        );
    }

    #[test]
    fn short_output_passes_and_long_output_compacts() {
        assert_eq!(optimize_text(0, "short\noutput"), Action::Pass);
        let input = (0..100)
            .map(|index| format!("line {index}"))
            .collect::<Vec<_>>()
            .join("\n");
        let Action::Optimize(output) = optimize_text(0, &input) else {
            panic!("long output should be optimized");
        };
        assert!(output.contains("70 lines omitted"));
        assert!(output.starts_with("line 0\n"));
        assert!(output.ends_with("line 99"));
    }
}
