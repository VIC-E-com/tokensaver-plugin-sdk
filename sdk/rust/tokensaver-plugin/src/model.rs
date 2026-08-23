use std::error::Error;
use std::fmt;

/// Maximum decoded input or optimized output accepted by the v1 SDK.
pub const MAX_CONTENT_BYTES: usize = 16 << 20;

/// A host-validated command-output optimization request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Request {
    kind: String,
    program: String,
    exit_code: i32,
    text: String,
    budget_ms: u32,
}

impl Request {
    pub(crate) fn new(
        kind: String,
        program: String,
        exit_code: i32,
        text: String,
        budget_ms: u32,
    ) -> Self {
        Self {
            kind,
            program,
            exit_code,
            text,
            budget_ms,
        }
    }

    /// TokenSaver command-output kind: test, build, lint, status, or log.
    pub fn kind(&self) -> &str {
        &self.kind
    }

    /// Executable basename measured by the host. Command arguments are never
    /// disclosed to a v1 optimizer plugin.
    pub fn program(&self) -> &str {
        &self.program
    }

    pub fn exit_code(&self) -> i32 {
        self.exit_code
    }

    pub fn text(&self) -> &str {
        &self.text
    }

    /// Advisory budget. The host enforces its own deadline independently.
    pub fn budget_ms(&self) -> u32 {
        self.budget_ms
    }
}

/// A plugin's response. TokenSaver independently measures and validates an
/// optimized response before displaying it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Action {
    Pass,
    Optimize(String),
}

impl Action {
    /// Constructs a safe UTF-8 optimization proposal.
    pub fn optimized(content: impl Into<String>) -> Result<Self, ActionError> {
        let content = content.into();
        if content.is_empty() {
            return Err(ActionError::Empty);
        }
        if content.as_bytes().contains(&0) {
            return Err(ActionError::NulByte);
        }
        if content.len() > MAX_CONTENT_BYTES {
            return Err(ActionError::TooLarge {
                actual: content.len(),
                maximum: MAX_CONTENT_BYTES,
            });
        }
        Ok(Self::Optimize(content))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ActionError {
    Empty,
    NulByte,
    TooLarge { actual: usize, maximum: usize },
}

impl fmt::Display for ActionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("optimized content cannot be empty"),
            Self::NulByte => formatter.write_str("optimized content cannot contain NUL bytes"),
            Self::TooLarge { actual, maximum } => {
                write!(
                    formatter,
                    "optimized content is {actual} bytes; maximum is {maximum}"
                )
            }
        }
    }
}

impl Error for ActionError {}

/// The only behavior a Rust optimizer plugin implements.
pub trait Optimizer {
    /// Reverse-DNS id matching the plugin manifest and initialize response.
    const PLUGIN_ID: &'static str;
    /// Semver version matching the plugin manifest and initialize response.
    const VERSION: &'static str;

    fn optimize(&self, request: Request) -> Action;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn optimized_action_enforces_sdk_boundaries() {
        assert_eq!(Action::optimized(""), Err(ActionError::Empty));
        assert_eq!(Action::optimized("bad\0output"), Err(ActionError::NulByte));
        assert!(matches!(
            Action::optimized("x".repeat(MAX_CONTENT_BYTES + 1)),
            Err(ActionError::TooLarge { .. })
        ));
        assert_eq!(
            Action::optimized("safe").expect("safe action"),
            Action::Optimize("safe".into())
        );
    }
}
