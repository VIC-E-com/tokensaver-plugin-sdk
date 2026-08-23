use crate::manifest::ValidationError;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::path::Path;

const RELEASE_DOMAIN: &[u8] = b"tokensaver-plugin-release-v1";
const RELEASE_PREFIX: &str = "tsr1_";
const ACTIVATION_PREFIX: &str = "tsa1_";

pub fn executable_digest(path: &Path) -> Result<String, ValidationError> {
    let mut file = File::open(path).map_err(|error| {
        ValidationError::new(
            "identity.read",
            format!("could not hash {}: {error}", path.display()),
            "Check executable permissions and retry.",
        )
    })?;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 64 << 10];
    loop {
        let read = file.read(&mut buffer).map_err(|error| {
            ValidationError::new(
                "identity.read",
                format!("could not hash {}: {error}", path.display()),
                "Check executable permissions and retry.",
            )
        })?;
        if read == 0 {
            break;
        }
        hash.update(&buffer[..read]);
    }
    Ok(format!("sha256:{:x}", hash.finalize()))
}

pub fn release_id(plugin_id: &str, version: &str, platform: &str, artifact_digest: &str) -> String {
    let mut hash = Sha256::new();
    for part in [
        RELEASE_DOMAIN,
        plugin_id.as_bytes(),
        version.as_bytes(),
        platform.as_bytes(),
        artifact_digest.as_bytes(),
    ] {
        hash.update((part.len() as u64).to_be_bytes());
        hash.update(part);
    }
    format!("{RELEASE_PREFIX}{:x}", hash.finalize())
}

pub fn new_activation_attempt_id() -> Result<String, ValidationError> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|error| {
        ValidationError::new(
            "identity.random",
            format!("could not generate activation-attempt id: {error}"),
            "Check operating-system random-source availability and retry.",
        )
    })?;
    Ok(format!("{ACTIVATION_PREFIX}{}", hex(&bytes)))
}

pub fn valid_release_id(value: &str) -> bool {
    valid_prefixed_hex(value, RELEASE_PREFIX, 64)
}

pub fn valid_activation_attempt_id(value: &str) -> bool {
    valid_prefixed_hex(value, ACTIVATION_PREFIX, 32)
}

fn valid_prefixed_hex(value: &str, prefix: &str, digits: usize) -> bool {
    value.len() == prefix.len() + digits
        && value.starts_with(prefix)
        && value[prefix.len()..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct IdentityCorpus {
        schema_version: u32,
        algorithm: String,
        cases: Vec<IdentityCase>,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct IdentityCase {
        plugin_id: String,
        version: String,
        platform: String,
        artifact_digest: String,
        release_id: String,
    }

    #[test]
    fn shared_release_identity_corpus_matches_rust() {
        let corpus: IdentityCorpus =
            serde_json::from_str(include_str!("../../../conformance/identity-v1.cases.json"))
                .expect("identity corpus");
        assert_eq!(corpus.schema_version, 1);
        assert_eq!(corpus.algorithm, "tsr1-sha256-length-prefixed-v1");
        assert!(!corpus.cases.is_empty());
        for case in corpus.cases {
            let actual = release_id(
                &case.plugin_id,
                &case.version,
                &case.platform,
                &case.artifact_digest,
            );
            assert_eq!(actual, case.release_id);
            assert!(valid_release_id(&actual));
        }
    }

    #[test]
    fn activation_attempt_ids_are_fresh_bounded_and_valid() {
        let first = new_activation_attempt_id().expect("first activation id");
        let second = new_activation_attempt_id().expect("second activation id");
        assert!(valid_activation_attempt_id(&first));
        assert!(valid_activation_attempt_id(&second));
        assert_ne!(first, second);
        assert!(!valid_activation_attempt_id("tsa1_not-hex"));
    }
}
