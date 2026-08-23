use crate::certification::CertificationSubject;
use crate::certification_trust::{
    CertificationDecisionContext, VerifiedCertification, verify_certification_evidence,
};
use crate::manifest::ValidationError;
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

const DEFAULT_LOCK_TIMEOUT: Duration = Duration::from_secs(2);
const LOCK_RETRY_INTERVAL: Duration = Duration::from_millis(10);
const MAX_LOCK_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_STATE_MARKERS: usize = 10_000;
const MAX_STATE_MARKER_BYTES: u64 = 1 << 10;

/// Exact issuer documents obtained through a host-owned authenticated transport.
///
/// The trust store is deliberately absent. It must be provisioned independently and cannot be
/// learned from registry evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertificationEvidenceDocuments {
    pub report: Vec<u8>,
    pub envelope: Vec<u8>,
    pub revocations: Vec<u8>,
}

/// Host transport boundary for obtaining certification evidence.
///
/// Implementations must authenticate the intended issuer, bound response sizes before retaining
/// them, avoid ambient credentials, and reject cross-origin redirects. This SDK intentionally
/// provides no HTTP client and grants no network authority.
pub trait AuthenticatedCertificationSource: Send + Sync {
    fn fetch(
        &self,
        expected_subject: &CertificationSubject,
    ) -> Result<CertificationEvidenceDocuments, ValidationError>;
}

/// Durable append-only rollback state for one independently provisioned trust domain.
#[derive(Clone, Debug)]
pub struct CertificationRevocationStateStore {
    root: PathBuf,
    lock_timeout: Duration,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RevocationStateMarker {
    schema_version: u32,
    issuer_id: String,
    sequence: u64,
}

struct StateLock(File);

impl Drop for StateLock {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.0);
    }
}

impl CertificationRevocationStateStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            lock_timeout: DEFAULT_LOCK_TIMEOUT,
        }
    }

    pub fn with_lock_timeout(
        root: impl Into<PathBuf>,
        lock_timeout: Duration,
    ) -> Result<Self, ValidationError> {
        if lock_timeout.is_zero() || lock_timeout > MAX_LOCK_TIMEOUT {
            return Err(distribution_error(
                "certification.stateLockTimeout",
                "certification state lock timeout must be between 1 millisecond and 30 seconds",
                "Use a bounded nonzero lock timeout no longer than 30 seconds.",
            ));
        }
        Ok(Self {
            root: root.into(),
            lock_timeout,
        })
    }

    pub fn highest_sequence(&self, issuer_id: &str) -> Result<Option<u64>, ValidationError> {
        validate_issuer_id(issuer_id)?;
        self.prepare_layout()?;
        let _lock = self.acquire_lock(issuer_id)?;
        let directory = self.issuer_directory(issuer_id);
        ensure_directory(&directory, "certification.stateDirectory")?;
        scan_highest_sequence(&directory, issuer_id)
    }

    /// Records a cryptographically verified sequence without ever replacing an older marker.
    /// Equal sequences are idempotent. Older sequences fail closed.
    pub(crate) fn record_verified(
        &self,
        verified: &VerifiedCertification,
    ) -> Result<(), ValidationError> {
        validate_issuer_id(&verified.issuer_id)?;
        self.prepare_layout()?;
        let _lock = self.acquire_lock(&verified.issuer_id)?;
        let directory = self.issuer_directory(&verified.issuer_id);
        ensure_directory(&directory, "certification.stateDirectory")?;
        let highest = scan_highest_sequence(&directory, &verified.issuer_id)?;
        if highest.is_some_and(|sequence| verified.revocation_sequence < sequence) {
            return Err(distribution_error(
                "certification.revocationRollback",
                "verified revocation sequence is older than durable state",
                "Reject rollback and fetch a signed list with an equal or newer sequence.",
            ));
        }
        if highest == Some(verified.revocation_sequence) {
            return Ok(());
        }
        let marker_count = marker_count(&directory)?;
        if marker_count >= MAX_STATE_MARKERS {
            return Err(distribution_error(
                "certification.stateMarkerLimit",
                "certification revocation state contains too many sequence markers",
                "Archive this trust domain through an administrator-controlled migration before accepting more evidence.",
            ));
        }
        self.append_marker(
            &directory,
            &verified.issuer_id,
            verified.revocation_sequence,
        )
    }

    fn prepare_layout(&self) -> Result<(), ValidationError> {
        ensure_directory(&self.root, "certification.stateRoot")?;
        ensure_directory(&self.root.join("locks"), "certification.stateLocks")?;
        ensure_directory(&self.root.join("pending"), "certification.statePending")?;
        ensure_directory(&self.root.join("issuers"), "certification.stateIssuers")
    }

    fn issuer_directory(&self, issuer_id: &str) -> PathBuf {
        self.root
            .join("issuers")
            .join(format!("sha256-{}", issuer_hash(issuer_id)))
    }

    fn acquire_lock(&self, issuer_id: &str) -> Result<StateLock, ValidationError> {
        let path = self
            .root
            .join("locks")
            .join(format!("sha256-{}.lock", issuer_hash(issuer_id)));
        reject_symlink(&path, "certification.stateLock")?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|error| state_io_error("certification.stateLock", &path, error))?;
        let deadline = Instant::now() + self.lock_timeout;
        loop {
            match FileExt::try_lock_exclusive(&file) {
                Ok(()) => return Ok(StateLock(file)),
                Err(error) if lock_is_contended(&error) => {
                    if Instant::now() >= deadline {
                        return Err(distribution_error(
                            "certification.stateLockTimeout",
                            "timed out waiting for the certification revocation state lock",
                            "Retry after the other verifier finishes; do not accept evidence without durable rollback state.",
                        ));
                    }
                    thread::sleep(LOCK_RETRY_INTERVAL);
                }
                Err(error) => {
                    return Err(state_io_error("certification.stateLock", &path, error));
                }
            }
        }
    }

    fn append_marker(
        &self,
        directory: &Path,
        issuer_id: &str,
        sequence: u64,
    ) -> Result<(), ValidationError> {
        let marker = RevocationStateMarker {
            schema_version: 1,
            issuer_id: issuer_id.to_owned(),
            sequence,
        };
        let mut bytes = serde_json::to_vec(&marker).map_err(|error| {
            ValidationError::new(
                "certification.stateSerialize",
                format!("could not serialize certification revocation state: {error}"),
                "Report this internal SDK error and reject the certification decision.",
            )
        })?;
        bytes.push(b'\n');
        let mut nonce = [0u8; 16];
        getrandom::fill(&mut nonce).map_err(|error| {
            ValidationError::new(
                "certification.stateRandom",
                format!("could not create a unique certification state marker: {error}"),
                "Restore operating-system randomness and retry verification.",
            )
        })?;
        let pending = self.root.join("pending").join(format!(
            "{}-{}-{}.tmp",
            std::process::id(),
            sequence,
            hex_bytes(&nonce)
        ));
        reject_symlink(&pending, "certification.statePending")?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&pending)
            .map_err(|error| state_io_error("certification.statePending", &pending, error))?;
        let result = (|| {
            file.write_all(&bytes)
                .and_then(|()| file.sync_all())
                .map_err(|error| state_io_error("certification.stateWrite", &pending, error))?;
            drop(file);
            let final_path = directory.join(marker_file_name(sequence));
            fs::hard_link(&pending, &final_path)
                .map_err(|error| state_io_error("certification.stateCommit", &final_path, error))?;
            sync_directory(directory)?;
            Ok(())
        })();
        let cleanup = fs::remove_file(&pending);
        match (result, cleanup) {
            (Err(error), _) => Err(error),
            (Ok(()), Ok(())) => Ok(()),
            (Ok(()), Err(error)) if error.kind() == ErrorKind::NotFound => Ok(()),
            (Ok(()), Err(error)) => Err(state_io_error(
                "certification.stateCleanup",
                &pending,
                error,
            )),
        }
    }
}

/// Fetches issuer evidence, verifies it against a separately provisioned trust store, then
/// durably records rollback state before returning an accepted certification decision.
pub fn fetch_verify_and_record_certification<S: AuthenticatedCertificationSource + ?Sized>(
    source: &S,
    trust_store_bytes: &[u8],
    expected_subject: &CertificationSubject,
    now_unix: u64,
    state_store: &CertificationRevocationStateStore,
) -> Result<VerifiedCertification, ValidationError> {
    let evidence = source.fetch(expected_subject)?;
    let verified = verify_certification_evidence(
        &evidence.report,
        &evidence.envelope,
        trust_store_bytes,
        &evidence.revocations,
        expected_subject,
        CertificationDecisionContext {
            now_unix,
            minimum_revocation_sequence: 0,
        },
    )?;
    state_store.record_verified(&verified)?;
    Ok(verified)
}

fn lock_is_contended(error: &std::io::Error) -> bool {
    if error.kind() == ErrorKind::WouldBlock {
        return true;
    }
    matches!(
        (
            error.raw_os_error(),
            fs2::lock_contended_error().raw_os_error()
        ),
        (Some(actual), Some(expected)) if actual == expected
    )
}

fn ensure_directory(path: &Path, code: &'static str) -> Result<(), ValidationError> {
    reject_symlink(path, code)?;
    fs::create_dir_all(path).map_err(|error| state_io_error(code, path, error))?;
    let metadata = fs::symlink_metadata(path).map_err(|error| state_io_error(code, path, error))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(distribution_error(
            code,
            "certification state path is not a real directory",
            "Use a private local directory without symbolic links for revocation state.",
        ));
    }
    Ok(())
}

fn reject_symlink(path: &Path, code: &'static str) -> Result<(), ValidationError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(distribution_error(
            code,
            "certification state path is a symbolic link",
            "Use a private local path without symbolic links for revocation state.",
        )),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(state_io_error(code, path, error)),
    }
}

fn scan_highest_sequence(
    directory: &Path,
    issuer_id: &str,
) -> Result<Option<u64>, ValidationError> {
    let mut highest = None;
    let mut count = 0usize;
    for entry in fs::read_dir(directory)
        .map_err(|error| state_io_error("certification.stateRead", directory, error))?
    {
        let entry =
            entry.map_err(|error| state_io_error("certification.stateRead", directory, error))?;
        count = count.saturating_add(1);
        if count > MAX_STATE_MARKERS {
            return Err(distribution_error(
                "certification.stateMarkerLimit",
                "certification revocation state contains too many sequence markers",
                "Reject the state and perform an administrator-controlled state migration.",
            ));
        }
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| state_io_error("certification.stateRead", &path, error))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(distribution_error(
                "certification.stateEntry",
                "certification revocation state contains a non-file or symbolic-link entry",
                "Reject corrupted state and restore it from trusted local administration.",
            ));
        }
        if metadata.len() == 0 || metadata.len() > MAX_STATE_MARKER_BYTES {
            return Err(distribution_error(
                "certification.stateEntry",
                "certification revocation state marker is empty or oversized",
                "Reject corrupted state and restore it from trusted local administration.",
            ));
        }
        let name = entry.file_name();
        let name = name.to_str().ok_or_else(|| {
            distribution_error(
                "certification.stateEntry",
                "certification revocation state marker name is not valid Unicode",
                "Reject corrupted state and restore it from trusted local administration.",
            )
        })?;
        let sequence = parse_marker_file_name(name).ok_or_else(|| {
            distribution_error(
                "certification.stateEntry",
                "certification revocation state contains an unexpected entry",
                "Reject corrupted state and restore it from trusted local administration.",
            )
        })?;
        let bytes = fs::read(&path)
            .map_err(|error| state_io_error("certification.stateRead", &path, error))?;
        crate::superec::validate_unambiguous_json(&bytes).map_err(|error| {
            ValidationError::new(
                "certification.stateEntry",
                format!("certification revocation state is not unambiguous JSON: {error}"),
                "Reject corrupted state and restore it from trusted local administration.",
            )
        })?;
        let marker: RevocationStateMarker = serde_json::from_slice(&bytes).map_err(|error| {
            ValidationError::new(
                "certification.stateEntry",
                format!("certification revocation state does not match its v1 contract: {error}"),
                "Reject corrupted state and restore it from trusted local administration.",
            )
        })?;
        if marker.schema_version != 1
            || marker.issuer_id != issuer_id
            || marker.sequence != sequence
        {
            return Err(distribution_error(
                "certification.stateEntry",
                "certification revocation state marker identity does not match its path",
                "Reject corrupted state and restore it from trusted local administration.",
            ));
        }
        highest = Some(highest.map_or(sequence, |value: u64| value.max(sequence)));
    }
    Ok(highest)
}

fn marker_count(directory: &Path) -> Result<usize, ValidationError> {
    fs::read_dir(directory)
        .map_err(|error| state_io_error("certification.stateRead", directory, error))?
        .try_fold(0usize, |count, entry| {
            entry
                .map(|_| count.saturating_add(1))
                .map_err(|error| state_io_error("certification.stateRead", directory, error))
        })
}

fn marker_file_name(sequence: u64) -> String {
    format!("sequence-{sequence:020}.json")
}

fn parse_marker_file_name(name: &str) -> Option<u64> {
    let digits = name.strip_prefix("sequence-")?.strip_suffix(".json")?;
    if digits.len() != 20 || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let sequence = digits.parse().ok()?;
    (marker_file_name(sequence) == name).then_some(sequence)
}

fn issuer_hash(issuer_id: &str) -> String {
    hex_bytes(&Sha256::digest(issuer_id.as_bytes()))
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("write hex");
    }
    output
}

#[cfg(unix)]
fn sync_directory(directory: &Path) -> Result<(), ValidationError> {
    File::open(directory)
        .and_then(|file| file.sync_all())
        .map_err(|error| state_io_error("certification.stateCommit", directory, error))
}

#[cfg(not(unix))]
fn sync_directory(_directory: &Path) -> Result<(), ValidationError> {
    Ok(())
}

fn validate_issuer_id(issuer_id: &str) -> Result<(), ValidationError> {
    if !(1..=128).contains(&issuer_id.len())
        || !issuer_id.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':' | b'/')
        })
    {
        return Err(distribution_error(
            "certification.stateIssuer",
            "certification state issuer id is invalid",
            "Use the bounded issuer id authenticated by certification verification.",
        ));
    }
    Ok(())
}

fn state_io_error(code: &'static str, path: &Path, error: std::io::Error) -> ValidationError {
    ValidationError::new(
        code,
        format!(
            "certification state operation failed at {}: {error}",
            path.display()
        ),
        "Keep rollback state on a writable private local filesystem and reject the decision if persistence fails.",
    )
}

fn distribution_error(
    code: &'static str,
    message: &'static str,
    remediation: &'static str,
) -> ValidationError {
    ValidationError::new(code, message, remediation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certification::{
        CertificationAuthority, CertificationLevel, CertificationReport, CertificationSubject,
    };
    use std::sync::{Arc, Barrier};
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos();
            Self(std::env::temp_dir().join(format!(
                "tokensaver-{label}-{}-{unique}",
                std::process::id()
            )))
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn subject() -> CertificationSubject {
        CertificationSubject {
            plugin_id: "com.example.plugin".into(),
            version: "1.0.0".into(),
            platform: "linux-x64".into(),
            api_version: 1,
            artifact_digest: format!("sha256:{}", "a".repeat(64)),
            package_digest: format!("sha256:{}", "b".repeat(64)),
            release_id: format!("tsr1_{}", "c".repeat(64)),
        }
    }

    fn verified(sequence: u64) -> VerifiedCertification {
        let subject = subject();
        VerifiedCertification {
            report: CertificationReport {
                schema_version: 1,
                ok: true,
                certification_level: CertificationLevel::Conformant,
                subject,
                authority: CertificationAuthority {
                    issuer_id: "com.tokensaver.registry".into(),
                    policy_id: "com.tokensaver.plugin-certification".into(),
                    policy_version: 1,
                    revocation_id: "cert:example".into(),
                },
                checks: Vec::new(),
            },
            issuer_id: "com.tokensaver.registry".into(),
            certification_key_id: "certification-2026-01".into(),
            revocation_key_id: "revocation-2026-01".into(),
            revocation_sequence: sequence,
        }
    }

    #[test]
    fn append_only_state_is_persistent_idempotent_and_rollback_safe() {
        let directory = TestDirectory::new("certification-state");
        let store = CertificationRevocationStateStore::new(&directory.0);
        assert_eq!(
            store
                .highest_sequence("com.tokensaver.registry")
                .expect("empty state"),
            None
        );
        store.record_verified(&verified(42)).expect("record state");
        store
            .record_verified(&verified(42))
            .expect("idempotent state");

        let reopened = CertificationRevocationStateStore::new(&directory.0);
        assert_eq!(
            reopened
                .highest_sequence("com.tokensaver.registry")
                .expect("persistent state"),
            Some(42)
        );
        assert_eq!(
            reopened
                .record_verified(&verified(41))
                .expect_err("rollback")
                .code,
            "certification.revocationRollback"
        );
        let issuer_directory = reopened.issuer_directory("com.tokensaver.registry");
        assert_eq!(
            fs::read_dir(issuer_directory)
                .expect("state entries")
                .count(),
            1
        );
    }

    #[test]
    fn concurrent_writers_serialize_and_preserve_the_highest_sequence() {
        let directory = TestDirectory::new("certification-state-concurrent");
        let store = Arc::new(CertificationRevocationStateStore::new(&directory.0));
        let barrier = Arc::new(Barrier::new(16));
        let threads = (1..=16)
            .map(|sequence| {
                let store = Arc::clone(&store);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    store.record_verified(&verified(sequence))
                })
            })
            .collect::<Vec<_>>();
        for thread in threads {
            let result = thread.join().expect("writer thread");
            if let Err(error) = result {
                assert_eq!(error.code, "certification.revocationRollback");
            }
        }
        assert_eq!(
            store
                .highest_sequence("com.tokensaver.registry")
                .expect("concurrent state"),
            Some(16)
        );
    }

    #[test]
    fn malformed_unknown_and_mismatched_state_fail_closed() {
        let directory = TestDirectory::new("certification-state-corrupt");
        let store = CertificationRevocationStateStore::new(&directory.0);
        store.record_verified(&verified(7)).expect("record state");
        let issuer_directory = store.issuer_directory("com.tokensaver.registry");
        fs::write(issuer_directory.join("unexpected.json"), b"{}").expect("write unexpected state");
        assert_eq!(
            store
                .highest_sequence("com.tokensaver.registry")
                .expect_err("unexpected state")
                .code,
            "certification.stateEntry"
        );

        fs::remove_file(issuer_directory.join("unexpected.json")).expect("remove test corruption");
        fs::write(
            issuer_directory.join(marker_file_name(8)),
            br#"{"schemaVersion":1,"issuerId":"other.issuer","sequence":8}"#,
        )
        .expect("write mismatched state");
        assert_eq!(
            store
                .highest_sequence("com.tokensaver.registry")
                .expect_err("mismatched state")
                .code,
            "certification.stateEntry"
        );

        fs::remove_file(issuer_directory.join(marker_file_name(8)))
            .expect("remove mismatched state");
        fs::write(
            issuer_directory.join(marker_file_name(9)),
            br#"{"schemaVersion":1,"issuerId":"com.tokensaver.registry","sequence":9,"unknown":true}"#,
        )
        .expect("write unknown state field");
        assert_eq!(
            store
                .highest_sequence("com.tokensaver.registry")
                .expect_err("unknown state field")
                .code,
            "certification.stateEntry"
        );
    }

    #[test]
    fn invalid_issuer_and_unbounded_lock_timeout_are_rejected() {
        let directory = TestDirectory::new("certification-state-invalid");
        let store = CertificationRevocationStateStore::new(&directory.0);
        assert_eq!(
            store
                .highest_sequence("invalid issuer")
                .expect_err("issuer")
                .code,
            "certification.stateIssuer"
        );
        assert_eq!(
            CertificationRevocationStateStore::with_lock_timeout(&directory.0, Duration::ZERO)
                .expect_err("zero timeout")
                .code,
            "certification.stateLockTimeout"
        );
    }

    #[test]
    fn contended_state_lock_obeys_the_bounded_timeout() {
        let directory = TestDirectory::new("certification-state-lock-timeout");
        let store = CertificationRevocationStateStore::with_lock_timeout(
            &directory.0,
            Duration::from_millis(25),
        )
        .expect("bounded store");
        store.prepare_layout().expect("state layout");
        let lock_path = store.root.join("locks").join(format!(
            "sha256-{}.lock",
            issuer_hash("com.tokensaver.registry")
        ));
        let lock_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock_path)
            .expect("test lock file");
        FileExt::lock_exclusive(&lock_file).expect("hold state lock");
        let error = store
            .highest_sequence("com.tokensaver.registry")
            .expect_err("lock timeout");
        FileExt::unlock(&lock_file).expect("release state lock");
        assert_eq!(error.code, "certification.stateLockTimeout");
    }

    #[test]
    fn stale_pending_write_does_not_hide_committed_state() {
        let directory = TestDirectory::new("certification-state-pending");
        let store = CertificationRevocationStateStore::new(&directory.0);
        store.record_verified(&verified(11)).expect("record state");
        fs::write(
            store.root.join("pending").join("interrupted.tmp"),
            b"partial",
        )
        .expect("stale pending write");
        assert_eq!(
            store
                .highest_sequence("com.tokensaver.registry")
                .expect("committed state"),
            Some(11)
        );
    }

    #[cfg(unix)]
    #[test]
    fn symbolic_link_state_entry_is_rejected() {
        use std::os::unix::fs::symlink;

        let directory = TestDirectory::new("certification-state-symlink");
        let store = CertificationRevocationStateStore::new(&directory.0);
        store.record_verified(&verified(3)).expect("record state");
        let issuer_directory = store.issuer_directory("com.tokensaver.registry");
        symlink(
            issuer_directory.join(marker_file_name(3)),
            issuer_directory.join(marker_file_name(4)),
        )
        .expect("state symlink");
        assert_eq!(
            store
                .highest_sequence("com.tokensaver.registry")
                .expect_err("symlink state")
                .code,
            "certification.stateEntry"
        );
    }

    struct FailedSource;

    impl AuthenticatedCertificationSource for FailedSource {
        fn fetch(
            &self,
            _expected_subject: &CertificationSubject,
        ) -> Result<CertificationEvidenceDocuments, ValidationError> {
            Err(ValidationError::new(
                "certification.sourceUnavailable",
                "authenticated certification source is unavailable",
                "Retry without accepting certification.",
            ))
        }
    }

    #[test]
    fn authenticated_source_failure_never_creates_or_reuses_state() {
        let directory = TestDirectory::new("certification-source-failure");
        let store = CertificationRevocationStateStore::new(&directory.0);
        let error = fetch_verify_and_record_certification(
            &FailedSource,
            b"untrusted",
            &subject(),
            1,
            &store,
        )
        .expect_err("source failure");
        assert_eq!(error.code, "certification.sourceUnavailable");
        assert!(!directory.0.exists());
    }
}
