use crate::certification::CertificationLevel;
use crate::manifest::ValidationError;
use crate::package::PackageReport;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

const REPORT_SUFFIX: &str = ".tsplug.package-report.json";
const REPORT_MAX_BYTES: u64 = 1 << 20;
const PACKAGE_MAX_BYTES: u64 = 256 << 20;
const CATALOG_MAX_PACKAGES: usize = 32;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PackageCatalogEntry {
    pub file: String,
    pub size_bytes: usize,
    pub digest: String,
    #[serde(default)]
    pub release_id: String,
    pub certification_level: CertificationLevel,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PackageCatalog {
    pub schema_version: u32,
    pub plugin_id: String,
    pub version: String,
    pub packages: BTreeMap<String, PackageCatalogEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CatalogReport {
    pub schema_version: u32,
    pub ok: bool,
    pub plugin_id: String,
    pub version: String,
    pub catalog: String,
    pub catalog_size_bytes: usize,
    pub catalog_digest: String,
    pub package_count: usize,
    pub platforms: Vec<String>,
}

pub fn assemble_package_catalog(
    input: &Path,
    output: &Path,
) -> Result<CatalogReport, ValidationError> {
    if output.exists() {
        return Err(ValidationError::new(
            "catalog.exists",
            format!("catalog output already exists: {}", output.display()),
            "Choose a new --output path or remove the old catalog explicitly.",
        ));
    }
    if output.extension().and_then(|value| value.to_str()) != Some("json") {
        return Err(ValidationError::new(
            "catalog.extension",
            "catalog output must use the .json extension",
            "Pass --output with a filename ending in .json.",
        ));
    }
    let output_parent = output.parent().unwrap_or_else(|| Path::new("."));
    if !output_parent.is_dir() {
        return Err(ValidationError::new(
            "catalog.outputDirectory",
            format!(
                "catalog output directory does not exist: {}",
                output_parent.display()
            ),
            "Create the output directory and retry.",
        ));
    }
    let input_metadata = fs::symlink_metadata(input).map_err(catalog_read_error(input))?;
    if input_metadata.file_type().is_symlink() || !input_metadata.is_dir() {
        return Err(ValidationError::new(
            "catalog.inputDirectory",
            format!(
                "catalog input must be a regular directory: {}",
                input.display()
            ),
            "Use a directory containing only release packages and their package reports.",
        ));
    }

    let mut entries = fs::read_dir(input)
        .map_err(catalog_read_error(input))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            ValidationError::new(
                "catalog.read",
                format!("could not enumerate {}: {error}", input.display()),
                "Check catalog input permissions and retry.",
            )
        })?;
    entries.sort_by_key(std::fs::DirEntry::file_name);

    let mut packages = BTreeMap::<String, PathBuf>::new();
    let mut reports = BTreeMap::<String, PathBuf>::new();
    for entry in entries {
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(catalog_read_error(&path))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(ValidationError::new(
                "catalog.fileType",
                format!("catalog input must be a regular file: {}", path.display()),
                "Remove directories, symlinks, and special files from the catalog input.",
            ));
        }
        let name = entry.file_name().into_string().map_err(|_| {
            ValidationError::new(
                "catalog.filename",
                "catalog input filenames must be portable UTF-8",
                "Rename release files using portable ASCII names.",
            )
        })?;
        if name.ends_with(REPORT_SUFFIX) {
            let package_name = name
                .strip_suffix(".package-report.json")
                .expect("report suffix checked")
                .to_owned();
            if reports.insert(package_name.clone(), path).is_some() {
                return Err(duplicate_artifact_error(&package_name));
            }
        } else if name.ends_with(".tsplug") {
            if packages.insert(name.clone(), path).is_some() {
                return Err(duplicate_artifact_error(&name));
            }
        } else {
            return Err(ValidationError::new(
                "catalog.unexpectedFile",
                format!("unexpected catalog input file: {name}"),
                "Keep only .tsplug files and matching .tsplug.package-report.json files in the input directory.",
            ));
        }
    }
    if packages.is_empty() {
        return Err(ValidationError::new(
            "catalog.empty",
            "catalog input contains no .tsplug packages",
            "Add at least one package and its package report.",
        ));
    }
    if packages.len() > CATALOG_MAX_PACKAGES {
        return Err(ValidationError::new(
            "catalog.bounds",
            format!("catalog input contains {} packages", packages.len()),
            "Keep each catalog at or below 32 platform packages.",
        ));
    }
    if packages.keys().collect::<BTreeSet<_>>() != reports.keys().collect::<BTreeSet<_>>() {
        return Err(ValidationError::new(
            "catalog.reportSet",
            "every package must have exactly one matching .tsplug.package-report.json file",
            "Regenerate or rename reports so each package and report basename matches exactly.",
        ));
    }

    let mut plugin_id = None;
    let mut version = None;
    let mut catalog_packages = BTreeMap::new();
    for (name, package_path) in packages {
        let report_path = reports.get(&name).expect("matching report set");
        let report = read_report(report_path)?;
        validate_report_identity(&report, &name)?;
        match (&plugin_id, &version) {
            (None, None) => {
                plugin_id = Some(report.plugin_id.clone());
                version = Some(report.version.clone());
            }
            (Some(expected_id), Some(expected_version))
                if expected_id == &report.plugin_id && expected_version == &report.version => {}
            _ => {
                return Err(ValidationError::new(
                    "catalog.identity",
                    "all catalog packages must have one plugin id and release version",
                    "Build a separate catalog for each plugin release.",
                ));
            }
        }
        if !valid_platform(&report.platform) {
            return Err(ValidationError::new(
                "catalog.platform",
                format!("invalid package platform: {:?}", report.platform),
                "Use the lowercase OS-architecture platform emitted by a native tsp package run.",
            ));
        }
        let package_data = read_bounded_file(&package_path, PACKAGE_MAX_BYTES, "package")?;
        let actual_digest = digest(&package_data);
        if report.archive_size_bytes != package_data.len() || report.archive_digest != actual_digest
        {
            return Err(ValidationError::new(
                "catalog.packageIntegrity",
                format!("package size or digest does not match its report: {name}"),
                "Restore the package produced by the reported native build or rerun tsp package.",
            ));
        }
        let entry = PackageCatalogEntry {
            file: name,
            size_bytes: package_data.len(),
            digest: actual_digest,
            release_id: report.release_id.clone(),
            certification_level: report.certification_level,
        };
        if catalog_packages
            .insert(report.platform.clone(), entry)
            .is_some()
        {
            return Err(ValidationError::new(
                "catalog.duplicatePlatform",
                format!("duplicate package platform: {}", report.platform),
                "Include exactly one package for each platform in a release catalog.",
            ));
        }
    }

    let plugin_id = plugin_id.expect("non-empty package set");
    let version = version.expect("non-empty package set");
    let catalog = PackageCatalog {
        schema_version: 1,
        plugin_id: plugin_id.clone(),
        version: version.clone(),
        packages: catalog_packages,
    };
    let mut catalog_data = serde_json::to_vec_pretty(&catalog).map_err(|error| {
        ValidationError::new(
            "catalog.serialize",
            format!("could not serialize package catalog: {error}"),
            "Report this TokenSaver SDK defect.",
        )
    })?;
    catalog_data.push(b'\n');
    let catalog_digest = digest(&catalog_data);
    write_atomic(output, &catalog_data)?;
    Ok(CatalogReport {
        schema_version: 1,
        ok: true,
        plugin_id,
        version,
        catalog: output.display().to_string(),
        catalog_size_bytes: catalog_data.len(),
        catalog_digest,
        package_count: catalog.packages.len(),
        platforms: catalog.packages.into_keys().collect(),
    })
}

fn read_report(path: &Path) -> Result<PackageReport, ValidationError> {
    let data = read_bounded_file(path, REPORT_MAX_BYTES, "package report")?;
    let mut report: PackageReport = serde_json::from_slice(&data).map_err(|error| {
        ValidationError::new(
            "catalog.report",
            format!("could not parse {}: {error}", path.display()),
            "Use the unmodified --json output from tsp package.",
        )
    })?;
    let expected_release_id = crate::identity::release_id(
        &report.plugin_id,
        &report.version,
        &report.platform,
        &report.executable_digest,
    );
    if report.release_id.is_empty() {
        report.release_id = expected_release_id.clone();
    }
    if report.schema_version != 1
        || !report.ok
        || !report.reproducible
        || report.certification_level != CertificationLevel::Conformant
        || report.archive_size_bytes == 0
        || !valid_digest(&report.archive_digest)
        || !valid_digest(&report.executable_digest)
        || report.release_id != expected_release_id
    {
        return Err(ValidationError::new(
            "catalog.reportContract",
            format!("invalid v1 package report: {}", path.display()),
            "Regenerate the report with the current tsp package command.",
        ));
    }
    Ok(report)
}

fn validate_report_identity(
    report: &PackageReport,
    package_name: &str,
) -> Result<(), ValidationError> {
    let archive_name = Path::new(&report.archive)
        .file_name()
        .and_then(|name| name.to_str());
    let expected_name = format!(
        "{}-{}-{}.tsplug",
        report.plugin_id, report.version, report.platform
    );
    if archive_name != Some(package_name) || package_name != expected_name {
        return Err(ValidationError::new(
            "catalog.filename",
            format!("package filename is not canonical: {package_name}"),
            "Name packages <plugin-id>-<version>-<platform>.tsplug and keep the report archive basename identical.",
        ));
    }
    Ok(())
}

fn read_bounded_file(
    path: &Path,
    maximum: u64,
    description: &str,
) -> Result<Vec<u8>, ValidationError> {
    let metadata = fs::symlink_metadata(path).map_err(catalog_read_error(path))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(ValidationError::new(
            "catalog.fileType",
            format!("{description} must be a regular file: {}", path.display()),
            "Use the original regular release files without symlinks.",
        ));
    }
    if metadata.len() > maximum {
        return Err(ValidationError::new(
            "catalog.fileSize",
            format!("{description} is too large: {}", path.display()),
            "Keep packages below 256 MiB and package reports below 1 MiB.",
        ));
    }
    fs::read(path).map_err(catalog_read_error(path))
}

fn valid_platform(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.split('-').count() >= 2
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && !value.starts_with('-')
        && !value.ends_with('-')
        && !value.contains("--")
}

fn valid_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn duplicate_artifact_error(name: &str) -> ValidationError {
    ValidationError::new(
        "catalog.duplicate",
        format!("duplicate catalog input artifact: {name}"),
        "Keep exactly one copy of each package and package report.",
    )
}

fn catalog_read_error(path: &Path) -> impl FnOnce(std::io::Error) -> ValidationError + '_ {
    move |error| {
        ValidationError::new(
            "catalog.read",
            format!("could not read {}: {error}", path.display()),
            "Check catalog input permissions and retry.",
        )
    }
}

fn write_atomic(path: &Path, data: &[u8]) -> Result<(), ValidationError> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("catalog.json");
    let temporary = path.with_file_name(format!(".{file_name}.tmp-{}", std::process::id()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|error| {
                ValidationError::new(
                    "catalog.write",
                    format!("could not create {}: {error}", temporary.display()),
                    "Check output permissions and remove stale temporary files.",
                )
            })?;
        file.write_all(data)
            .and_then(|_| file.sync_all())
            .map_err(|error| {
                ValidationError::new(
                    "catalog.write",
                    format!("could not write {}: {error}", temporary.display()),
                    "Check free disk space and output permissions.",
                )
            })?;
        drop(file);
        fs::rename(&temporary, path).map_err(|error| {
            ValidationError::new(
                "catalog.commit",
                format!("could not commit {}: {error}", path.display()),
                "Check output permissions and retry.",
            )
        })
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn digest(data: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(data))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::package::PackageFileReport;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "tokensaver-tsp-catalog-{}-{unique}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create test directory");
            Self(path)
        }

        fn add(&self, platform: &str, data: &[u8]) -> PathBuf {
            let name = format!("com.example.plugin-1.2.3-{platform}.tsplug");
            let package = self.0.join(&name);
            fs::write(&package, data).expect("write package");
            let report = PackageReport {
                schema_version: 1,
                ok: true,
                plugin_id: "com.example.plugin".into(),
                version: "1.2.3".into(),
                platform: platform.into(),
                release_id: crate::identity::release_id(
                    "com.example.plugin",
                    "1.2.3",
                    platform,
                    &digest(b"executable"),
                ),
                certification_level: CertificationLevel::Conformant,
                archive: package.display().to_string(),
                archive_size_bytes: data.len(),
                archive_digest: digest(data),
                executable_digest: digest(b"executable"),
                reproducible: true,
                files: vec![PackageFileReport {
                    path: "plugin.json".into(),
                    size_bytes: 2,
                    digest: digest(b"{}"),
                    executable: false,
                }],
            };
            fs::write(
                self.0.join(format!("{name}.package-report.json")),
                serde_json::to_vec_pretty(&report).expect("serialize report"),
            )
            .expect("write report");
            package
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn catalog_is_sorted_deterministic_and_digest_verified() {
        let first = TestDirectory::new();
        first.add("windows-x64", b"windows package");
        first.add("linux-x64", b"linux package");
        let first_output = first.0.join("catalog.json");
        let report = assemble_package_catalog(&first.0, &first_output).expect("assemble catalog");
        assert!(report.ok);
        assert_eq!(report.platforms, ["linux-x64", "windows-x64"]);

        let second = TestDirectory::new();
        second.add("linux-x64", b"linux package");
        second.add("windows-x64", b"windows package");
        let second_output = second.0.join("catalog.json");
        assemble_package_catalog(&second.0, &second_output).expect("assemble second catalog");
        assert_eq!(
            fs::read(first_output).expect("read first catalog"),
            fs::read(second_output).expect("read second catalog")
        );
    }

    #[test]
    fn catalog_rejects_tampering_and_existing_output() {
        let directory = TestDirectory::new();
        let package = directory.add("linux-x64", b"original");
        fs::write(package, b"tampered").expect("tamper package");
        let output = directory.0.join("catalog.json");
        let error = assemble_package_catalog(&directory.0, &output).expect_err("reject tampering");
        assert_eq!(error.code, "catalog.packageIntegrity");

        fs::write(&output, b"keep").expect("write existing output");
        let error = assemble_package_catalog(&directory.0, &output).expect_err("refuse overwrite");
        assert_eq!(error.code, "catalog.exists");
        assert_eq!(fs::read(output).expect("read existing output"), b"keep");
    }

    #[test]
    fn catalog_rejects_a_self_promoted_package_report() {
        let directory = TestDirectory::new();
        directory.add("linux-x64", b"package");
        let report_path = directory
            .0
            .join("com.example.plugin-1.2.3-linux-x64.tsplug.package-report.json");
        let mut report: PackageReport =
            serde_json::from_slice(&fs::read(&report_path).expect("read package report"))
                .expect("parse package report");
        report.certification_level = CertificationLevel::Certified;
        fs::write(
            report_path,
            serde_json::to_vec_pretty(&report).expect("serialize promoted report"),
        )
        .expect("write promoted report");

        let error = assemble_package_catalog(&directory.0, &directory.0.join("catalog.json"))
            .expect_err("reject self-promoted report");
        assert_eq!(error.code, "catalog.reportContract");
    }

    #[test]
    fn catalog_rejects_a_tampered_release_identity() {
        let directory = TestDirectory::new();
        directory.add("linux-x64", b"package");
        let report_path = directory
            .0
            .join("com.example.plugin-1.2.3-linux-x64.tsplug.package-report.json");
        let mut report: PackageReport =
            serde_json::from_slice(&fs::read(&report_path).expect("read package report"))
                .expect("parse package report");
        report.release_id = format!("tsr1_{}", "f".repeat(64));
        fs::write(
            report_path,
            serde_json::to_vec_pretty(&report).expect("serialize tampered report"),
        )
        .expect("write tampered report");

        let error = assemble_package_catalog(&directory.0, &directory.0.join("catalog.json"))
            .expect_err("reject tampered release identity");
        assert_eq!(error.code, "catalog.reportContract");
    }

    #[test]
    fn catalog_derives_a_missing_additive_release_identity() {
        let directory = TestDirectory::new();
        directory.add("linux-x64", b"package");
        let report_path = directory
            .0
            .join("com.example.plugin-1.2.3-linux-x64.tsplug.package-report.json");
        let mut report: serde_json::Value =
            serde_json::from_slice(&fs::read(&report_path).expect("read legacy package report"))
                .expect("parse legacy package report");
        report
            .as_object_mut()
            .expect("package report object")
            .remove("releaseId");
        fs::write(
            report_path,
            serde_json::to_vec_pretty(&report).expect("serialize legacy report"),
        )
        .expect("write legacy report");

        let output = directory.0.join("catalog.json");
        assemble_package_catalog(&directory.0, &output).expect("accept legacy report");
        let catalog: PackageCatalog =
            serde_json::from_slice(&fs::read(output).expect("read catalog"))
                .expect("parse catalog");
        let entry = &catalog.packages["linux-x64"];
        assert!(crate::identity::valid_release_id(&entry.release_id));
    }

    #[test]
    fn catalog_rejects_unexpected_files_and_missing_reports() {
        let directory = TestDirectory::new();
        fs::write(directory.0.join("notes.txt"), b"unexpected").expect("write unexpected file");
        let error = assemble_package_catalog(&directory.0, &directory.0.join("catalog.json"))
            .expect_err("reject unexpected file");
        assert_eq!(error.code, "catalog.unexpectedFile");

        let directory = TestDirectory::new();
        fs::write(
            directory
                .0
                .join("com.example.plugin-1.2.3-linux-x64.tsplug"),
            b"package",
        )
        .expect("write package");
        let error = assemble_package_catalog(&directory.0, &directory.0.join("catalog.json"))
            .expect_err("reject missing report");
        assert_eq!(error.code, "catalog.reportSet");
    }
}
