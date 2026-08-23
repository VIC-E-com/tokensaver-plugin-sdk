use crate::certification::CertificationLevel;
use crate::manifest::{ResolvedPlugin, ValidationError};
use crate::protocol::validate_plugin;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};

const PACKAGE_MAX_BYTES: usize = 256 << 20;
const PACKAGE_MAX_FILES: usize = 4096;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PackageFileReport {
    pub path: String,
    pub size_bytes: usize,
    pub digest: String,
    pub executable: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PackageReport {
    pub schema_version: u32,
    pub ok: bool,
    pub plugin_id: String,
    pub version: String,
    pub platform: String,
    #[serde(default)]
    pub release_id: String,
    pub certification_level: CertificationLevel,
    pub archive: String,
    pub archive_size_bytes: usize,
    pub archive_digest: String,
    pub executable_digest: String,
    pub reproducible: bool,
    pub files: Vec<PackageFileReport>,
}

struct PackageFile {
    data: Vec<u8>,
    executable: bool,
}

pub fn default_package_path(plugin: &ResolvedPlugin) -> PathBuf {
    PathBuf::from(format!(
        "{}-{}-{}.tsplug",
        plugin.manifest.id, plugin.manifest.version, plugin.platform
    ))
}

pub fn package_plugin(
    plugin: &ResolvedPlugin,
    output: &Path,
) -> Result<PackageReport, ValidationError> {
    if output.exists() {
        return Err(ValidationError::new(
            "package.exists",
            format!("package output already exists: {}", output.display()),
            "Choose a new --output path or remove the old artifact explicitly.",
        ));
    }
    if output.extension().and_then(|value| value.to_str()) != Some("tsplug") {
        return Err(ValidationError::new(
            "package.extension",
            "package output must use the .tsplug extension",
            "Pass --output with a filename ending in .tsplug.",
        ));
    }
    let parent = output.parent().unwrap_or_else(|| Path::new("."));
    if !parent.is_dir() {
        return Err(ValidationError::new(
            "package.outputDirectory",
            format!(
                "package output directory does not exist: {}",
                parent.display()
            ),
            "Create the output directory and retry.",
        ));
    }

    let executable_before_validation = read_package_file(&plugin.executable)?;
    if digest(&executable_before_validation) != plugin.artifact_digest {
        return Err(ValidationError::new(
            "package.executableChanged",
            "runtime executable changed after its immutable release id was resolved",
            "Stop concurrent builds, resolve the plugin again, and package the stable artifact.",
        ));
    }
    let validation = validate_plugin(plugin)?;
    let executable_data = read_package_file(&plugin.executable)?;
    if executable_data != executable_before_validation {
        return Err(ValidationError::new(
            "package.executableChanged",
            "runtime executable changed while Level 1 conformance was running",
            "Stop concurrent builds, rebuild once, and package the stable artifact.",
        ));
    }
    let executable_digest = digest(&executable_data);
    let executable_name = plugin
        .executable
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .ok_or_else(|| {
            ValidationError::new(
                "package.executableName",
                "runtime executable must have a portable UTF-8 filename",
                "Rename the executable using portable ASCII characters.",
            )
        })?;
    let executable_archive_path = format!("bin/{}/{executable_name}", plugin.platform);

    let mut manifest: Value =
        serde_json::from_slice(&fs::read(&plugin.manifest_path).map_err(|error| {
            ValidationError::new(
                "package.manifest",
                format!("could not read {}: {error}", plugin.manifest_path.display()),
                "Check plugin.json permissions and retry.",
            )
        })?)
        .map_err(|error| {
            ValidationError::new(
                "package.manifest",
                format!("could not parse plugin.json for packaging: {error}"),
                "Fix plugin.json and run `tsp validate` before packaging.",
            )
        })?;
    let runtime = manifest
        .get_mut("runtime")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| {
            ValidationError::new(
                "package.manifest",
                "plugin.json runtime must be an object",
                "Fix plugin.json and run `tsp validate` before packaging.",
            )
        })?;
    runtime.insert(
        "entry".into(),
        Value::Object(Map::from_iter([(
            plugin.platform.clone(),
            Value::String(executable_archive_path.clone()),
        )])),
    );
    manifest
        .as_object_mut()
        .expect("validated manifest object")
        .insert(
            "integrity".into(),
            json!({
                "algorithm": "sha256",
                "digests": { plugin.platform.clone(): executable_digest.clone() }
            }),
        );
    let mut manifest_data = serde_json::to_vec_pretty(&manifest).map_err(|error| {
        ValidationError::new(
            "package.manifest",
            format!("could not serialize package manifest: {error}"),
            "Report this TokenSaver SDK defect.",
        )
    })?;
    manifest_data.push(b'\n');

    let root = plugin
        .manifest_path
        .parent()
        .unwrap_or_else(|| Path::new("."));
    let mut files = BTreeMap::new();
    insert_file(&mut files, "plugin.json", manifest_data, false)?;
    insert_file(&mut files, &executable_archive_path, executable_data, true)?;
    for name in [
        "plugin.superec",
        "README.md",
        "LICENSE",
        "LICENSE.md",
        "LICENSE.txt",
    ] {
        let path = root.join(name);
        if path.exists() {
            insert_file(&mut files, name, read_package_file(&path)?, false)?;
        }
    }
    let wiki = root.join("wiki");
    if wiki.exists() {
        collect_tree(&wiki, &wiki, "wiki", &mut files)?;
    }
    ensure_package_bounds(&files)?;

    let archive_data = write_zip(&files)?;
    let archive_digest = digest(&archive_data);
    write_atomic(output, &archive_data)?;
    let reports = files
        .iter()
        .map(|(path, file)| PackageFileReport {
            path: path.clone(),
            size_bytes: file.data.len(),
            digest: digest(&file.data),
            executable: file.executable,
        })
        .collect();
    Ok(PackageReport {
        schema_version: 1,
        ok: true,
        plugin_id: plugin.manifest.id.clone(),
        version: plugin.manifest.version.clone(),
        platform: plugin.platform.clone(),
        release_id: validation.release_id,
        certification_level: validation.certification_level,
        archive: output.display().to_string(),
        archive_size_bytes: archive_data.len(),
        archive_digest,
        executable_digest,
        reproducible: true,
        files: reports,
    })
}

fn collect_tree(
    root: &Path,
    directory: &Path,
    prefix: &str,
    files: &mut BTreeMap<String, PackageFile>,
) -> Result<(), ValidationError> {
    let metadata = fs::symlink_metadata(directory).map_err(package_read_error(directory))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(ValidationError::new(
            "package.tree",
            format!(
                "package tree contains a symlink or non-directory: {}",
                directory.display()
            ),
            "Use regular files and directories only inside the package knowledge tree.",
        ));
    }
    let mut entries = fs::read_dir(directory)
        .map_err(package_read_error(directory))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            ValidationError::new(
                "package.read",
                format!("could not enumerate {}: {error}", directory.display()),
                "Check package file permissions and retry.",
            )
        })?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(package_read_error(&path))?;
        if metadata.file_type().is_symlink() {
            return Err(ValidationError::new(
                "package.symlink",
                format!("package input cannot be a symlink: {}", path.display()),
                "Replace symlinks with regular package-owned files.",
            ));
        }
        if metadata.is_dir() {
            collect_tree(root, &path, prefix, files)?;
        } else if metadata.is_file() {
            let relative = path.strip_prefix(root).expect("tree child");
            let archive_path = portable_path(relative).map(|value| format!("{prefix}/{value}"))?;
            insert_file(files, &archive_path, read_package_file(&path)?, false)?;
        } else {
            return Err(ValidationError::new(
                "package.fileType",
                format!("unsupported package file type: {}", path.display()),
                "Use regular files and directories only.",
            ));
        }
    }
    Ok(())
}

fn portable_path(path: &Path) -> Result<String, ValidationError> {
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(value) => parts.push(
                value
                    .to_str()
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| {
                        ValidationError::new(
                            "package.path",
                            "package paths must be portable UTF-8",
                            "Rename package files using portable UTF-8 names.",
                        )
                    })?
                    .to_owned(),
            ),
            _ => {
                return Err(ValidationError::new(
                    "package.path",
                    "package paths cannot contain root or parent-directory components",
                    "Keep every package file inside the plugin directory.",
                ));
            }
        }
    }
    Ok(parts.join("/"))
}

fn insert_file(
    files: &mut BTreeMap<String, PackageFile>,
    path: &str,
    data: Vec<u8>,
    executable: bool,
) -> Result<(), ValidationError> {
    if path.is_empty()
        || path.starts_with('/')
        || path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(ValidationError::new(
            "package.path",
            format!("unsafe package path: {path:?}"),
            "Use normalized relative package paths.",
        ));
    }
    if files
        .insert(path.to_owned(), PackageFile { data, executable })
        .is_some()
    {
        return Err(ValidationError::new(
            "package.duplicate",
            format!("duplicate package path: {path}"),
            "Give every package file a unique path.",
        ));
    }
    Ok(())
}

fn read_package_file(path: &Path) -> Result<Vec<u8>, ValidationError> {
    let metadata = fs::symlink_metadata(path).map_err(package_read_error(path))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(ValidationError::new(
            "package.fileType",
            format!("package input must be a regular file: {}", path.display()),
            "Replace symlinks and special files with regular package-owned files.",
        ));
    }
    if metadata.len() > PACKAGE_MAX_BYTES as u64 {
        return Err(ValidationError::new(
            "package.size",
            format!("package file is too large: {}", path.display()),
            "Keep each package file and the complete archive below 256 MiB.",
        ));
    }
    fs::read(path).map_err(package_read_error(path))
}

fn package_read_error(path: &Path) -> impl FnOnce(std::io::Error) -> ValidationError + '_ {
    move |error| {
        ValidationError::new(
            "package.read",
            format!("could not read {}: {error}", path.display()),
            "Check package file permissions and retry.",
        )
    }
}

fn ensure_package_bounds(files: &BTreeMap<String, PackageFile>) -> Result<(), ValidationError> {
    let bytes = files
        .values()
        .try_fold(0usize, |total, file| total.checked_add(file.data.len()))
        .unwrap_or(usize::MAX);
    if files.len() > PACKAGE_MAX_FILES || bytes > PACKAGE_MAX_BYTES {
        return Err(ValidationError::new(
            "package.bounds",
            format!(
                "package inventory has {} files and {bytes} bytes",
                files.len()
            ),
            "Keep packages below 4096 files and 256 MiB of uncompressed content.",
        ));
    }
    Ok(())
}

fn write_zip(files: &BTreeMap<String, PackageFile>) -> Result<Vec<u8>, ValidationError> {
    let mut output = Vec::new();
    let mut central = Vec::new();
    for (name, file) in files {
        let name = name.as_bytes();
        let name_len = u16::try_from(name.len()).map_err(|_| zip_bounds_error())?;
        let size = u32::try_from(file.data.len()).map_err(|_| zip_bounds_error())?;
        let offset = u32::try_from(output.len()).map_err(|_| zip_bounds_error())?;
        let crc = crc32(&file.data);
        write_u32(&mut output, 0x0403_4b50);
        write_u16(&mut output, 20);
        write_u16(&mut output, 0x0800);
        write_u16(&mut output, 0);
        write_u16(&mut output, 0);
        write_u16(&mut output, 0x0021);
        write_u32(&mut output, crc);
        write_u32(&mut output, size);
        write_u32(&mut output, size);
        write_u16(&mut output, name_len);
        write_u16(&mut output, 0);
        output.extend_from_slice(name);
        output.extend_from_slice(&file.data);

        write_u32(&mut central, 0x0201_4b50);
        write_u16(&mut central, (3 << 8) | 20);
        write_u16(&mut central, 20);
        write_u16(&mut central, 0x0800);
        write_u16(&mut central, 0);
        write_u16(&mut central, 0);
        write_u16(&mut central, 0x0021);
        write_u32(&mut central, crc);
        write_u32(&mut central, size);
        write_u32(&mut central, size);
        write_u16(&mut central, name_len);
        write_u16(&mut central, 0);
        write_u16(&mut central, 0);
        write_u16(&mut central, 0);
        write_u16(&mut central, 0);
        write_u32(
            &mut central,
            if file.executable { 0o100755 } else { 0o100644 } << 16,
        );
        write_u32(&mut central, offset);
        central.extend_from_slice(name);
    }
    let central_offset = u32::try_from(output.len()).map_err(|_| zip_bounds_error())?;
    let central_size = u32::try_from(central.len()).map_err(|_| zip_bounds_error())?;
    output.extend_from_slice(&central);
    let count = u16::try_from(files.len()).map_err(|_| zip_bounds_error())?;
    write_u32(&mut output, 0x0605_4b50);
    write_u16(&mut output, 0);
    write_u16(&mut output, 0);
    write_u16(&mut output, count);
    write_u16(&mut output, count);
    write_u32(&mut output, central_size);
    write_u32(&mut output, central_offset);
    write_u16(&mut output, 0);
    if output.len() > PACKAGE_MAX_BYTES {
        return Err(zip_bounds_error());
    }
    Ok(output)
}

fn zip_bounds_error() -> ValidationError {
    ValidationError::new(
        "package.archiveBounds",
        "package exceeds deterministic ZIP32 limits",
        "Reduce package file count, path lengths, or total size.",
    )
}

fn write_atomic(path: &Path, data: &[u8]) -> Result<(), ValidationError> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("package.tsplug");
    let temporary = path.with_file_name(format!(".{file_name}.tmp-{}", std::process::id()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|error| {
                ValidationError::new(
                    "package.write",
                    format!("could not create {}: {error}", temporary.display()),
                    "Check output directory permissions and remove stale temporary files.",
                )
            })?;
        file.write_all(data)
            .and_then(|_| file.sync_all())
            .map_err(|error| {
                ValidationError::new(
                    "package.write",
                    format!("could not write {}: {error}", temporary.display()),
                    "Check free disk space and output directory permissions.",
                )
            })?;
        drop(file);
        fs::rename(&temporary, path).map_err(|error| {
            ValidationError::new(
                "package.commit",
                format!("could not commit {}: {error}", path.display()),
                "Check output directory permissions and retry.",
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

fn crc32(data: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & 0u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}

fn write_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn write_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_matches_standard_check_value() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
    }

    #[test]
    fn deterministic_zip_has_sorted_entries_and_stable_bytes() {
        let files = BTreeMap::from([
            (
                "z.txt".to_owned(),
                PackageFile {
                    data: b"last".to_vec(),
                    executable: false,
                },
            ),
            (
                "a.txt".to_owned(),
                PackageFile {
                    data: b"first".to_vec(),
                    executable: false,
                },
            ),
        ]);
        let first = write_zip(&files).expect("write ZIP");
        let second = write_zip(&files).expect("write ZIP again");
        assert_eq!(first, second);
        assert!(first.windows(5).any(|window| window == b"a.txt"));
        assert!(first.ends_with(&[0, 0]));
    }
}
