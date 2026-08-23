#!/usr/bin/env python3
"""Strictly verify one TokenSaver native runtime-host artifact directory."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

PLATFORMS = {
    "windows-x64": ("tokensaver-plugin-runtime-host.exe", None),
    "windows-arm64": ("tokensaver-plugin-runtime-host.exe", None),
    "linux-x64": ("tokensaver-plugin-runtime-host", None),
    "linux-arm64": ("tokensaver-plugin-runtime-host", None),
    "darwin-x64": ("tokensaver-plugin-runtime-host", "tokensaver-plugin-limit-launcher"),
    "darwin-arm64": ("tokensaver-plugin-runtime-host", "tokensaver-plugin-limit-launcher"),
}
MANIFEST = "runtime-host-assets.v1.json"
CHECKSUMS = "SHA256SUMS"
DIGEST = re.compile(r"^[0-9a-f]{64}$")
CHECKSUM_LINE = re.compile(r"^([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._-]{0,127})$")


class VerificationError(ValueError):
    pass


def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise VerificationError("duplicate JSON member")
        result[key] = value
    return result


def digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(64 << 10):
            digest.update(block)
    return digest.hexdigest()


def require_asset(value: object, filename: str, actual_digest: str) -> None:
    if not isinstance(value, dict) or set(value) != {"file", "sha256"}:
        raise VerificationError("invalid asset identity")
    if value["file"] != filename or value["sha256"] != f"sha256:{actual_digest}":
        raise VerificationError("asset identity mismatch")


def verify(directory: Path, platform: str) -> None:
    if platform not in PLATFORMS:
        raise VerificationError("unsupported platform")
    root = directory.resolve(strict=True)
    if not root.is_dir():
        raise VerificationError("artifact root is not a directory")
    host, launcher = PLATFORMS[platform]
    payload_names = {host, MANIFEST}
    if launcher:
        payload_names.add(launcher)
    expected_names = payload_names | {CHECKSUMS}
    entries = list(root.iterdir())
    if {entry.name for entry in entries} != expected_names:
        raise VerificationError("artifact directory membership mismatch")
    for entry in entries:
        if entry.is_symlink() or not entry.is_file():
            raise VerificationError("artifact entry is not a regular file")

    checksum_path = root / CHECKSUMS
    if checksum_path.stat().st_size == 0 or checksum_path.stat().st_size > 4 << 10:
        raise VerificationError("checksum inventory size is invalid")
    checksum_data = checksum_path.read_text(encoding="ascii")
    if not checksum_data.endswith("\n"):
        raise VerificationError("checksum inventory is not canonical")
    checksums: dict[str, str] = {}
    for line in checksum_data.splitlines():
        match = CHECKSUM_LINE.fullmatch(line)
        if match is None or match.group(2) in checksums:
            raise VerificationError("invalid checksum inventory")
        checksums[match.group(2)] = match.group(1)
    if set(checksums) != payload_names:
        raise VerificationError("checksum inventory membership mismatch")
    actual: dict[str, str] = {}
    for name in sorted(payload_names):
        if (root / name).stat().st_size == 0 or (root / name).stat().st_size > 256 << 20:
            raise VerificationError("artifact size is invalid")
        value = digest_file(root / name)
        if not DIGEST.fullmatch(value) or checksums[name] != value:
            raise VerificationError("checksum mismatch")
        actual[name] = value

    manifest_path = root / MANIFEST
    if manifest_path.stat().st_size == 0 or manifest_path.stat().st_size > 16 << 10:
        raise VerificationError("manifest size is invalid")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"), object_pairs_hook=unique_object)
    except (OSError, UnicodeError, json.JSONDecodeError, VerificationError) as error:
        raise VerificationError("manifest JSON is invalid") from error
    expected_keys = {"schemaVersion", "platform", "host"}
    if launcher:
        expected_keys.add("limitLauncher")
    if not isinstance(manifest, dict) or set(manifest) != expected_keys:
        raise VerificationError("manifest membership mismatch")
    if type(manifest["schemaVersion"]) is not int or manifest["schemaVersion"] != 1 or manifest["platform"] != platform:
        raise VerificationError("manifest identity mismatch")
    require_asset(manifest["host"], host, actual[host])
    if launcher:
        require_asset(manifest["limitLauncher"], launcher, actual[launcher])


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--platform", required=True, choices=sorted(PLATFORMS))
    args = parser.parse_args()
    try:
        verify(args.directory, args.platform)
    except (OSError, VerificationError) as error:
        print(f"runtime-host asset verification failed: {error}", file=sys.stderr)
        return 1
    print(f"runtime-host assets verified: {args.platform}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
