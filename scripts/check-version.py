#!/usr/bin/env python3
"""Verify every public SDK release-version surface."""

from __future__ import annotations

import json
import pathlib
import re
import sys
import tomllib


ROOT = pathlib.Path(__file__).resolve().parents[1]
SEMVER = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$")


def fail(message: str) -> None:
    raise SystemExit(f"version check failed: {message}")


def toml(path: pathlib.Path) -> dict:
    with path.open("rb") as stream:
        return tomllib.load(stream)


def main() -> None:
    if len(sys.argv) > 2:
        fail("usage: check-version.py [VERSION]")
    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    if not SEMVER.fullmatch(version):
        fail(f"VERSION is not release semver: {version!r}")
    if len(sys.argv) == 2 and sys.argv[1] != version:
        fail(f"requested {sys.argv[1]!r}, repository declares {version!r}")

    for manifest in sorted(ROOT.rglob("Cargo.toml")):
        if "target" in manifest.parts:
            continue
        package = toml(manifest).get("package")
        if package is not None and package.get("version") != version:
            fail(f"{manifest.relative_to(ROOT)} declares {package.get('version')!r}")

    python_version = toml(ROOT / "sdk/python/pyproject.toml")["project"]["version"]
    if python_version != version:
        fail(f"sdk/python/pyproject.toml declares {python_version!r}")

    typescript = json.loads((ROOT / "sdk/typescript/tokensaver-plugin/package.json").read_text(encoding="utf-8"))
    if typescript.get("version") != version:
        fail(f"TypeScript package declares {typescript.get('version')!r}")

    example_plugin_ids: set[str] = set()
    for manifest in sorted((ROOT / "examples").glob("*/plugin.json")):
        plugin = json.loads(manifest.read_text(encoding="utf-8"))
        declared = plugin.get("version")
        if declared != version:
            fail(f"{manifest.relative_to(ROOT)} declares {declared!r}")
        plugin_id = plugin.get("id")
        if not isinstance(plugin_id, str) or not plugin_id:
            fail(f"{manifest.relative_to(ROOT)} has no plugin id")
        example_plugin_ids.add(plugin_id)

    workflow = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
    if f"SDK_VERSION: {version}" not in workflow:
        fail("release workflow SDK_VERSION does not match VERSION")
    for plugin_id in sorted(example_plugin_ids):
        if plugin_id not in workflow:
            fail(f"release workflow does not use manifest plugin id {plugin_id!r}")
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    if f"## [{version}]" not in changelog:
        fail("CHANGELOG has no current release heading")
    print(f"TokenSaver Plugin SDK version {version}: OK")


if __name__ == "__main__":
    main()
