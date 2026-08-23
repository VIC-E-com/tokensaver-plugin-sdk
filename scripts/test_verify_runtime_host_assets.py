import hashlib
import json
import os
import shutil
import unittest
import uuid
from pathlib import Path

from verify_runtime_host_assets import (
    CHECKSUMS,
    MANIFEST,
    PLATFORMS,
    VerificationError,
    verify,
    write_checksums,
)


class RuntimeHostAssetVerificationTests(unittest.TestCase):
    def fixture(self, platform: str) -> Path:
        fixture_parent = Path(__file__).resolve().parent / ".test-tmp"
        fixture_parent.mkdir(mode=0o755, exist_ok=True)
        os.chmod(fixture_parent, 0o755)
        root = fixture_parent / f"runtime-host-assets-{uuid.uuid4().hex}"
        root.mkdir(mode=0o755)
        os.chmod(root, 0o755)
        self.addCleanup(lambda: self.remove_fixture(root))
        host, launcher = PLATFORMS[platform]
        (root / host).write_bytes(b"trusted host")
        manifest = {
            "schemaVersion": 1,
            "platform": platform,
            "host": self.identity(root / host),
        }
        if launcher:
            (root / launcher).write_bytes(b"trusted launcher")
            manifest["limitLauncher"] = self.identity(root / launcher)
        (root / MANIFEST).write_text(json.dumps(manifest, separators=(",", ":")), encoding="utf-8")
        payload = [host, MANIFEST] + ([launcher] if launcher else [])
        (root / CHECKSUMS).write_text(
            "".join(f"{self.digest(root / name)}  {name}\n" for name in payload),
            encoding="ascii",
        )
        return root

    def test_accepts_exact_artifact_for_every_platform(self):
        for platform in PLATFORMS:
            with self.subTest(platform=platform):
                verify(self.fixture(platform), platform)

    def test_checksum_writer_is_canonical_idempotent_and_rejects_extra_members(self):
        root = self.fixture("windows-arm64")
        lines = (root / CHECKSUMS).read_text(encoding="ascii").splitlines()
        (root / CHECKSUMS).write_text(
            "".join(f"{line[:64]} *{line[66:]}\n" for line in lines),
            encoding="ascii",
        )
        write_checksums(root, "windows-arm64")
        first = (root / CHECKSUMS).read_bytes()
        self.assertTrue(first.endswith(b"\n"))
        self.assertNotIn(b" *", first)
        self.assertEqual(first.splitlines(), sorted(first.splitlines()))
        verify(root, "windows-arm64")
        write_checksums(root, "windows-arm64")
        self.assertEqual((root / CHECKSUMS).read_bytes(), first)

        (root / "extra").write_bytes(b"extra")
        with self.assertRaises(VerificationError):
            write_checksums(root, "windows-arm64")

    def test_rejects_missing_extra_drift_and_manifest_identity(self):
        mutations = {
            "missing checksum": lambda root: (root / CHECKSUMS).write_text("", encoding="ascii"),
            "extra file": lambda root: (root / "extra").write_bytes(b"extra"),
            "host drift": lambda root: (root / PLATFORMS["windows-x64"][0]).write_bytes(b"changed"),
            "wrong platform": lambda root: self.edit_manifest(root, lambda value: value.update(platform="linux-x64")),
            "wrong digest": lambda root: self.edit_manifest(root, lambda value: value["host"].update(sha256="sha256:" + "0" * 64)),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                root = self.fixture("windows-x64")
                mutate(root)
                with self.assertRaises(VerificationError):
                    verify(root, "windows-x64")

    def test_rejects_duplicate_unknown_and_trailing_manifest_json(self):
        for name, data in {
            "duplicate": '{"schemaVersion":1,"schemaVersion":1}',
            "unknown": '{"schemaVersion":1,"platform":"windows-x64","host":{},"unknown":true}',
            "trailing": '{} {}',
        }.items():
            with self.subTest(name=name):
                root = self.fixture("windows-x64")
                (root / MANIFEST).write_text(data, encoding="utf-8")
                self.refresh_checksum(root, MANIFEST)
                with self.assertRaises(VerificationError):
                    verify(root, "windows-x64")

    @staticmethod
    def digest(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def identity(self, path: Path) -> dict[str, str]:
        return {"file": path.name, "sha256": "sha256:" + self.digest(path)}

    def refresh_checksum(self, root: Path, name: str) -> None:
        lines = (root / CHECKSUMS).read_text(encoding="ascii").splitlines()
        updated = [f"{self.digest(root / name)}  {name}" if line.endswith("  " + name) else line for line in lines]
        (root / CHECKSUMS).write_text("\n".join(updated) + "\n", encoding="ascii")

    def edit_manifest(self, root: Path, edit) -> None:
        value = json.loads((root / MANIFEST).read_text(encoding="utf-8"))
        edit(value)
        (root / MANIFEST).write_text(json.dumps(value, separators=(",", ":")), encoding="utf-8")
        self.refresh_checksum(root, MANIFEST)

    @staticmethod
    def remove_fixture(root: Path) -> None:
        if root.exists():
            shutil.rmtree(root)
        parent = root.parent
        if parent.exists() and not any(parent.iterdir()):
            parent.rmdir()


if __name__ == "__main__":
    unittest.main()
