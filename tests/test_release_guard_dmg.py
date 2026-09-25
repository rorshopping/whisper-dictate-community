"""Tests for the disk-image branch of the release guard.

A `.dmg` cannot be opened by the standard library, so the guard accepts one only
when a macOS verification record matches the exact bytes.  These tests pin that
fail-closed behaviour, including the case where the image was swapped after it
was checked.
"""

from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(r"C:\Users\Richard\AppData\Local\Temp\opencode\whisper-dictate-community-repo")
sys.path.insert(0, str(ROOT))

from scripts.release_guard import (  # noqa: E402
    DMG_REQUIRED_CHECKS,
    DMG_VERIFICATION_SCHEMA,
    inspect,
    inspect_dmg,
)

IMAGE_BYTES = b"not-a-real-disk-image" * 64


def record_for(image: Path, *, passed: bool = True, checks=None) -> dict:
    return {
        "schema": DMG_VERIFICATION_SCHEMA,
        "image": image.name,
        "sha256": hashlib.sha256(image.read_bytes()).hexdigest(),
        "size_bytes": image.stat().st_size,
        "verified_on": "macOS 26.5.1 (arm64)",
        "verified_at": "2026-09-25T21:54:45Z",
        "app": "WhisperDictate.app",
        "passed": passed,
        "checks": checks
        if checks is not None
        else [{"name": name, "passed": True, "detail": "ok"} for name in DMG_REQUIRED_CHECKS],
    }


class DmgGuardTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.image = self.root / "WhisperDictate-0.1.0-macos-arm64-notarized.dmg"
        self.image.write_bytes(IMAGE_BYTES)
        self.evidence = self.root / "dmg.verification.json"

    def write_record(self, record: dict) -> Path:
        self.evidence.write_text(json.dumps(record), encoding="utf-8")
        return self.evidence

    def test_image_without_evidence_fails_closed(self):
        violations = inspect(self.image)
        self.assertEqual(len(violations), 1)
        self.assertIn("macOS verification", violations[0][1])

    def test_matching_evidence_passes(self):
        self.write_record(record_for(self.image))
        self.assertEqual(inspect_dmg(self.image, self.evidence), [])

    def test_evidence_for_other_image_name_is_rejected(self):
        record = record_for(self.image)
        record["image"] = "SomethingElse.dmg"
        self.write_record(record)
        violations = inspect_dmg(self.image, self.evidence)
        self.assertTrue(any("names" in reason for _, reason in violations))

    def test_changed_image_is_rejected(self):
        self.write_record(record_for(self.image))
        self.image.write_bytes(IMAGE_BYTES + b"tampered")
        violations = inspect_dmg(self.image, self.evidence)
        self.assertTrue(any("SHA-256 does not match" in reason for _, reason in violations))

    def test_wrong_schema_is_rejected(self):
        record = record_for(self.image)
        record["schema"] = "something-else"
        self.write_record(record)
        violations = inspect_dmg(self.image, self.evidence)
        self.assertTrue(any("schema" in reason for _, reason in violations))

    def test_missing_check_is_rejected(self):
        record = record_for(self.image, checks=[{"name": "hdiutil-verify", "passed": True}])
        self.write_record(record)
        violations = inspect_dmg(self.image, self.evidence)
        self.assertTrue(any("spctl-app" in reason for _, reason in violations))

    def test_failed_overall_result_is_rejected(self):
        self.write_record(record_for(self.image, passed=False))
        violations = inspect_dmg(self.image, self.evidence)
        self.assertTrue(any("overall pass" in reason for _, reason in violations))

    def test_unreadable_record_is_rejected(self):
        self.evidence.write_text("{not json", encoding="utf-8")
        violations = inspect_dmg(self.image, self.evidence)
        self.assertTrue(any("unreadable" in reason for _, reason in violations))

    def test_zip_path_is_still_inspected_as_before(self):
        # The disk-image branch must not swallow ordinary archives.
        zip_path = self.root / "payload.zip"
        import zipfile

        with zipfile.ZipFile(zip_path, "w") as handle:
            handle.writestr("WhisperDictate/dictate.log", "private")
        violations = inspect(zip_path)
        self.assertEqual(len(violations), 1)
        self.assertIn("dictate.log", violations[0][0])


if __name__ == "__main__":
    unittest.main()
