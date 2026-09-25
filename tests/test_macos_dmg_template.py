"""Regression tests for the macOS packaging template.

The DMG path was shipped broken once: `spctl --assess --type diskimage` is not a
valid assessment type on current macOS, and because the notarized image only
existed inside a temp directory removed by the EXIT trap, that failure
discarded a completed notarization.  These tests pin both fixes.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(r"C:\Users\Richard\AppData\Local\Temp\opencode\whisper-dictate-community-repo")
SCRIPT = ROOT / "packaging" / "macos" / "build_signed_dmg.sh"


def read() -> str:
    return SCRIPT.read_text(encoding="utf-8")


class MacosDmgTemplateTests(unittest.TestCase):
    def test_disk_image_assessment_uses_a_supported_spctl_invocation(self):
        text = read()
        self.assertNotIn(
            "--assess --type diskimage",
            text,
            "spctl has no 'diskimage' assessment type; a signed image is checked "
            "with an open assessment against the primary signature",
        )
        self.assertIn("--context context:primary-signature", text)

    def test_notarized_image_is_copied_out_before_verification(self):
        text = read()
        copy_line = text.index('cp "$DMG_PATH" "$OUTPUT_PATH"')
        for check in ("hdiutil verify", "context:primary-signature"):
            self.assertIn(check, text)
            self.assertLess(
                copy_line,
                text.index(check),
                f"the image must be published before '{check}' so a failing check "
                "cannot destroy a completed notarization",
            )

    def test_verification_runs_against_the_published_file(self):
        text = read()
        verify_block = text[text.index('cp "$DMG_PATH" "$OUTPUT_PATH"'):]
        self.assertIn('hdiutil verify "$OUTPUT_PATH"', verify_block)
        self.assertIn('"$OUTPUT_PATH"', verify_block)

    def test_no_credential_material_is_embedded(self):
        text = read()
        for pattern in (
            r"BEGIN [A-Z ]*PRIVATE KEY",
            r"AuthKey_[A-Z0-9]{10}",
            r"--issuer\s+[0-9a-fA-F-]{36}",
            r"--apple-id\s+\S",
            r"--password\s+\S",
            r"AKIA[0-9A-Z]{16}",
        ):
            with self.subTest(pattern=pattern):
                self.assertIsNone(
                    re.search(pattern, text),
                    f"credential material matching {pattern!r} must not be in the template",
                )
        # Credentials may only arrive through the environment.
        self.assertIn("NOTARYTOOL_KEY", text)
        self.assertIn("DEVELOPER_ID_APPLICATION", text)

    def test_dmg_path_still_requires_hdiutil(self):
        text = read()
        self.assertIn("require_command hdiutil", text)
        self.assertIn('FORMAT="${FORMAT:-zip}"', text)


if __name__ == "__main__":
    unittest.main()
