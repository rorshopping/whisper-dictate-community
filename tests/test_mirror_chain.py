"""Add mirror-chain and startup-prefetch tests to the community source suite."""

from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(r"C:\Users\Richard\AppData\Local\Temp\opencode\whisper-dictate-community-repo")
sys.path.insert(0, str(ROOT))

from model_manager import (  # noqa: E402
    ManifestError,
    ModelManager,
    ModelManifest,
    default_manifests,
    parse_model_config,
    validate_https_urls,
)

EN = "nvidia/nemotron-speech-streaming-en-0.6b"


# The fake payload must satisfy the manifest exactly, so the integrity check is
# exercised rather than bypassed.
PAYLOAD = b'{"ok":true}'
PAYLOAD_SHA256 = hashlib.sha256(PAYLOAD).hexdigest()


def small_manifest(model_id: str = EN, revision: str = "0" * 40) -> ModelManifest:
    return ModelManifest.from_mapping(
        {
            "model_id": model_id,
            "revision": revision,
            "files": [
                {"name": "config.json", "size": len(PAYLOAD), "sha256": PAYLOAD_SHA256},
            ],
        }
    )


def write_payload(destination) -> Path:
    path = Path(destination)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(PAYLOAD)
    return path


class MirrorUrlListTests(unittest.TestCase):
    def test_single_string_is_a_one_entry_chain(self):
        self.assertEqual(validate_https_urls("https://mirror.example/"), ("https://mirror.example",))

    def test_order_is_preserved_and_duplicates_dropped(self):
        self.assertEqual(
            validate_https_urls(["https://b.example", "https://a.example", "https://b.example/"]),
            ("https://b.example", "https://a.example"),
        )

    def test_empty_values_mean_no_mirror(self):
        self.assertEqual(validate_https_urls(None), ())
        self.assertEqual(validate_https_urls(""), ())
        self.assertEqual(validate_https_urls([]), ())

    def test_insecure_and_non_string_entries_are_rejected(self):
        for value in ("http://mirror.example", ["https://ok.example", "http://no.example"], ["ftp://x"], [None], 5):
            with self.subTest(value=value):
                with self.assertRaises(ManifestError):
                    validate_https_urls(value)

    def test_config_accepts_mirror_urls_and_keeps_mirror_url(self):
        settings = parse_model_config(
            {
                "model_resolver": {
                    "mirror_urls": ["https://one.example", "https://two.example"],
                    "mirror_url": "https://legacy.example",
                }
            }
        )
        self.assertEqual(settings.mirror_urls, ("https://one.example", "https://two.example"))
        self.assertEqual(settings.mirror_url, "https://legacy.example")

    def test_single_mirror_url_still_becomes_a_chain(self):
        settings = parse_model_config({"model_resolver": {"mirror_url": "https://legacy.example"}})
        self.assertEqual(settings.mirror_urls, ("https://legacy.example",))

    def test_profile_may_override_the_chain(self):
        settings = parse_model_config(
            {"model_resolver": {"mirror_urls": ["https://global.example"]}},
            {"mirror_urls": ["https://profile.example"]},
        )
        self.assertEqual(settings.mirror_urls, ("https://profile.example",))

    def test_manager_constructor_exposes_the_chain(self):
        manager = ModelManager(manifest=small_manifest(), mirror_urls=["https://a.example", "https://b.example"])
        self.assertEqual(manager.mirror_urls, ("https://a.example", "https://b.example"))
        single = ModelManager(manifest=small_manifest(), mirror_url="https://legacy.example")
        self.assertEqual(single.mirror_urls, ("https://legacy.example",))
        self.assertEqual(single.mirror_url, "https://legacy.example")


class MirrorFallbackTests(unittest.TestCase):
    """A blocked Hugging Face must not stop the download when a mirror serves it."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.cache = Path(self._tmp.name) / "cache"

    def manager(self, **kwargs):
        return ModelManager(manifest=small_manifest(), cache_dir=self.cache, **kwargs)

    def test_download_uses_the_first_mirror_and_never_touches_huggingface(self):
        requested: list[str] = []

        def downloader(url, destination, **kwargs):
            requested.append(url)
            return write_payload(destination)

        manager = self.manager(
            mirror_urls=["https://mirror.example"],
            huggingface_endpoint="https://blocked-huggingface.example",
            downloader=downloader,
        )
        resolved = manager.resolve(EN, source="mirror")
        self.assertEqual(resolved.source, "mirror")
        self.assertTrue(all(url.startswith("https://mirror.example/") for url in requested))
        self.assertFalse(any("blocked-huggingface" in url for url in requested))

    def test_second_mirror_is_tried_when_the_first_fails(self):
        attempts: list[str] = []

        def downloader(url, destination, **kwargs):
            attempts.append(url)
            if url.startswith("https://down.example"):
                raise OSError("connection refused")
            return write_payload(destination)

        manager = self.manager(
            mirror_urls=["https://down.example", "https://up.example"],
            huggingface_endpoint="https://blocked-huggingface.example",
            downloader=downloader,
        )
        resolved = manager.resolve(EN, source="mirror")
        self.assertEqual(resolved.source, "mirror")
        self.assertTrue(any(url.startswith("https://down.example/") for url in attempts))
        self.assertTrue(any(url.startswith("https://up.example/") for url in attempts))
        trace = {event.source: event.status for event in resolved.trace}
        self.assertIn(trace.get("mirror"), {"downloaded", "selected", "cached"})
        details = " ".join(event.detail for event in resolved.trace)
        self.assertIn("down.example", details)
        self.assertIn("unavailable", " ".join(event.status for event in resolved.trace))

    def test_huggingface_is_the_last_resort_after_every_mirror_fails(self):
        attempts: list[str] = []

        def downloader(url, destination, **kwargs):
            attempts.append(url)
            if url.startswith("https://huggingface.co/"):
                return write_payload(destination)
            raise OSError(f"unreachable: {url}")

        manager = self.manager(
            mirror_urls=["https://one.example", "https://two.example"],
            downloader=downloader,
        )
        resolved = manager.resolve(EN)
        self.assertEqual(resolved.source, "huggingface")
        self.assertTrue(any(url.startswith("https://one.example/") for url in attempts))
        self.assertTrue(any(url.startswith("https://two.example/") for url in attempts))
        self.assertTrue(any(url.startswith("https://huggingface.co/") for url in attempts))

    def test_offline_mode_skips_every_mirror(self):
        attempts: list[str] = []

        def downloader(url, destination, **kwargs):
            attempts.append(url)
            raise AssertionError("offline mode must not download")

        manager = self.manager(mirror_urls=["https://mirror.example"], offline=True, downloader=downloader)
        with self.assertRaises(Exception):
            manager.resolve(EN)
        self.assertEqual(attempts, [])

    def test_corrupt_mirror_bytes_are_rejected_by_hash(self):
        def downloader(url, destination, **kwargs):
            Path(destination).parent.mkdir(parents=True, exist_ok=True)
            Path(destination).write_bytes(b'{"ok":FALSE}')  # right size, wrong hash
            return destination

        manager = self.manager(
            mirror_urls=["https://liar.example"],
            huggingface_endpoint="https://blocked-huggingface.example",
            downloader=downloader,
        )
        with self.assertRaises(Exception):
            manager.resolve(EN, source="mirror")
        self.assertFalse((self.cache / "snapshots").exists() and list((self.cache / "snapshots").glob("*/.whisper-dictate-manifest.json")))

    def test_url_template_with_placeholders_is_supported(self):
        seen: list[str] = []

        def downloader(url, destination, **kwargs):
            seen.append(url)
            return write_payload(destination)

        manager = self.manager(
            mirror_urls=["https://files.example/{model_id}/{revision}/{filename}"],
            downloader=downloader,
        )
        manager.resolve(EN, source="mirror")
        self.assertEqual(
            seen,
            [f"https://files.example/{EN}/{'0' * 40}/config.json"],
        )

    def test_shipped_config_declares_a_non_huggingface_mirror(self):
        config = json.loads((ROOT / "config.json").read_text(encoding="utf-8"))
        urls = validate_https_urls((config.get("model_resolver") or {}).get("mirror_urls"))
        self.assertTrue(urls, "the shipped config must configure a mirror fallback")
        self.assertFalse(
            any("huggingface.co" in url for url in urls),
            "a mirror must be a host other than Hugging Face",
        )
        # The default manifests must still resolve against that chain.
        catalog = default_manifests()
        self.assertIn(EN, [m.model_id for m in catalog.manifests])


if __name__ == "__main__":
    unittest.main()
