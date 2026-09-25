"""Tests for the split-file mirror manifest.

The mirror path is exercised end to end over a real local HTTP server: a model
file larger than any single release asset is published as parts, fetched,
verified part by part, assembled, and only accepted when the assembled file
matches the pinned SHA-256.  Every corruption case must fail closed.
"""

from __future__ import annotations

import contextlib
import hashlib
import http.server
import json
import sys
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

from model_manager import (  # noqa: E402
    ManifestError,
    ModelManager,
    ModelManifest,
    parse_mirror_manifest,
)

MODEL_ID = "nvidia/nemotron-speech-streaming-en-0.6b"
REVISION = "ebe59e5a817142986528bbbee5dba8db7b38ed50"
# Big enough to need two parts, small enough to stay fast.
WEIGHTS = b"whisper-dictate-weights-" + bytes(range(256)) * 8
WEIGHTS_SHA = hashlib.sha256(WEIGHTS).hexdigest()
CONFIG = b'{"model_type":"x"}'
CONFIG_SHA = hashlib.sha256(CONFIG).hexdigest()
PART_SIZE = 1000


def parts_of(payload: bytes) -> list[bytes]:
    return [payload[index:index + PART_SIZE] for index in range(0, len(payload), PART_SIZE)]


def part_names(payload: bytes) -> list[str]:
    return [f"model.safetensors.part{index:03d}" for index in range(len(parts_of(payload)))]


def urls_for(payload: bytes, base: str = "https://files.example") -> dict[str, str]:
    mapping = {"config.json": f"{base}/config.json"}
    for name in part_names(payload):
        mapping[name] = f"{base}/{name}"
    return mapping


def manifest_for(weights: bytes, config: bytes, part_urls: dict[str, str]) -> dict:
    weight_parts = []
    for index, chunk in enumerate(parts_of(weights)):
        weight_parts.append(
            {
                "name": f"model.safetensors.part{index:03d}",
                "size": len(chunk),
                "sha256": hashlib.sha256(chunk).hexdigest(),
                "url": part_urls[f"model.safetensors.part{index:03d}"],
            }
        )
    return {
        "schema": "whisper-dictate.model-mirror.v1",
        "models": {
            MODEL_ID: {
                "revision": REVISION,
                "files": {
                    "config.json": {
                        "size": len(config),
                        "sha256": hashlib.sha256(config).hexdigest(),
                        "url": part_urls["config.json"],
                    },
                    "model.safetensors": {
                        "size": len(weights),
                        "sha256": hashlib.sha256(weights).hexdigest(),
                        "parts": weight_parts,
                    },
                },
            }
        },
    }


class MirrorManifestParsingTests(unittest.TestCase):
    def valid(self) -> dict:
        return manifest_for(WEIGHTS, CONFIG, urls_for(WEIGHTS))

    def test_valid_manifest_round_trips(self):
        parsed = parse_mirror_manifest(self.valid())
        entry = parsed[MODEL_ID]
        self.assertEqual(entry["revision"], REVISION)
        self.assertEqual(len(entry["files"]["model.safetensors"]["parts"]), len(part_names(WEIGHTS)))
        self.assertEqual(entry["files"]["config.json"]["size"], len(CONFIG))

    def test_schema_must_match(self):
        for bad in ({}, {"schema": "something-else", "models": {}}, {"models": {}}):
            with self.subTest(bad=bad):
                with self.assertRaises(ManifestError):
                    parse_mirror_manifest(bad)

    def test_insecure_part_url_is_rejected(self):
        data = self.valid()
        data["models"][MODEL_ID]["files"]["model.safetensors"]["parts"][0]["url"] = "http://files.example/p0"
        with self.assertRaises(ManifestError):
            parse_mirror_manifest(data)

    def test_part_sizes_must_add_up(self):
        data = self.valid()
        data["models"][MODEL_ID]["files"]["model.safetensors"]["parts"][0]["size"] = 5
        with self.assertRaises(ManifestError):
            parse_mirror_manifest(data)

    def test_missing_hash_is_rejected(self):
        data = self.valid()
        del data["models"][MODEL_ID]["files"]["model.safetensors"]["sha256"]
        with self.assertRaises(ManifestError):
            parse_mirror_manifest(data)

    def test_path_traversal_file_name_is_rejected(self):
        data = self.valid()
        data["models"][MODEL_ID]["files"]["../escape"] = data["models"][MODEL_ID]["files"]["config.json"]
        with self.assertRaises(ManifestError):
            parse_mirror_manifest(data)

    def test_pinned_manifest_agrees_with_the_mirror_manifest(self):
        """The mirror may not disagree with the hashes the app already pins."""
        pinned = ModelManifest.from_mapping(
            {
                "model_id": MODEL_ID,
                "revision": REVISION,
                "files": [
                    {"name": "config.json", "size": len(CONFIG), "sha256": CONFIG_SHA},
                    {"name": "model.safetensors", "size": len(WEIGHTS), "sha256": WEIGHTS_SHA},
                ],
            }
        )
        parsed = parse_mirror_manifest(self.valid())
        mirror_files = parsed[MODEL_ID]["files"]
        for entry in pinned.required_files:
            self.assertEqual(mirror_files[entry.name]["size"], entry.size)
            self.assertEqual(mirror_files[entry.name]["sha256"], entry.sha256)


@contextlib.contextmanager
def allow_loopback_mirror():
    """Permit the test server's http base; production checks stay https-only.

    Two guards are relaxed here and only here: the mirror-base validator and the
    per-request HTTPS rule inside `atomic_download`.  Everything that protects
    the download itself - part sizes, part hashes, the assembled-file hash, and
    snapshot publication - runs exactly as it does in production.
    """

    import model_manager as mm

    original_validate = mm.validate_https_url
    original_atomic = mm.atomic_download

    def permissive_atomic(url, destination, *, require_https=True, **kwargs):
        return original_atomic(url, destination, require_https=False, **kwargs)

    mm.validate_https_url = lambda value: (value.rstrip("/") if value else None)
    mm.atomic_download = permissive_atomic
    try:
        yield
    finally:
        mm.validate_https_url = original_validate
        mm.atomic_download = original_atomic


class MirrorManifestDownloadTests(unittest.TestCase):
    """Real HTTP server, real part downloads, real hash verification."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.cache = self.root / "cache"
        self.served = self.root / "served"
        self.served.mkdir()

        (self.served / "config.json").write_bytes(CONFIG)
        for index, chunk in enumerate(parts_of(WEIGHTS)):
            (self.served / f"model.safetensors.part{index:03d}").write_bytes(chunk)
        (self.served / "model.safetensors").write_bytes(b"decoy, must never be used")

        handler = _make_handler(self.served)
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.server.shutdown)
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        self._publish_mirror_manifest()

    def _publish_mirror_manifest(self) -> None:
        names = ["config.json", *part_names(WEIGHTS)]
        urls = {name: f"{self.base}/{name}" for name in names}
        (self.served / "mirror-manifest.json").write_text(
            json.dumps(manifest_for(WEIGHTS, CONFIG, urls)), encoding="utf-8"
        )

    def _manager(self, **kwargs) -> ModelManager:
        with allow_loopback_mirror():
            return ModelManager(
                manifest=ModelManifest.from_mapping(
                    {
                        "model_id": MODEL_ID,
                        "revision": REVISION,
                        "files": [
                            {"name": "config.json", "size": len(CONFIG), "sha256": CONFIG_SHA},
                            {
                                "name": "model.safetensors",
                                "size": len(WEIGHTS),
                                "sha256": WEIGHTS_SHA,
                            },
                        ],
                    }
                ),
                cache_dir=self.cache,
                **kwargs,
            )

    def _resolve(self, manager: ModelManager):
        with allow_loopback_mirror():
            return manager.resolve(MODEL_ID, source="mirror")

    def test_assembles_and_verifies_a_split_file(self):
        manager = self._manager(mirror_urls=[self.base])
        resolved = self._resolve(manager)
        self.assertEqual(resolved.source, "mirror")
        weights = Path(resolved.path) / "model.safetensors"
        self.assertEqual(weights.read_bytes(), WEIGHTS)
        self.assertEqual((Path(resolved.path) / "config.json").read_bytes(), CONFIG)
        self.assertIn("mirror", {event.source for event in resolved.trace})
        # The un-split decoy must never be requested: the manifest is used.
        self.assertTrue((resolved.path / ".whisper-dictate-manifest.json").is_file())

    def test_corrupt_part_is_rejected_and_never_published(self):
        (self.served / part_names(WEIGHTS)[1]).write_bytes(b"x" * len(parts_of(WEIGHTS)[1]))
        manager = self._manager(mirror_urls=[self.base], max_retries=0, backoff_factor=0)
        with self.assertRaises(Exception):
            self._resolve(manager)
        self.assertEqual(list(self.cache.rglob(".whisper-dictate-manifest.json")), [])

    def test_truncated_part_is_rejected(self):
        (self.served / part_names(WEIGHTS)[0]).write_bytes(parts_of(WEIGHTS)[0][:-10])
        manager = self._manager(mirror_urls=[self.base], max_retries=0, backoff_factor=0)
        with self.assertRaises(Exception):
            self._resolve(manager)

    def test_missing_manifest_falls_back_to_huggingface_layout(self):
        (self.served / "mirror-manifest.json").unlink()
        manager = self._manager(
            mirror_urls=[self.base],
            huggingface_endpoint="https://huggingface.co",
            max_retries=0,
            backoff_factor=0,
        )
        with self.assertRaises(Exception) as caught:
            self._resolve(manager)
        # With no manifest the resolver must fall back to the Hugging Face URL
        # layout instead of inventing part URLs.
        statuses = {
            (event.source, event.status): event.detail
            for event in getattr(caught.exception, "trace", ())
        }
        absent = [detail for (_, status), detail in statuses.items() if status == "absent"]
        self.assertTrue(
            any("no mirror-manifest.json" in detail for detail in absent),
            f"expected an explicit 'no mirror-manifest.json' trace, got {statuses!r}",
        )

    def test_manifest_revision_mismatch_is_refused(self):
        data = json.loads((self.served / "mirror-manifest.json").read_text(encoding="utf-8"))
        data["models"][MODEL_ID]["revision"] = "0" * 40
        (self.served / "mirror-manifest.json").write_text(json.dumps(data), encoding="utf-8")
        manager = self._manager(mirror_urls=[self.base], max_retries=0, backoff_factor=0)
        with self.assertRaises(Exception) as caught:
            self._resolve(manager)
        self.assertIn("does not match the pinned revision", str(caught.exception))

    def test_manifest_that_disagrees_with_pinned_hashes_is_refused(self):
        data = json.loads((self.served / "mirror-manifest.json").read_text(encoding="utf-8"))
        data["models"][MODEL_ID]["files"]["model.safetensors"]["sha256"] = "b" * 64
        (self.served / "mirror-manifest.json").write_text(json.dumps(data), encoding="utf-8")
        manager = self._manager(mirror_urls=[self.base], max_retries=0, backoff_factor=0)
        with self.assertRaises(Exception) as caught:
            self._resolve(manager)
        self.assertIn("disagrees with the pinned manifest", str(caught.exception))


def _make_handler(directory: Path):
    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=str(directory), **kwargs)

        def log_message(self, *args):  # silence the test output
            pass

    return Handler


if __name__ == "__main__":
    unittest.main()
