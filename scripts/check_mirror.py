#!/usr/bin/env python3
"""Verify a configured model mirror without downloading the weights.

Checks, against the mirror chain in `config.json`:

1. the base serves a `mirror-manifest.json` that parses and validates;
2. every model and file the application pins is present with matching size and
   SHA-256;
3. every part URL answers over HTTPS with the expected size (a ranged read of a
   few bytes, so this stays fast for multi-gigabyte files);
4. the Hugging Face revision stays the pinned one.

Run it before a release and after a mirror refresh:

    python scripts/check_mirror.py
    python scripts/check_mirror.py --part-bytes 65536
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from model_manager import (  # noqa: E402
    MIRROR_MANIFEST_NAME,
    ModelManifest,
    default_manifests,
    parse_mirror_manifest,
    parse_model_config,
)

TIMEOUT = 60


def fetch_json(url: str) -> dict:
    with urlopen(Request(url, headers={"User-Agent": "whisper-dictate-mirror-check"}), timeout=TIMEOUT) as response:
        if response.status != 200:
            raise RuntimeError(f"{url} returned HTTP {response.status}")
        return json.loads(response.read().decode("utf-8"))


def check_part(url: str, expected_size: int, sample_bytes: int) -> str:
    """Confirm the part answers and reports the expected length."""

    request = Request(url, headers={"User-Agent": "whisper-dictate-mirror-check", "Range": f"bytes=0-{sample_bytes - 1}"})
    with urlopen(request, timeout=TIMEOUT) as response:  # noqa: S310 - https URL from the manifest
        declared = response.headers.get("Content-Range") or response.headers.get("Content-Length")
        body = response.read(sample_bytes)
    if declared and "/" in str(declared):
        total = int(str(declared).rsplit("/", 1)[1])
        if total != expected_size:
            return f"size mismatch: server reports {total}, manifest says {expected_size}"
    elif declared and str(declared).isdigit() and not body:
        return f"size mismatch: server reports {declared}, manifest says {expected_size}"
    if not body:
        return "empty response"
    return "ok"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config", default=str(ROOT / "config.json"))
    parser.add_argument("--part-bytes", type=int, default=1024, help="bytes to read per part probe")
    args = parser.parse_args()

    config = json.loads(Path(args.config).read_text(encoding="utf-8"))
    settings = parse_model_config(config)
    bases = list(settings.mirror_urls)
    if not bases:
        print("no mirror base is configured; nothing to verify")
        return 0
    pinned = {manifest.model_id: manifest for manifest in default_manifests().manifests}

    problems: list[str] = []
    for base in bases:
        url = f"{base.rstrip('/')}/{MIRROR_MANIFEST_NAME}"
        print(f"== {url}")
        try:
            payload = fetch_json(url)
        except urllib.error.HTTPError as exc:
            problems.append(f"{url} returned HTTP {exc.code}")
            continue
        except (urllib.error.URLError, OSError, ValueError) as exc:
            problems.append(f"{url} could not be read: {exc}")
            continue

        try:
            mirror = parse_mirror_manifest(payload)
        except Exception as exc:  # noqa: BLE001 - report any validation problem
            problems.append(f"{url} is not a valid mirror manifest: {exc}")
            continue

        for model_id, manifest in pinned.items():
            entry = mirror.get(model_id)
            if entry is None:
                problems.append(f"{base} does not mirror {model_id}")
                continue
            if entry["revision"] != manifest.revision:
                problems.append(
                    f"{base} {model_id}: revision {entry['revision']} != pinned {manifest.revision}"
                )
                continue
            for required in manifest.required_files:
                spec = entry["files"].get(required.name)
                if spec is None:
                    problems.append(f"{base} {model_id}: {required.name} is missing")
                    continue
                if spec["size"] != required.size or spec["sha256"] != required.sha256:
                    problems.append(
                        f"{base} {model_id}/{required.name}: manifest disagrees with the pinned hash"
                    )
                    continue
                for part in spec["parts"]:
                    try:
                        status = check_part(part["url"], part["size"], args.part_bytes)
                    except (urllib.error.URLError, OSError) as exc:
                        status = f"unreachable: {exc}"
                    if status != "ok":
                        problems.append(f"{part['url']}: {status}")
                    else:
                        print(f"   ok {part['url'].rsplit('/', 1)[-1]} ({part['size']:,} bytes)")

    if problems:
        print("Mirror check FAILED:")
        for problem in problems:
            print(f"- {problem}")
        return 1
    print(f"Mirror check passed: {len(bases)} base(s) mirror every pinned file.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
