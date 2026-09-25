#!/usr/bin/env python3
"""Generate a CycloneDX SBOM from a frozen Whisper Dictate artifact.

The source of truth is the artifact itself, not the build machine: PyInstaller
keeps ``*.dist-info`` metadata for many packages, so the exact versions and
license fields that are redistributed can be read back out of the published
archive. Packages that are bundled as compiled modules *without* their metadata
are reported separately as unresolved, because an SBOM that silently omitted
them would be worse than useless.

Only the standard library is used, so this runs on a clean review machine with
no extra install step and no network access.

    python scripts/sbom_from_package.py Artifact.zip -o sbom.cdx.json
    python scripts/sbom_from_package.py dist/WhisperDictate.app -o sbom.cdx.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import zipfile
from email.message import Message
from email.parser import Parser
from pathlib import Path, PurePosixPath

SBOM_SPEC_VERSION = "1.5"
TOOL_NAME = "whisper-dictate-community/sbom_from_package"
DIST_INFO_RE = re.compile(r"(?P<name>.+?)-(?P<version>[0-9][^-]*)\.dist-info$")
LICENSE_CLASSIFIER_RE = re.compile(r"^License :: OSI Approved :: (.+)$")

# Top-level import names whose dist-info is commonly dropped by PyInstaller.
# They are listed so the report can name them as unresolved instead of hiding
# them; this list is a review aid, not a licence determination.
KNOWN_UNMETADATAD_PACKAGES = {
    "ctranslate2",
    "faster_whisper",
    "pyperclip",
    "pynput",
    "pystray",
    "rapidfuzz",
    "sounddevice",
    "soundfile",
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_metadata(text: str) -> "Message":
    return Parser().parsestr(text)


def license_info(metadata: "Message") -> tuple[str | None, str | None]:
    """Return (SPDX-ish expression, human readable) from wheel metadata."""
    expression = (metadata.get("License-Expression") or "").strip() or None
    classifiers = [
        match.group(1)
        for match in (LICENSE_CLASSIFIER_RE.match(value) for value in metadata.get_all("Classifier", []))
        if match
    ]
    if expression is None and classifiers:
        # A classifier is the weakest signal; keep the raw string so a reviewer
        # can see exactly what the wheel claimed.
        expression = classifiers[0]
    text = (metadata.get("License") or "").strip() or None
    return expression, text


class ArtifactReader:
    """Uniform read access for a directory tree or a ZIP archive."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._zip: zipfile.ZipFile | None = None
        self._root = path
        if path.is_file() and zipfile.is_zipfile(path):
            self._zip = zipfile.ZipFile(path)
        elif not path.is_dir():
            raise SystemExit(f"error: {path} is neither a directory nor a ZIP archive")

    def close(self) -> None:
        if self._zip is not None:
            self._zip.close()

    def __enter__(self) -> "ArtifactReader":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def files(self) -> list[str]:
        if self._zip is not None:
            return self._zip.namelist()
        found: list[str] = []
        for item in self._root.rglob("*"):
            if item.is_file():
                found.append(item.relative_to(self._root).as_posix())
        return found

    def read(self, name: str) -> bytes:
        if self._zip is not None:
            return self._zip.read(name)
        return (self._root / PurePosixPath(name)).read_bytes()


def collect(reader: ArtifactReader) -> tuple[list[dict], list[str]]:
    files = reader.files()
    packages: dict[tuple[str, str], dict] = {}
    unresolved: set[str] = set()

    for name in files:
        parts = PurePosixPath(name).parts
        dist_info_index = next((i for i, part in enumerate(parts) if DIST_INFO_RE.match(part)), None)
        if dist_info_index is None:
            continue
        match = DIST_INFO_RE.match(parts[dist_info_index])
        assert match is not None
        if parts[-1] != "METADATA":
            continue
        key = (match.group("name").lower().replace("_", "-"), match.group("version"))
        if key in packages:
            continue
        metadata = parse_metadata(reader.read(name).decode("utf-8", "replace"))
        expression, text = license_info(metadata)
        packages[key] = {
            "name": metadata.get("Name") or match.group("name"),
            "version": metadata.get("Version") or match.group("version"),
            "spdx": expression,
            "license_text": text,
            "metadata_path": name,
            "has_license_files": any(
                parts[dist_info_index] in f.split("/") and "license" in PurePosixPath(f).name.lower()
                for f in files
                if len(PurePosixPath(f).parts) > dist_info_index + 1
                and PurePosixPath(f).parts[dist_info_index] == parts[dist_info_index]
            ),
        }

    # Any of the known packages present as compiled modules but absent from the
    # dist-info inventory are reported as unresolved rather than omitted.
    resolved_names = {name for name, _version in packages}
    for name in files:
        parts = PurePosixPath(name).parts
        for candidate in KNOWN_UNMETADATAD_PACKAGES:
            if candidate in resolved_names:
                continue
            if any(part.lower() == candidate for part in parts):
                resolved_names.add(candidate)
                unresolved.add(candidate)
    return [packages[key] for key in sorted(packages)], sorted(unresolved)


def build_sbom(
    artifact: Path,
    packages: list[dict],
    unresolved: list[str],
    artifact_sha256: str | None,
) -> dict:
    components = [
        {
            "type": "library",
            "name": package["name"],
            "version": package["version"],
            "purl": f"pkg:pypi/{package['name'].lower().replace('_', '-')}@{package['version']}",
            "scope": "required",
            "licenses": (
                [{"license": {"id": package["spdx"]}}]
                if package["spdx"]
                else ([{"license": {"name": package["license_text"]}}] if package["license_text"] else [])
            ),
            "properties": [
                {"name": "whisper-dictate:metadata-path", "value": package["metadata_path"]},
                {
                    "name": "whisper-dictate:license-files-in-metadata",
                    "value": "true" if package["has_license_files"] else "false",
                },
            ],
        }
        for package in packages
    ]
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": SBOM_SPEC_VERSION,
        "version": 1,
        "metadata": {
            "tools": {"components": [{"type": "application", "name": TOOL_NAME}]},
            "component": {
                "type": "application",
                "name": "Whisper Dictate Community Edition",
                "version": "0.1.0",
            },
            "properties": [
                {"name": "whisper-dictate:artifact", "value": artifact.name},
                *(
                    [{"name": "whisper-dictate:artifact-sha256", "value": artifact_sha256}]
                    if artifact_sha256
                    else []
                ),
            ],
        },
        "components": components,
    }
    if unresolved:
        document["properties"] = [
            {
                "name": "whisper-dictate:unresolved-bundled-packages",
                "value": ",".join(unresolved),
            },
            {
                "name": "whisper-dictate:unresolved-note",
                "value": (
                    "These packages ship as compiled modules without bundled dist-info metadata. "
                    "Their versions must be recorded in THIRD-PARTY-NOTICES.md from the build "
                    "environment before a stable release."
                ),
            },
        ]
    return document


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("artifact", type=Path, help="frozen .zip, .app, or an unpacked payload directory")
    parser.add_argument("-o", "--output", type=Path, help="write JSON here instead of stdout")
    args = parser.parse_args()

    artifact_sha256 = sha256_file(args.artifact) if args.artifact.is_file() else None
    with ArtifactReader(args.artifact) as reader:
        packages, unresolved = collect(reader)

    if not packages:
        print("error: no *.dist-info metadata found; the artifact cannot produce an SBOM", file=sys.stderr)
        return 1

    document = build_sbom(args.artifact, packages, unresolved, artifact_sha256)
    payload = json.dumps(document, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload, encoding="utf-8", newline="\n")
        print(f"wrote {args.output} ({len(packages)} component(s), {len(unresolved)} unresolved)")
    else:
        sys.stdout.write(payload)
    if unresolved:
        print(f"warning: unresolved bundled packages: {', '.join(unresolved)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
