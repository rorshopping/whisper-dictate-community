# Releasing the Community Edition

The repository contains a guarded GitHub Actions release workflow. It is designed to produce **draft, unsigned qualification artifacts**; it does not silently publish them.

## Before tagging

1. Confirm the source tree and exported runtime are clean.
2. Run the full test suite with Python 3.12.
3. Build and test the exact Windows x64 and macOS arm64 payloads on clean machines.
4. Obtain Windows Authenticode signing and macOS Developer ID signing/notarization credentials outside the repository.
5. Review `MODEL_LICENSES.md`, `THIRD-PARTY-NOTICES.md`, the SBOM, and the model revisions.
6. Confirm the website `releases.json` points to the final tag and checksums.

## Export manifest scope

`COMMUNITY_EXPORT_MANIFEST.json` records the deterministic community source
payload produced by the exporter. Repository-level governance files, CI, and
packaging templates added after that export are maintained separately and are
not represented as model/application payload entries.

## Workflow behavior

Pushing a `v*` tag or manually dispatching the workflow:

- runs tests and package guards;
- builds Windows x64 and macOS arm64 archives, including a Windows portable
  archive that carries `PORTABLE.txt` and `WhisperDictate-Portable.cmd`;
- never guards a macOS disk image without a macOS verification record, and
  never ships a mirror it has not checked against the pinned hashes;
- rejects logs, history, local files, secrets, model weights, and unsafe paths;
- generates a CycloneDX SBOM from each built payload
  (`scripts/sbom_from_package.py`) and fails loudly on packaging surprises;
- generates SHA-256 files and machine-readable manifests;
- attaches everything to a **draft** release.

A human must inspect the artifacts, complete signing/notarization, publish the release, and then update the website manifest. Do not treat a successful unsigned build as a stable public release.

Attach the SBOMs, `SHA256SUMS`, and the aggregate `release-manifest.json` to
the published release as well, so a third party can verify what was
redistributed without trusting this repository.

## Local checks

```bash
python -m unittest discover -s tests -p "test_*.py" -v
python scripts/release_guard.py dist/WhisperDictate
python scripts/release_manifest.py <archive> --help
python scripts/sbom_from_package.py dist/WhisperDictate -o sbom.cdx.json
python scripts/check_mirror.py
```

## macOS disk images

A `.dmg` cannot be opened off macOS, so it is guarded by a record instead of by
listing members:

1. build and notarize it on an Apple Silicon Mac with
   `packaging/macos/build_signed_dmg.sh FORMAT=dmg` (the image is written to the
   output directory before the remaining checks, so a failing check cannot
   discard a completed notarization);
2. run `packaging/macos/verify_dmg.sh <image.dmg>` on that Mac, in a GUI
   session, and keep the emitted `*.verification.json`;
3. guard and publish with
   `python scripts/release_guard.py <image.dmg> --dmg-evidence <record.json>`,
   and attach the record to the release so a third party can re-check the claim.

The guard accepts the image only when the record's schema, overall result and
per-check results are present and the image's SHA-256 still matches, so an image
that changed after verification is rejected rather than published.

## Model mirror

`python scripts/check_mirror.py` verifies the mirror chain in `config.json`
without downloading the weights: it fetches `mirror-manifest.json`, validates it
against the pinned manifests, and probes every part URL. Run it before a release
and after any mirror refresh.

Never commit model weights, `.env` files, logs, transcription history, local vocabulary, signing keys, or API tokens.
