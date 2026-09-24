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
- builds Windows x64 and macOS arm64 archives;
- rejects logs, history, local files, secrets, model weights, and unsafe paths;
- generates SHA-256 files and machine-readable manifests;
- attaches everything to a **draft** release.

A human must inspect the artifacts, complete signing/notarization, publish the release, and then update the website manifest. Do not treat a successful unsigned build as a stable public release.

## Local checks

```bash
python -m unittest discover -s tests -p "test_*.py" -v
python scripts/release_guard.py dist/WhisperDictate
python scripts/release_manifest.py <archive> --help
```

Never commit model weights, `.env` files, logs, transcription history, local vocabulary, signing keys, or API tokens.
