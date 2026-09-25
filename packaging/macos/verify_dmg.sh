#!/usr/bin/env bash
# Verify a notarized macOS disk image and emit machine-readable evidence.
#
# The release guard cannot mount a disk image on a non-Apple machine, so this
# script runs every check that matters and writes a signed-off JSON record.  The
# guard then accepts the image when the file's SHA-256 matches the record and the
# record lists each required check as passed - it never trusts a name.
#
# Usage:
#   verify_dmg.sh <image.dmg> [evidence.json]
#
# Run it in a GUI session: codesign needs the login keychain (errSecInternalComponent
# over a plain SSH session).

set -euo pipefail

IMAGE="${1:?usage: verify_dmg.sh <image.dmg> [evidence.json]}"
EVIDENCE="${2:-${IMAGE%.dmg}.verification.json}"
MOUNT_DIR="$(mktemp -d "${TMPDIR:-/tmp}/wd-dmg-verify.XXXXXX")"

cleanup() {
  hdiutil detach "$MOUNT_DIR" -force >/dev/null 2>&1 || true
  rmdir "$MOUNT_DIR" >/dev/null 2>&1 || true
}
trap cleanup EXIT

fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

[[ -f "$IMAGE" ]] || fail "image not found: $IMAGE"
[[ "$(uname -s)" == "Darwin" ]] || fail "this verification must run on macOS"

IMAGE_SHA="$(shasum -a 256 "$IMAGE" | awk '{print $1}')"
IMAGE_SIZE="$(stat -f %z "$IMAGE")"
APP_NAME="WhisperDictate.app"

# Renders one check as a JSON object; CHECKS_JSON accumulates them so the
# document stays valid JSON (a missing comma here would silently produce a
# record the guard cannot parse).
CHECKS_JSON=""
check_json() {
  # $1 = name, $2 = passed(0/1), $3 = detail
  local passed="false"
  [[ "$2" == "1" ]] && passed="true"
  local entry
  printf -v entry '    {"name": "%s", "passed": %s, "detail": "%s"}' "$1" "$passed" "$3"
  if [[ -n "$CHECKS_JSON" ]]; then
    CHECKS_JSON+=",
$entry"
  else
    CHECKS_JSON="$entry"
  fi
}

hdiutil verify "$IMAGE" >/dev/null 2>&1 && HDIUTIL_OK=1 || HDIUTIL_OK=0
hdiutil attach "$IMAGE" -nobrowse -readonly -mountpoint "$MOUNT_DIR" >/dev/null
[[ -d "$MOUNT_DIR/$APP_NAME" ]] || fail "$APP_NAME is not at the image root"

APP="$MOUNT_DIR/$APP_NAME"
codesign --verify --deep --strict "$APP" >/dev/null 2>&1 && CODESIGN_OK=1 || CODESIGN_OK=0
xcrun stapler validate "$APP" >/dev/null 2>&1 && APP_STAPLED_OK=1 || APP_STAPLED_OK=0
ASSESSMENT="$(spctl -a -t exec -vv "$APP" 2>&1 || true)"
if printf '%s' "$ASSESSMENT" | grep -q "source=Notarized Developer ID"; then
  SPCTL_OK=1
else
  SPCTL_OK=0
fi
DMG_ASSESSMENT="$(spctl -a -t open --context context:primary-signature -vv "$IMAGE" 2>&1 || true)"
if printf '%s' "$DMG_ASSESSMENT" | grep -q "source=Notarized Developer ID"; then
  DMG_SPCTL_OK=1
else
  DMG_SPCTL_OK=0
fi

# The app must not start a model download or a tray loop during verification.
DOCTOR_OUTPUT="$("$APP/Contents/MacOS/WhisperDictate" --doctor --console 2>&1 || true)"
if printf '%s' "$DOCTOR_OUTPUT" | grep -q "Whisper Dictate doctor"; then
  DOCTOR_OK=1
else
  DOCTOR_OK=0
fi
if printf '%s' "$DOCTOR_OUTPUT" | grep -q "model cached"; then
  DOCTOR_NO_MODEL_NOTE="model caches absent, as expected on a clean machine"
else
  DOCTOR_NO_MODEL_NOTE="model caches present"
fi

cleanup
trap - EXIT

ALL_OK=1
for value in "$HDIUTIL_OK" "$CODESIGN_OK" "$APP_STAPLED_OK" "$SPCTL_OK" "$DMG_SPCTL_OK" "$DOCTOR_OK"; do
  [[ "$value" == "1" ]] || ALL_OK=0
done

check_json "hdiutil-verify" "$HDIUTIL_OK" "image checksum verified"
check_json "codesign-deep-strict" "$CODESIGN_OK" "app signature valid on disk"
check_json "stapler-app" "$APP_STAPLED_OK" "app inside the image has a stapled ticket"
check_json "spctl-app" "$SPCTL_OK" "Gatekeeper: source=Notarized Developer ID"
check_json "spctl-image" "$DMG_SPCTL_OK" "image assessment: source=Notarized Developer ID"
check_json "doctor-smoke" "$DOCTOR_OK" "$DOCTOR_NO_MODEL_NOTE"

OVERALL="false"
[[ "$ALL_OK" == "1" ]] && OVERALL="true"

cat >"$EVIDENCE" <<JSON
{
  "schema": "whisper-dictate.dmg-verification.v1",
  "image": "$(basename "$IMAGE")",
  "sha256": "$IMAGE_SHA",
  "size_bytes": $IMAGE_SIZE,
  "verified_on": "macOS $(sw_vers -productVersion) ($(uname -m))",
  "verified_at": "$(date -u +%FT%TZ)",
  "app": "$APP_NAME",
  "passed": $OVERALL,
  "checks": [
$CHECKS_JSON
  ]
}
JSON

python3 -c "import json,sys; json.load(open(sys.argv[1]))" "$EVIDENCE" \
  || fail "the generated evidence record is not valid JSON"

cat "$EVIDENCE"
[[ "$ALL_OK" == "1" ]] || fail "one or more disk-image checks failed; see $EVIDENCE"
printf 'Wrote %s\n' "$EVIDENCE"
