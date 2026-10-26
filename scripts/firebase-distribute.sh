#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# firebase-distribute.sh
# Builds the Flutter APK (split per ABI) and uploads both variants to
# Firebase App Distribution.
#
# Prerequisites:
#   1. Firebase CLI installed: npm install -g firebase-tools
#   2. Logged in OR FIREBASE_TOKEN set:
#        firebase login          (interactive, for local use)
#        firebase login:ci       (prints a CI token — save as FIREBASE_TOKEN)
#   3. FIREBASE_APP_ID env var set to your Android app ID from Firebase Console
#        Format: 1:123456789:android:abcdef1234567890
#        Find it: Firebase Console → your project → Project settings → Your apps
#
# Usage:
#   FIREBASE_APP_ID="1:xxx:android:yyy" ./scripts/firebase-distribute.sh
#   FIREBASE_APP_ID="1:xxx:android:yyy" RELEASE_NOTES="Bug fixes" ./scripts/firebase-distribute.sh
# ---------------------------------------------------------------------------
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
FLUTTER_APP="$REPO_ROOT/mobile/iceberg_app"
APK_DIR="$FLUTTER_APP/build/app/outputs/flutter-apk"
DOWNLOADS_DIR="$REPO_ROOT/web/downloads"

if [[ -z "${FIREBASE_APP_ID:-}" ]]; then
  echo "ERROR: FIREBASE_APP_ID is not set."
  echo "  Find it in Firebase Console → Project settings → Your apps"
  echo "  Format: 1:123456789:android:abcdef1234567890"
  exit 1
fi

RELEASE_NOTES="${RELEASE_NOTES:-$(git -C "$REPO_ROOT" log -1 --pretty=format:'%s' 2>/dev/null || echo 'New build')}"
TESTERS="${TESTERS:-}"        # comma-separated emails, e.g. "a@b.com,c@d.com"
TESTER_GROUPS="${TESTER_GROUPS:-}"  # comma-separated group aliases

echo "==> Building Flutter APKs (split per ABI)..."
cd "$FLUTTER_APP"
flutter build apk --release --split-per-abi

ARM64_APK="$APK_DIR/app-arm64-v8a-release.apk"
ARM32_APK="$APK_DIR/app-armeabi-v7a-release.apk"

echo "==> Built:"
ls -lh "$ARM64_APK" "$ARM32_APK"

# Copy to web/downloads/ so the website stays in sync
mkdir -p "$DOWNLOADS_DIR"
cp "$ARM64_APK"  "$DOWNLOADS_DIR/iceberg.apk"
cp "$ARM32_APK"  "$DOWNLOADS_DIR/iceberg-32bit.apk"
echo "==> Copied APKs to web/downloads/"

distribute() {
  local apk="$1"
  local label="$2"
  local notes="$RELEASE_NOTES [$label]"

  echo ""
  echo "==> Distributing $label: $(basename "$apk")"

  local args=(
    --app "$FIREBASE_APP_ID"
    --file "$apk"
    --release-notes "$notes"
  )
  [[ -n "$TESTERS" ]]       && args+=(--testers "$TESTERS")
  [[ -n "$TESTER_GROUPS" ]] && args+=(--groups "$TESTER_GROUPS")
  [[ -n "${FIREBASE_TOKEN:-}" ]] && args+=(--token "$FIREBASE_TOKEN")

  firebase appdistribution:distribute "${args[@]}"
  echo "==> Done: $label"
}

distribute "$ARM64_APK" "arm64"
distribute "$ARM32_APK" "arm32"

echo ""
echo "==> Both APKs distributed to Firebase App Distribution."
echo "    Testers will receive an email/notification to install the update."
