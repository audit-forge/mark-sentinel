#!/bin/bash
# Build and sign ArckonESCollector.app — the Endpoint Security client for
# Arckon's Protected Files monitoring feature.
#
# Adapted from the proven Pharaoh ESF build pipeline (project-pharaoh/agent/macos-esf/build.sh).
# Same signing identity, same entitlement, same bundle structure required by AMFI.
#
# WHY A BUNDLE: AMFI's restricted-entitlement validator does its own
# bundle-structure-aware provisioning-profile lookup. A bare executable —
# even with the entitlement and embedded profile — is rejected at EXEC time
# with AppleMobileFileIntegrityError -413 "No matching profile found."
# A real .app bundle with Contents/Info.plist and Contents/embedded.provisionprofile
# as actual FILES is required. Verified live in the Pharaoh ESF implementation.
#
# Requires FULL Xcode (not just Command Line Tools): libEndpointSecurity.tbd
# is only in the Xcode SDK.
set -euo pipefail
cd "$(dirname "$0")"

IDENTITY="Developer ID Application: M. F. Dynamics LLC (SWRJ6ZV39K)"
TEAM_ID="SWRJ6ZV39K"
APP="ArckonESCollector.app"
ENTITLEMENTS="arckon-es-collector.entitlements"
INFO_PLIST="arckon-es-collector.Info.plist"
PROFILE="arckon-es-collector.provisionprofile"

# ── Locate a full Xcode ──────────────────────────────────────────────────────
find_xcode() {
  if [ -n "${DEVELOPER_DIR:-}" ] && [ -x "$DEVELOPER_DIR/usr/bin/swiftc" ]; then return; fi
  local sel; sel="$(xcode-select -p 2>/dev/null || true)"
  if echo "$sel" | grep -q "Xcode.app"; then export DEVELOPER_DIR="$sel"; return; fi
  for cand in /Applications/Xcode.app "$HOME/Downloads/Xcode.app"; do
    if [ -d "$cand" ]; then export DEVELOPER_DIR="$cand/Contents/Developer"; return; fi
  done
  echo "ERROR: full Xcode not found (CLT can't link EndpointSecurity)." >&2
  exit 1
}
find_xcode
echo "==> Using Xcode at: $DEVELOPER_DIR"

if ! security find-identity -v -p codesigning | grep -q "$TEAM_ID"; then
  echo "ERROR: Developer ID Application identity ($TEAM_ID) not in Keychain." >&2
  exit 1
fi
if [ ! -f "$PROFILE" ]; then
  echo "ERROR: $PROFILE missing — create it in the Apple Developer portal:" >&2
  echo "  1. Certificates, IDs & Profiles → Identifiers → create App ID" >&2
  echo "     ai.mfdynamics.arckon.agent (with ES capability)" >&2
  echo "  2. Profiles → create Developer ID provisioning profile for that App ID" >&2
  echo "  3. Download it and place as $PROFILE" >&2
  exit 1
fi

# ── Lay out the bundle ────────────────────────────────────────────────────────
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$INFO_PLIST" "$APP/Contents/Info.plist"
cp "$PROFILE" "$APP/Contents/embedded.provisionprofile"

echo "==> Compiling arckon-es-collector (universal)…"
LINK=(-lEndpointSecurity -lbsm)
xcrun swiftc -O -target arm64-apple-macos12  "${LINK[@]}" -o "${APP}/Contents/MacOS/arckon-es-collector.arm64"  arckon-es-collector.swift
xcrun swiftc -O -target x86_64-apple-macos12 "${LINK[@]}" -o "${APP}/Contents/MacOS/arckon-es-collector.x86_64" arckon-es-collector.swift
lipo -create -output "${APP}/Contents/MacOS/arckon-es-collector" "${APP}/Contents/MacOS/arckon-es-collector.arm64" "${APP}/Contents/MacOS/arckon-es-collector.x86_64"
rm -f "${APP}/Contents/MacOS/arckon-es-collector.arm64" "${APP}/Contents/MacOS/arckon-es-collector.x86_64"

# ── Sign the BUNDLE ──────────────────────────────────────────────────────────
echo "==> Signing…"
codesign --sign "$IDENTITY" --entitlements "$ENTITLEMENTS" \
  --options runtime --timestamp --force "$APP"

echo "==> Verifying…"
codesign --verify --deep --verbose=2 "$APP"
codesign -d --entitlements :- "$APP" 2>/dev/null | grep -q "endpoint-security" \
  && echo "    ✓ endpoint-security entitlement present" \
  || { echo "    ✗ entitlement missing" >&2; exit 1; }

# ── Notarize + staple ────────────────────────────────────────────────────────
# Default to the dedicated 'arckon' keychain profile. Falls back to 'pharaoh'
# (the legacy shared profile) if 'arckon' isn't configured yet. Override with
# ARCKON_NOTARY_PROFILE env var. Create the profile with:
#   xcrun notarytool store-credentials arckon --apple-id keith@mfdynamics.ai --team-id SWRJ6ZV39K
NOTARY_PROFILE="${ARCKON_NOTARY_PROFILE:-arckon}"
ZIP="ArckonESCollector.app.zip"
ditto -c -k --keepParent "$APP" "$ZIP"
if xcrun notarytool history --keychain-profile "$NOTARY_PROFILE" >/dev/null 2>&1; then
  echo "==> Notarizing via keychain profile '$NOTARY_PROFILE'…"
  xcrun notarytool submit "$ZIP" --keychain-profile "$NOTARY_PROFILE" --wait
  echo "==> Stapling…"
  xcrun stapler staple "$APP"
  xcrun stapler validate "$APP" && echo "    ✓ stapled"
  spctl -a -vv "$APP" 2>&1 || true
else
  # Fall back to the legacy shared profile if the dedicated one isn't set up yet
  FALLBACK="pharaoh"
  if xcrun notarytool history --keychain-profile "$FALLBACK" >/dev/null 2>&1; then
    echo "==> Notarizing via fallback keychain profile '$FALLBACK'…"
    xcrun notarytool submit "$ZIP" --keychain-profile "$FALLBACK" --wait
    echo "==> Stapling…"
    xcrun stapler staple "$APP"
    xcrun stapler validate "$APP" && echo "    ✓ stapled"
    spctl -a -vv "$APP" 2>&1 || true
  else
    echo "==> Skipping notarization: no keychain profile '$NOTARY_PROFILE' or '$FALLBACK'." >&2
    echo "    Create one with: xcrun notarytool store-credentials arckon --apple-id keith@mfdynamics.ai --team-id SWRJ6ZV39K" >&2
  fi
fi
rm -f "$ZIP"

echo "==> Built: $APP"
echo "    Install: sudo cp -r $APP /Library/Arckon/"
echo "    LaunchDaemon: sudo cp ai.mfdynamics.arckon-es-collector.plist /Library/LaunchDaemons/"
echo "    Load: sudo launchctl load /Library/LaunchDaemons/ai.mfdynamics.arckon-es-collector.plist"