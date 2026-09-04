#!/bin/bash
# Build a signed, notarizable .pkg installer for the Arckon ES Collector.
#
# The payload is ArckonESCollector.app (built + already notarized/stapled by
# build.sh). This .pkg additionally gets its own signature + notarization so
# Gatekeeper trusts the INSTALLER action itself; that's separate from (and in
# addition to) the payload .app's own stapled ticket, which is what actually
# satisfies AMFI at daemon-launch time.
#
# This is the artifact an MDM deploys to a fleet (paired with the PPPC profile
# for silent Full Disk Access — see arckon-es-collector.pppc.mobileconfig).
#
# Prereq: build.sh has produced the signed + notarized + stapled
#         ArckonESCollector.app.
# Requires the Developer ID Installer cert (verified: SWRJ6ZV39K).
set -euo pipefail
cd "$(dirname "$0")"

INSTALLER_ID="Developer ID Installer: M. F. Dynamics LLC (SWRJ6ZV39K)"
PKG_ID="ai.mfdynamics.arckon.es-collector"
VERSION="1.0.34"
APP="ArckonESCollector.app"
PLIST="ai.mfdynamics.arckon-es-collector.plist"
OUT="Arckon-ES-Collector-${VERSION}.pkg"
INSTALL_APP_DIR="/Library/Arckon"

[ -d "$APP" ] || { echo "ERROR: $APP not built — run build.sh first." >&2; exit 1; }
security find-identity -v 2>/dev/null | grep -q "Developer ID Installer" \
  || { echo "ERROR: Developer ID Installer cert not in Keychain." >&2; exit 1; }

# ── Stage the install root (payload laid out at final on-disk paths) ─────────
ROOT="pkgroot"
rm -rf "$ROOT" && mkdir -p "$ROOT${INSTALL_APP_DIR}" "$ROOT/Library/LaunchDaemons"
# ditto (not cp) preserves the code signature and resource fork/xattrs.
ditto "$APP" "$ROOT${INSTALL_APP_DIR}/${APP}"
install -m 0644 "$PLIST" "$ROOT/Library/LaunchDaemons/$PLIST"
chmod +x pkg/scripts/postinstall

# ── Build component pkg, then sign it as a distribution pkg ──────────────────
rm -f "component.pkg" "$OUT"
pkgbuild \
  --root "$ROOT" \
  --scripts pkg/scripts \
  --identifier "$PKG_ID" \
  --version "$VERSION" \
  --install-location / \
  "component.pkg"

productbuild \
  --package "component.pkg" \
  --identifier "$PKG_ID" \
  --version "$VERSION" \
  --sign "$INSTALLER_ID" \
  "$OUT"
rm -f "component.pkg"
rm -rf "$ROOT"

echo "==> Verifying pkg signature…"
pkgutil --check-signature "$OUT" | grep -iE "Status|Developer ID Installer" | head -3

# ── Notarize + staple the installer itself ────────────────────────────────────
NOTARY_PROFILE="${ARCKON_NOTARY_PROFILE:-pharaoh}"
if xcrun notarytool history --keychain-profile "$NOTARY_PROFILE" >/dev/null 2>&1; then
  echo "==> Notarizing $OUT (Apple queue; may take a while)…"
  xcrun notarytool submit "$OUT" --keychain-profile "$NOTARY_PROFILE" --wait
  echo "==> Stapling…"
  xcrun stapler staple "$OUT"
  xcrun stapler validate "$OUT" && echo "    ✓ stapled"
  spctl -a -vv -t install "$OUT" 2>&1 || true
else
  echo "==> Skipping notarization: no keychain profile '$NOTARY_PROFILE'." >&2
fi

echo "==> Built: $OUT"
echo "    MDM deploy: push via Jamf/Kandji/Intune/Mosyle alongside the PPPC profile"
echo "    Manual install: sudo installer -pkg $OUT -target /"