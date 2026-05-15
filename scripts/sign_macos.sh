#!/usr/bin/env bash
# M.A.R.K. Sentinel — macOS Code Signing + Notarization Pipeline
#
# Prerequisites:
#   1. Apple Developer Program membership ($99/yr) — developer.apple.com
#   2. Two certificates in your Keychain:
#        "Developer ID Application: M.A.R.K. AI Systems (XXXXXXXXXX)"
#        "Developer ID Installer:   M.A.R.K. AI Systems (XXXXXXXXXX)"
#   3. App-specific password for notarytool:
#        appleid.apple.com → Sign-In and Security → App-Specific Passwords
#   4. Xcode Command Line Tools: xcode-select --install
#
# Usage:
#   bash scripts/sign_macos.sh
#   SKIP_NOTARIZE=1 bash scripts/sign_macos.sh   # sign only, skip notarization
#
# Output:
#   dist/SentinelAgent-1.0.0.pkg   — signed + notarized installer
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

# ── Configuration (fill these in before running) ─────────────────────────────

APP_IDENTITY="Developer ID Application: M.A.R.K. AI Systems (XXXXXXXXXX)"
PKG_IDENTITY="Developer ID Installer: M.A.R.K. AI Systems (XXXXXXXXXX)"

APPLE_ID="your-apple-id@example.com"
APPLE_TEAM_ID="XXXXXXXXXX"
# Generate at appleid.apple.com → Sign-In and Security → App-Specific Passwords
NOTARY_PASSWORD="xxxx-xxxx-xxxx-xxxx"

APP_VERSION="1.0.0"
BUNDLE_ID="io.hash.sentinel"

# ── Paths ─────────────────────────────────────────────────────────────────────

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_BUNDLE="${REPO_ROOT}/Sentinel.app"
ENTITLEMENTS="${REPO_ROOT}/Sentinel.entitlements"
DIST_DIR="${REPO_ROOT}/dist"
PKG_ROOT="${DIST_DIR}/pkgroot"
PKG_COMPONENT="${DIST_DIR}/SentinelAgent-component.pkg"
PKG_FINAL="${DIST_DIR}/SentinelAgent-${APP_VERSION}.pkg"
INSTALL_LOCATION="/Applications"

mkdir -p "${DIST_DIR}"

echo ""
echo "M.A.R.K. Sentinel — macOS Signing Pipeline"
echo "─────────────────────────────────────────────"

# ── Step 1: Sign the .app bundle ──────────────────────────────────────────────

echo ""
echo "[1/5] Signing Sentinel.app ..."

codesign \
    --deep \
    --force \
    --verify \
    --verbose \
    --timestamp \
    --options runtime \
    --entitlements "${ENTITLEMENTS}" \
    --sign "${APP_IDENTITY}" \
    "${APP_BUNDLE}"

echo "  Verifying signature ..."
codesign --verify --deep --strict --verbose=2 "${APP_BUNDLE}"
spctl --assess --type exec --verbose "${APP_BUNDLE}"
echo "  Signature OK"

# ── Step 2: Build component .pkg ──────────────────────────────────────────────

echo ""
echo "[2/5] Building installer package ..."

mkdir -p "${PKG_ROOT}${INSTALL_LOCATION}"
cp -R "${APP_BUNDLE}" "${PKG_ROOT}${INSTALL_LOCATION}/"

pkgbuild \
    --root "${PKG_ROOT}" \
    --identifier "${BUNDLE_ID}.pkg" \
    --version "${APP_VERSION}" \
    --install-location "/" \
    "${PKG_COMPONENT}"

# ── Step 3: Sign the .pkg ─────────────────────────────────────────────────────

echo ""
echo "[3/5] Signing installer package ..."

productsign \
    --sign "${PKG_IDENTITY}" \
    --timestamp \
    "${PKG_COMPONENT}" \
    "${PKG_FINAL}"

pkgutil --check-signature "${PKG_FINAL}"
echo "  Package signature OK"

rm -f "${PKG_COMPONENT}"
rm -rf "${PKG_ROOT}"

if [[ "${SKIP_NOTARIZE:-0}" == "1" ]]; then
    echo ""
    echo "SKIP_NOTARIZE=1 — skipping notarization."
    echo "Signed package: ${PKG_FINAL}"
    exit 0
fi

# ── Step 4: Submit for notarization ──────────────────────────────────────────

echo ""
echo "[4/5] Submitting to Apple Notary Service (this takes 1–5 minutes) ..."

xcrun notarytool submit "${PKG_FINAL}" \
    --apple-id     "${APPLE_ID}" \
    --team-id      "${APPLE_TEAM_ID}" \
    --password     "${NOTARY_PASSWORD}" \
    --wait \
    --timeout 600

# ── Step 5: Staple notarization ticket ───────────────────────────────────────

echo ""
echo "[5/5] Stapling notarization ticket ..."

xcrun stapler staple "${PKG_FINAL}"
xcrun stapler validate "${PKG_FINAL}"

echo ""
echo "Done."
echo "  Output : ${PKG_FINAL}"
echo ""
echo "Distribute SentinelAgent-${APP_VERSION}.pkg — it will install cleanly on"
echo "any Mac without Gatekeeper warnings, no internet check required at install."
