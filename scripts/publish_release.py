#!/usr/bin/env python3
"""Download signed agent release artifacts from GitHub and publish to the Arckon release host.

This script is meant to be run from a maintainer workstation after the GitHub Actions
`Signed Agent Release` workflow finishes. It:

1. Finds the workflow run for a given tag.
2. Downloads the Linux, macOS, and Windows release artifacts.
3. Verifies the Ed25519 signature on each manifest using the pinned agent public key.
4. Verifies each artifact's SHA-256 and size against its manifest.
5. Pushes the validated artifacts and manifests to the GCP release host via
   `gcloud compute scp`, then atomically swaps them into /opt/sentinel/releases.

Usage:
    export ARCKON_RELEASE_HOST=mark-sentinel
    export ARCKON_RELEASE_HOST_ZONE=us-central1-a
    export ARCKON_RELEASE_HOST_PROJECT=infra-analyzer-496922-p0
    export ARCKON_RELEASE_HOST_USER=keith@mfdynamics.ai
    python3 scripts/publish_release.py v1.0.17

Requirements:
    - gcloud CLI authenticated and authorized to SSH via IAP to the release host.
    - gh CLI authenticated (github.com).
    - cryptography (already in requirements.txt).
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# Must match agent.py / scripts/create_release.py exactly.
PINNED_UPDATE_PUBLIC_KEY_DER_B64 = "MCowBQYDK2VwAyEAxQSQJT9gaFKKcPEy7nPM7Bdk0fT8LXNDIsQkw1qfLyw="
_PLATFORMS = ("linux", "macos", "windows")
_VERSION_RE = re.compile(r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")


def _pinned_public_key() -> Ed25519PublicKey:
    pub = serialization.load_der_public_key(
        base64.b64decode(PINNED_UPDATE_PUBLIC_KEY_DER_B64, validate=True)
    )
    if not isinstance(pub, Ed25519PublicKey):
        raise RuntimeError("pinned key is not Ed25519")
    return pub


def _run(cmd: list[str], *, check: bool = True, capture: bool = True) -> str:
    result = subprocess.run(
        cmd,
        capture_output=capture,
        text=True,
        check=False,
    )
    if check and result.returncode != 0:
        sys.stderr.write(f"Command failed: {' '.join(cmd)}\n")
        sys.stderr.write(result.stderr or "")
        raise SystemExit(result.returncode)
    return (result.stdout or "").strip()


def _gh_release_assets(tag: str, tmp: Path) -> dict[str, Path]:
    """Download artifact tarball and both manifest files for every platform."""
    version = tag.lstrip("v")
    assets: dict[str, Path] = {}
    for plat in _PLATFORMS:
        # Linux artifact uses the `-linux-amd64` suffix; macOS/Windows do not.
        artifact_name = (
            f"arckon-agent-{version}-linux-amd64.tar.gz"
            if plat == "linux"
            else f"arckon-agent-{version}-{plat}.tar.gz"
        )
        manifest_name = f"{plat}-manifest.json"
        sig_name = f"{plat}-manifest.sig"
        for name in (artifact_name, manifest_name, sig_name):
            dest = tmp / name
            _run(["gh", "release", "download", tag, "--repo", "audit-forge/mark-sentinel", "--pattern", name, "--dir", str(tmp)])
            assets[name] = dest
    return assets


def _verify_manifest(pub: Ed25519PublicKey, manifest_path: Path, sig_path: Path, artifact_path: Path) -> dict:
    manifest_bytes = manifest_path.read_bytes()
    signature = sig_path.read_bytes()
    try:
        pub.verify(signature, manifest_bytes)
    except InvalidSignature as e:
        raise ValueError(f"invalid signature for {manifest_path.name}") from e

    manifest = json.loads(manifest_bytes)
    canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if canonical != manifest_bytes:
        raise ValueError(f"manifest {manifest_path.name} is not canonical JSON")

    data = artifact_path.read_bytes()
    if len(data) != manifest["size"]:
        raise ValueError(f"size mismatch for {artifact_path.name}")
    if hashlib.sha256(data).hexdigest() != manifest["sha256"]:
        raise ValueError(f"sha256 mismatch for {artifact_path.name}")

    return manifest


def _gcloud_ssh_base(host: str, zone: str, project: str) -> list[str]:
    return [
        "gcloud", "compute", "ssh", host,
        f"--project={project}",
        f"--zone={zone}",
        "--tunnel-through-iap",
    ]


def _publish_to_host(
    tag: str,
    assets: dict[str, Path],
    host: str,
    zone: str,
    project: str,
    user: str | None,
) -> None:
    version = tag.lstrip("v")
    ssh_base = _gcloud_ssh_base(host, zone, project)
    if user:
        ssh_base.extend([f"--account={user}"])

    target_parent = f"/opt/sentinel/releases/v{version}"
    tmp_parent = f"/tmp/sentinel-publish-v{version}-{int(time.time())}"

    # Sanity check: the agent expects /releases/<platform>/manifest.json relative to
    # the server URL. The live platform paths are symlinks that we atomically swap.

    # 1. Create a versioned staging directory on the host.
    _run(ssh_base + [f"--command=sudo mkdir -p {target_parent} && sudo chown root:docker {target_parent} && sudo chmod 750 {target_parent}"])

    # 2. Push each platform directory separately with correct permissions.
    for plat in _PLATFORMS:
        local_dir = assets["dir"] / plat
        # The local directory already contains the platform files. scp --recurse
        # will create a sub-directory named after the source, so stage into a
        # sibling temp path and then move its contents up one level.
        staging_parent = f"{tmp_parent}/{plat}-src"
        staging_dir = f"{staging_parent}/{plat}"
        final_dir = f"{target_parent}/{plat}"

        _run(ssh_base + [f"--command=sudo mkdir -p {staging_parent} && sudo chown $(whoami):docker {staging_parent}"])
        scp_cmd = [
            "gcloud", "compute", "scp",
            "--project", project,
            "--zone", zone,
            "--tunnel-through-iap",
            "--recurse",
            str(local_dir),
            f"{host}:{staging_parent}",
        ]
        if user:
            scp_cmd[1:1] = [f"--account={user}"]
        _run(scp_cmd)
        _run(ssh_base + [
            f"--command=sudo mv {staging_dir} {final_dir} && "
            f"sudo rm -rf {staging_parent} && "
            f"sudo chown -R root:docker {final_dir} && "
            f"sudo chmod -R 750 {final_dir}",
        ])

    # 3. Atomically swap the live platform symlinks. Avoid 'cd' into a
    # directory that the unprivileged SSH user cannot read; use absolute paths.
    _run(ssh_base + [
        f"--command="
        f"cd /tmp && "
        f"for plat in {' '.join(_PLATFORMS)}; do "
        f"  sudo ln -sfn {target_parent}/$plat /opt/sentinel/releases/$plat.new && "
        f"  sudo mv -Tf /opt/sentinel/releases/$plat.new /opt/sentinel/releases/$plat; "
        f"done && "
        f"echo 'Live release now points to v{version}'",
    ])

    print(f"Published {tag} to release host {host} at {target_parent}")


def _main() -> int:
    parser = argparse.ArgumentParser(description="Publish a signed Arckon agent release to the release host.")
    parser.add_argument("tag", help="Git tag to publish, e.g. v1.0.17")
    parser.add_argument("--host", default=os.environ.get("ARCKON_RELEASE_HOST", "mark-sentinel"), help="GCP VM name")
    parser.add_argument("--zone", default=os.environ.get("ARCKON_RELEASE_HOST_ZONE", "us-central1-a"), help="GCP zone")
    parser.add_argument("--project", default=os.environ.get("ARCKON_RELEASE_HOST_PROJECT", "infra-analyzer-496922-p0"), help="GCP project")
    parser.add_argument("--user", default=os.environ.get("ARCKON_RELEASE_HOST_USER"), help="gcloud account override")
    parser.add_argument("--keep-tmp", action="store_true", help="Do not delete the temporary download directory")
    args = parser.parse_args()

    if not _VERSION_RE.fullmatch(args.tag):
        print(f"error: tag must be like vX.Y.Z, got {args.tag}", file=sys.stderr)
        return 1

    pub = _pinned_public_key()

    with tempfile.TemporaryDirectory(prefix="arckon-publish-") as tmpdir:
        tmp = Path(tmpdir)
        print(f"Downloading release assets for {args.tag}...")
        assets = _gh_release_assets(args.tag, tmp)

        # Group assets into per-platform directories for easy scp.
        for plat in _PLATFORMS:
            plat_dir = tmp / plat
            plat_dir.mkdir()
            version = args.tag.lstrip("v")
            # Linux artifact name includes -amd64; the manifest already names the
            # exact artifact, so keep the downloaded filename and just move it.
            artifact = (
                f"arckon-agent-{version}-linux-amd64.tar.gz"
                if plat == "linux"
                else f"arckon-agent-{version}-{plat}.tar.gz"
            )
            shutil.move(str(assets[artifact]), str(plat_dir / artifact))
            shutil.move(str(assets[f"{plat}-manifest.json"]), str(plat_dir / "manifest.json"))
            shutil.move(str(assets[f"{plat}-manifest.sig"]), str(plat_dir / "manifest.sig"))

        print("Verifying signed manifests and artifact hashes...")
        for plat in _PLATFORMS:
            plat_dir = tmp / plat
            version = args.tag.lstrip("v")
            artifact_name = (
                f"arckon-agent-{version}-linux-amd64.tar.gz"
                if plat == "linux"
                else f"arckon-agent-{version}-{plat}.tar.gz"
            )
            manifest = _verify_manifest(
                pub,
                plat_dir / "manifest.json",
                plat_dir / "manifest.sig",
                plat_dir / artifact_name,
            )
            print(f"  {plat}: OK (artifact={manifest['artifact']}, sha256={manifest['sha256'][:16]}...)")

        assets["dir"] = tmp
        print(f"Publishing to release host {args.host}...")
        _publish_to_host(args.tag, assets, args.host, args.zone, args.project, args.user)

        if args.keep_tmp:
            print(f"Keeping temporary directory: {tmp}")

    print("Done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
