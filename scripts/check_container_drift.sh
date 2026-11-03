#!/usr/bin/env bash
# Compare running server sources to an explicit release/build source directory.
# Default to the VM repo; non-git snapshots are useful only for hotfix checks.
set -euo pipefail
source_dir="${1:-/opt/sentinel}"
if git -C "$source_dir" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    git -C "$source_dir" diff --quiet HEAD -- server.py storage.py || {
        printf '%s\n' 'FAIL: release sources have uncommitted changes'
        exit 1
    }
fi
for file in server.py storage.py; do
    expected=$(sha256sum "$source_dir/$file")
    expected="${expected%% *}"
    for tenant in opco pix mfdynamicsllc; do
        actual=$(docker exec "sentinel-$tenant" sha256sum "/app/$file")
        actual="${actual%% *}"
        if [[ "$actual" != "$expected" ]]; then
            printf 'FAIL: %s %s differs from %s\n' "$tenant" "$file" "$source_dir"
            exit 1
        fi
        printf 'PASS: %s %s\n' "$tenant" "$file"
    done
done
