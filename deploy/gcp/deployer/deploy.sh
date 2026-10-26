#!/bin/sh
set -eu

# Source patching cannot preserve key mounts or provide image rollback.
echo "ERROR: API hot-patch deployment is retired. Use the approved signed-image promotion workflow. No files copied or containers restarted." >&2
exit 1
