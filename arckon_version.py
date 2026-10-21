"""Single source of truth for Arckon product versioning."""

VERSION = "1.0.68"
# Increment whenever the tenant-specific Windows installer changes. This is
# separate from the agent version because the package also contains install and
# uninstall logic that can change without a new agent binary.
INSTALLER_VERSION = "1.0.66.6"
EDGE_DNS_EVENT_SCHEMA_VERSION = 1
