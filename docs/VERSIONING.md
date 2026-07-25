# Arckon Versioning

Arckon uses semantic versioning. `arckon_version.py` is the runtime source of
truth, and package/deployment metadata must use the same release number.

The established product baseline is **v1.0.0**. The Edge DNS Sensor scaffold is
included in this baseline as an unshipped, local-only integration scaffold; it
is not a billable SaaS feature until tenant ingestion, storage, access controls,

Increment versions as follows:

- MAJOR: incompatible API, deployment, or data-model change.
- MINOR: backward-compatible product capability, such as the production Edge DNS
  add-on.
- PATCH: backward-compatible bug fix or security fix.
