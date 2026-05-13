terraform {
  required_version = ">= 1.3.0"
  required_providers {
    null = {
      source  = "hashicorp/null"
      version = ">= 3.0"
    }
  }
}

# ── Variables ─────────────────────────────────────────────────────────────────

variable "hosts" {
  description = "Map of host name → IP/hostname for each target machine"
  type        = map(string)
  # Example:
  # hosts = {
  #   web01 = "10.0.1.10"
  #   web02 = "10.0.1.11"
  #   db01  = "10.0.1.20"
  # }
}

variable "ssh_user"        { default     = "ubuntu" }
variable "ssh_key"         { description = "Path to SSH private key" }
variable "sentinel_server" { description = "Sentinel server URL (e.g. http://10.0.1.50:7331)" }
variable "sentinel_token"  { sensitive   = true }

# ── Deploy to all hosts in parallel ──────────────────────────────────────────
# Terraform deploys all instances concurrently by default.
# Use -parallelism=N to limit if SSH connections are rate-limited.

module "sentinel_agents" {
  for_each = var.hosts
  source   = "../../modules/sentinel-agent"

  host            = each.value
  ssh_user        = var.ssh_user
  ssh_key         = var.ssh_key
  sentinel_server = var.sentinel_server
  sentinel_token  = var.sentinel_token
}

# ── Outputs ───────────────────────────────────────────────────────────────────

output "device_ids" {
  description = "Map of host name → Sentinel device ID"
  value       = { for name, mod in module.sentinel_agents : name => mod.device_id }
}
