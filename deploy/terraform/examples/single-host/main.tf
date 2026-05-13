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

variable "host"            { description = "IP or hostname of the target machine" }
variable "ssh_user"        { default     = "ubuntu" }
variable "ssh_key"         { description = "Path to SSH private key" }
variable "sentinel_server" { description = "Sentinel server URL (e.g. http://10.0.1.50:7331)" }
variable "sentinel_token"  { sensitive   = true }

# ── Deploy to a single host ───────────────────────────────────────────────────

module "sentinel_agent" {
  source = "../../modules/sentinel-agent"

  host            = var.host
  ssh_user        = var.ssh_user
  ssh_key         = var.ssh_key
  sentinel_server = var.sentinel_server
  sentinel_token  = var.sentinel_token
}

# ── Outputs ───────────────────────────────────────────────────────────────────

output "device_id" {
  description = "Sentinel device ID registered on the remote host"
  value       = module.sentinel_agent.device_id
}
