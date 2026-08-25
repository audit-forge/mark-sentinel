# Arckon Agent — Terraform user_data module
# Drop this into your VM's user_data to auto-install the agent on first boot.
# Works with AWS, GCP, Azure, and any cloud that supports cloud-init user_data.

variable "arckon_server" {
  description = "Arckon server URL (e.g., https://arckon.riskraven.ai)"
  type        = string
}

variable "arckon_token" {
  description = "Agent token for authentication"
  type        = string
  sensitive   = true
}

variable "arckon_target" {
  description = "Scan target path"
  type        = string
  default     = "/"
}

variable "arckon_profile" {
  description = "Scan profile to use"
  type        = string
  default     = "default"
}

variable "arckon_interval" {
  description = "Scan interval in seconds"
  type        = number
  default     = 900
}

locals {
  install_script = <<-EOF
#!/bin/bash
curl -fsSL ${var.arckon_server}/install/install.sh | bash -s -- --server ${var.arckon_server} --token ${var.arckon_token} --target ${var.arckon_target}
EOF
}

# Example usage with AWS:
# module "arckon_agent" {
#   source = "./deploy/terraform"
#   arckon_server = "https://arckon.riskraven.ai"
#   arckon_token  = var.arckon_token
# }
#
# resource "aws_instance" "web" {
#   ...
#   user_data = module.arckon_agent.user_data
# }

output "user_data" {
  description = "Pass this to your VM resource's user_data argument"
  value       = local.install_script
}