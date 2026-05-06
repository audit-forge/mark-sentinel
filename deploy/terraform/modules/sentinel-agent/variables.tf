variable "host" {
  description = "IP address or hostname of the target machine to install the Sentinel Agent on."
  type        = string
}

variable "ssh_user" {
  description = "SSH username used to connect to the target machine."
  type        = string
  default     = "ubuntu"
}

variable "ssh_key" {
  description = "Path to the SSH private key file used to authenticate to the target machine."
  type        = string
}

variable "ssh_port" {
  description = "SSH port on the target machine."
  type        = number
  default     = 22
}

variable "sentinel_server" {
  description = "URL of the Sentinel server that the agent will report results to (e.g. http://10.0.1.50:7331)."
  type        = string
}

variable "sentinel_token" {
  description = "Authentication token the agent uses when communicating with the Sentinel server."
  type        = string
  sensitive   = true
}
