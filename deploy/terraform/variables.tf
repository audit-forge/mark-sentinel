variable "arckon_server" {
  description = "Arckon server URL"
  type        = string
}

variable "arckon_token" {
  description = "Agent token"
  type        = string
  sensitive   = true
}

variable "arckon_target" {
  description = "Scan target path"
  type        = string
  default     = "/"
}