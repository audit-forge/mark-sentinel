output "device_id" {
  description = "16-character hex device ID derived from the remote host's hostname (SHA-256 truncated)."
  value       = data.external.device_id.result["device_id"]
}
