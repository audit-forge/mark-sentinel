output "user_data" {
  description = "Pass this to your VM resource's user_data argument"
  value       = local.install_script
}