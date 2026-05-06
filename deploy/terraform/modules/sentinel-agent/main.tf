terraform {
  required_version = ">= 1.3.0"
  required_providers {
    null = {
      source  = "hashicorp/null"
      version = ">= 3.0"
    }
  }
}

resource "null_resource" "sentinel_agent" {
  triggers = {
    host             = var.host
    sentinel_server  = var.sentinel_server
    sentinel_token   = var.sentinel_token
  }

  connection {
    type        = "ssh"
    host        = var.host
    user        = var.ssh_user
    private_key = file(var.ssh_key)
    port        = var.ssh_port
    timeout     = "5m"
  }

  provisioner "file" {
    source      = "${path.module}/../../../install.sh"
    destination = "/tmp/sentinel-install.sh"
  }

  provisioner "file" {
    source      = "${path.module}/../../../"
    destination = "/tmp/sentinel-src"
  }

  provisioner "remote-exec" {
    inline = [
      "set -e",
      "chmod +x /tmp/sentinel-install.sh",
      "cd /tmp/sentinel-src",
      "sudo bash /tmp/sentinel-install.sh --server '${var.sentinel_server}' --token '${var.sentinel_token}'",
      "rm -rf /tmp/sentinel-src /tmp/sentinel-install.sh",
    ]
  }
}

data "external" "device_id" {
  depends_on = [null_resource.sentinel_agent]

  program = ["bash", "-c", <<-EOT
    ssh -i ${var.ssh_key} -o StrictHostKeyChecking=no \
      ${var.ssh_user}@${var.host} \
      "python3 -c \"import hashlib, socket; print('{\\\"device_id\\\": \\\"' + hashlib.sha256(socket.gethostname().encode()).hexdigest()[:16] + '\\\"}')\""
  EOT
  ]
}
