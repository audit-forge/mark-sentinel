terraform {
  required_version = ">= 1.3.0"
  required_providers {
    null = {
      source  = "hashicorp/null"
      version = ">= 3.0"
    }
  }
}

resource "null_resource" "arckon_agent" {
  triggers = {
    host             = var.host
    arckon_server  = var.arckon_server
    arckon_token   = var.arckon_token
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
    destination = "/tmp/arckon-install.sh"
  }

  provisioner "file" {
    source      = "${path.module}/../../../"
    destination = "/tmp/arckon-src"
  }

  provisioner "remote-exec" {
    inline = [
      "set -e",
      "chmod +x /tmp/arckon-install.sh",
      "cd /tmp/arckon-src",
      "sudo bash /tmp/arckon-install.sh --server '${var.arckon_server}' --token '${var.arckon_token}'",
      "rm -rf /tmp/arckon-src /tmp/arckon-install.sh",
    ]
  }
}

data "external" "device_id" {
  depends_on = [null_resource.arckon_agent]

  program = ["bash", "-c", <<-EOT
    ssh -i ${var.ssh_key} -o StrictHostKeyChecking=no \
      ${var.ssh_user}@${var.host} \
      "python3 -c \"import hashlib, socket; print('{\\\"device_id\\\": \\\"' + hashlib.sha256(socket.gethostname().encode()).hexdigest()[:16] + '\\\"}')\""
  EOT
  ]
}
