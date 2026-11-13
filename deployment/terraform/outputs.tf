# ==============================================================================
# SecureWatch 100% Docker Stack – Outputs
# ==============================================================================

output "server_public_ip" {
  description = "Static Elastic IP of your SecureWatch Docker host"
  value       = aws_eip.docker_host.public_ip
}

output "frontend_url" {
  description = "SecureWatch React SOC Web Portal"
  value       = "http://${aws_eip.docker_host.public_ip}"
}

output "backend_api_url" {
  description = "FastAPI Backend REST API & Endpoint Telemetry Ingestion"
  value       = "http://${aws_eip.docker_host.public_ip}:8000"
}

output "opensearch_dashboards_url" {
  description = "OpenSearch Dashboards Analytics Portal"
  value       = "http://${aws_eip.docker_host.public_ip}:5601"
}

output "ssh_command" {
  description = "Command to SSH into your Docker Host"
  value       = "ssh -i <YOUR_KEY>.pem ubuntu@${aws_eip.docker_host.public_ip}"
}
