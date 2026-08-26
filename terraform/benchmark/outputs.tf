output "instance_id" {
  description = "EC2 instance id of the job-scoped bare-metal confirmation host (SSM target)."
  value       = aws_instance.bench.id
}

output "bucket" {
  description = "Per-job S3 results bucket (staged runner in runner/, results in results/). Destroyed with the stack."
  value       = aws_s3_bucket.results.bucket
}

output "ami_id" {
  description = "AMI actually used. For measured runs this MUST equal the preregistration-bound ami_id."
  value       = aws_instance.bench.ami
}

output "instance_type" {
  description = "Instance type actually provisioned. For measured runs this MUST equal the preregistration-bound type."
  value       = aws_instance.bench.instance_type
}
