provider "aws" {
  region  = var.aws_region
  profile = var.aws_profile

  default_tags {
    tags = {
      Project   = var.name_prefix
      ManagedBy = "deploy/terraform/stacks/demo-aws"
    }
  }
}

# Lambda@Edge functions and CloudFront's ACM certificate are only accepted
# from us-east-1, regardless of where the VM runs. The aws-cloudfront-edge
# module is instantiated with this aliased provider so the stack stays correct
# even when aws_region is changed for the VM.
provider "aws" {
  alias   = "us_east_1"
  region  = "us-east-1"
  profile = var.aws_profile

  default_tags {
    tags = {
      Project   = var.name_prefix
      ManagedBy = "deploy/terraform/stacks/demo-aws"
    }
  }
}
