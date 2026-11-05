# Provider constraint for the generated files. Delete this file if your root module already declares required_providers.
# The per-resource region argument needs AWS provider 6.0 or later.
terraform {
  required_version = ">= 1.6"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0, < 7.0"
    }
  }
}
