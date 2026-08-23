terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

resource "aws_instance" "backupdballdatabase" {
  # Production backup EC2 instance
  ami           = "ami-0c02fb55956c7d316"
  instance_type = "t3.micro"

  lifecycle {
    # Prevent Terraform from accidentally destroying this critical resource
    prevent_destroy = true
  }

  tags = {
    # Identify the instance as a production backup resource
    Name = "backupdballdatabase"
  }
}
