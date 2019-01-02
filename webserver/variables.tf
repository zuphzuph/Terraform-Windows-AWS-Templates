variable "admin_password" {
  description = "Windows Administrator password to login as for povisioning"
  default = "password"
}

variable "key_name" {
  description = "Name of the SSH keypair to use in AWS."
  default = "key-name-here"
}

variable "aws_region" {
  description = "AWS region to launch servers."
  default     = "us-XXXX-#a"
}

variable "aws_availzone" {
  description = "AWS availibility zone to launch in."
  default     = "us-XXXX-#a"
}
