variable "allowed_cidr" {
  type        = string
  description = "Trusted source range for the restricted ingress rule (prefix length 8 or longer)"

  validation {
    condition     = can(cidrhost(var.allowed_cidr, 0)) && tonumber(split("/", var.allowed_cidr)[1]) >= 8
    error_message = "allowed_cidr must be a valid CIDR block with a prefix length of at least 8."
  }
}

variable "allowed_port" {
  type        = number
  description = "TCP port the restricted ingress rule opens"

  validation {
    condition     = var.allowed_port >= 1 && var.allowed_port <= 65535
    error_message = "allowed_port must be between 1 and 65535."
  }
}
