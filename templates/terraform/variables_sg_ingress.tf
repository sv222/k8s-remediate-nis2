variable "allowed_cidr" {
  type        = string
  description = "Trusted source range for the restricted ingress rule: a private IPv4 range (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 or 100.64.0.0/10 or smaller) or a public IPv4 range with prefix length 24 or longer"

  validation {
    condition = can(cidrhost(var.allowed_cidr, 0)) && anytrue([
      can(regex("^10[.][0-9]+[.][0-9]+[.][0-9]+/([89]|[12][0-9]|3[0-2])$", var.allowed_cidr)),
      can(regex("^172[.](1[6-9]|2[0-9]|3[01])[.][0-9]+[.][0-9]+/(1[2-9]|2[0-9]|3[0-2])$", var.allowed_cidr)),
      can(regex("^192[.]168[.][0-9]+[.][0-9]+/(1[6-9]|2[0-9]|3[0-2])$", var.allowed_cidr)),
      can(regex("^100[.](6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])[.][0-9]+[.][0-9]+/(1[0-9]|2[0-9]|3[0-2])$", var.allowed_cidr)),
      can(regex("^[1-9][0-9]*[.][0-9]+[.][0-9]+[.][0-9]+/(2[4-9]|3[0-2])$", var.allowed_cidr)),
    ])
    error_message = "allowed_cidr must be a private IPv4 range, or a public IPv4 range with a prefix length of at least 24. Internet-wide and wide public ranges are not accepted."
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
