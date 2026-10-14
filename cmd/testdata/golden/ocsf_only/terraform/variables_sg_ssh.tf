variable "ssh_allowed_cidr" {
  type        = map(string)
  description = "Trusted source range per security group ID for the restricted SSH (tcp/22) rule. Each value is a private IPv4 range (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 or 100.64.0.0/10 or smaller) or a public IPv4 range with prefix length 24 or longer"

  validation {
    condition = alltrue([
      for c in values(var.ssh_allowed_cidr) : can(cidrhost(c, 0)) && anytrue([
        can(regex("^10[.][0-9]+[.][0-9]+[.][0-9]+/([89]|[12][0-9]|3[0-2])$", c)),
        can(regex("^172[.](1[6-9]|2[0-9]|3[01])[.][0-9]+[.][0-9]+/(1[2-9]|2[0-9]|3[0-2])$", c)),
        can(regex("^192[.]168[.][0-9]+[.][0-9]+/(1[6-9]|2[0-9]|3[0-2])$", c)),
        can(regex("^100[.](6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])[.][0-9]+[.][0-9]+/(1[0-9]|2[0-9]|3[0-2])$", c)),
        can(regex("^[1-9][0-9]*[.][0-9]+[.][0-9]+[.][0-9]+/(2[4-9]|3[0-2])$", c)),
      ])
    ])
    error_message = "Every ssh_allowed_cidr value must be a private IPv4 range, or a public IPv4 range with a prefix length of at least 24. Internet-wide and wide public ranges are not accepted."
  }
}
