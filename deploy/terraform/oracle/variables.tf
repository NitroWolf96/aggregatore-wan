variable "tenancy_ocid" {
  description = "OCID of your Oracle Cloud tenancy."
  type        = string
}

variable "user_ocid" {
  description = "OCID of your Oracle Cloud user."
  type        = string
}

variable "fingerprint" {
  description = "Fingerprint of the API signing key."
  type        = string
}

variable "private_key_path" {
  description = "Path to the API signing private key."
  type        = string
}

variable "region" {
  description = "Home region (choose an EU region near you; it cannot be changed later)."
  type        = string
  default     = "eu-milan-1"
}

variable "compartment_ocid" {
  description = "Compartment OCID (the tenancy OCID works for the root compartment)."
  type        = string
}

variable "availability_domain" {
  description = "AD to try; retry-apply.sh cycles this on 'out of capacity'."
  type        = string
  default     = ""
}

variable "ssh_public_key" {
  description = "SSH public key installed on the instance."
  type        = string
}

variable "client_public_key" {
  description = "WireGuard public key of your treccia-client (generate with: treccia-client genkey | treccia-client pubkey)."
  type        = string
}

variable "dashboard_cidr" {
  description = "CIDR allowed to reach the dashboard port (empty disables the rule)."
  type        = string
  default     = ""
}

variable "ocpus" {
  description = "Ampere A1 OCPUs (Always Free allows 2 since June 2026; PAYG accounts may still get 4)."
  type        = number
  default     = 2
}

variable "memory_gb" {
  description = "RAM in GB (Always Free allows 12 since June 2026)."
  type        = number
  default     = 12
}

variable "tunnel_port" {
  description = "UDP port all client paths connect to."
  type        = number
  default     = 51820
}
