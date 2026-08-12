terraform {
  required_providers {
    oci = {
      source  = "oracle/oci"
      version = ">= 5.0"
    }
    random = {
      source = "hashicorp/random"
    }
  }
}

provider "oci" {
  tenancy_ocid     = var.tenancy_ocid
  user_ocid        = var.user_ocid
  fingerprint      = var.fingerprint
  private_key_path = var.private_key_path
  region           = var.region
}

data "oci_identity_availability_domains" "ads" {
  compartment_id = var.compartment_ocid
}

locals {
  ad = var.availability_domain != "" ? var.availability_domain : data.oci_identity_availability_domains.ads.availability_domains[0].name
}

# Shared control-plane secret, generated once and kept in the state.
resource "random_password" "control_psk" {
  length  = 48
  special = false
}

resource "oci_core_vcn" "treccia" {
  compartment_id = var.compartment_ocid
  display_name   = "treccia"
  cidr_blocks    = ["10.100.0.0/24"]
}

resource "oci_core_internet_gateway" "treccia" {
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.treccia.id
  display_name   = "treccia-igw"
}

resource "oci_core_route_table" "treccia" {
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.treccia.id
  display_name   = "treccia-rt"
  route_rules {
    destination       = "0.0.0.0/0"
    network_entity_id = oci_core_internet_gateway.treccia.id
  }
}

resource "oci_core_subnet" "treccia" {
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.treccia.id
  cidr_block     = "10.100.0.0/28"
  display_name   = "treccia-subnet"
  route_table_id = oci_core_route_table.treccia.id
}

resource "oci_core_network_security_group" "treccia" {
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.treccia.id
  display_name   = "treccia-nsg"
}

resource "oci_core_network_security_group_security_rule" "tunnel_udp" {
  network_security_group_id = oci_core_network_security_group.treccia.id
  direction                 = "INGRESS"
  protocol                  = "17" # UDP
  source                    = "0.0.0.0/0"
  udp_options {
    destination_port_range {
      min = var.tunnel_port
      max = var.tunnel_port
    }
  }
}

resource "oci_core_network_security_group_security_rule" "ssh" {
  network_security_group_id = oci_core_network_security_group.treccia.id
  direction                 = "INGRESS"
  protocol                  = "6" # TCP
  source                    = "0.0.0.0/0"
  tcp_options {
    destination_port_range {
      min = 22
      max = 22
    }
  }
}

resource "oci_core_network_security_group_security_rule" "dashboard" {
  count                     = var.dashboard_cidr != "" ? 1 : 0
  network_security_group_id = oci_core_network_security_group.treccia.id
  direction                 = "INGRESS"
  protocol                  = "6"
  source                    = var.dashboard_cidr
  tcp_options {
    destination_port_range {
      min = 8080
      max = 8080
    }
  }
}

# Latest Ubuntu 24.04 ARM image.
data "oci_core_images" "ubuntu_arm" {
  compartment_id           = var.compartment_ocid
  operating_system         = "Canonical Ubuntu"
  operating_system_version = "24.04"
  shape                    = "VM.Standard.A1.Flex"
  sort_by                  = "TIMECREATED"
  sort_order               = "DESC"
}

resource "oci_core_instance" "treccia" {
  compartment_id      = var.compartment_ocid
  availability_domain = local.ad
  display_name        = "treccia-server"
  shape               = "VM.Standard.A1.Flex"

  shape_config {
    ocpus         = var.ocpus
    memory_in_gbs = var.memory_gb
  }

  source_details {
    source_type = "image"
    source_id   = data.oci_core_images.ubuntu_arm.images[0].id
  }

  create_vnic_details {
    subnet_id        = oci_core_subnet.treccia.id
    assign_public_ip = true
    nsg_ids          = [oci_core_network_security_group.treccia.id]
  }

  metadata = {
    ssh_authorized_keys = var.ssh_public_key
    user_data = base64encode(templatefile("${path.module}/cloud-init.yaml", {
      control_psk       = random_password.control_psk.result
      client_public_key = var.client_public_key
      tunnel_port       = var.tunnel_port
    }))
  }

  lifecycle {
    # Image updates must not replace a working endpoint.
    ignore_changes = [source_details]
  }
}

output "server_ip" {
  value       = oci_core_instance.treccia.public_ip
  description = "Public IP for the client's server_addr (append :${var.tunnel_port})."
}

output "control_psk" {
  value       = random_password.control_psk.result
  sensitive   = true
  description = "control_psk for both configs (terraform output -raw control_psk)."
}

output "server_public_key_cmd" {
  value       = "ssh ubuntu@${oci_core_instance.treccia.public_ip} cat /etc/treccia/server.pub"
  description = "Run this to read the server's WireGuard public key for the client config."
}
