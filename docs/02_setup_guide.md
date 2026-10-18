# Phase 1: Environment Setup Guide

## 1. Overview
This guide details the steps required to provision an isolated Linux Virtual Machine (VM) and install Docker to host the Cowrie SSH Honeypot. 

We are using a **defense-in-depth architecture**: 
1. **The VM (VirtualBox + Ubuntu):** Isolates the honeypot from the Windows host OS.
2. **The Container (Docker):** Isolates the honeypot application from the Ubuntu OS.

This ensures that if the honeypot is compromised, the attacker is trapped inside a container, which is trapped inside a virtual machine.

## 2. Prerequisites
Before beginning, ensure you have the following:
- **Hardware:** A host machine (Windows) with at least 8GB RAM and 20GB free disk space.
- **Virtualization Enabled:** Ensure VT-x/AMD-V is enabled in your BIOS/UEFI settings.
- **Software:** 
  - [Oracle VirtualBox](https://www.virtualbox.org/) (Latest version)
  - [Ubuntu Server 22.04 LTS ISO](https://ubuntu.com/download/server) (Do not use the Desktop version).
- **Terminal:** Git Bash or Windows Terminal (for SSH access).

## 3. VM Configuration Specifications
Configure the VM with the following specs to ensure smooth operation without draining host resources:
- **Name:** `Honeypot-VM`
- **Memory (RAM):** 2048 MB (2GB)
- **Processors:** 1 CPU
- **Storage:** 20 GB (VDI, Dynamically allocated)
- **Network Adapter 1:** NAT (Allows internet access for Docker pulls).
- **Network Adapter 2:** Host-Only Adapter (Allows your Windows host to SSH into the VM securely).

## 4. OS Installation Steps (High-Level)
1. Boot the VM with the Ubuntu Server ISO.
2. Follow the installation wizard.
3. **User Setup:** Create a user named `honeypot` (Do not use `admin` or `root`).
4. **SSH Setup:** Check the box to "Install OpenSSH server".
5. Reboot and log into your new Ubuntu VM via your terminal (`ssh honeypot@<VM_IP>`).

## 5. Docker Installation (Inside the Ubuntu VM)
Once logged into the Ubuntu VM, run the following commands to install Docker:

```bash
# Update package lists
sudo apt update && sudo apt upgrade -y

# Install prerequisite packages
sudo apt install -y curl git ufw

# Install Docker using the official convenience script
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Add your user to the docker group (so you don't need 'sudo' for docker commands)
sudo usermod -aG docker $USER

# Apply group changes (log out and back in, or run this)
newgrp docker