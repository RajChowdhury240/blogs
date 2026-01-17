---
layout: post
title: "NetExec: Network Service Exploitation Tool Guide"
date: 2026-01-18 12:00:00 +0000
categories: [netexec, offensive-security, red-team, active-directory]
description: "A comprehensive guide to NetExec (nxc) for network security assessment and Active Directory attacks"
---

# NetExec Documentation Summary

## Overview

NetExec (nxc) is a network service exploitation tool designed for assessing security across large networks. It supports multiple protocols including SMB, SSH, LDAP, FTP, WMI, WinRM, RDP, VNC, and MSSQL.

## Key Capabilities

### Installation

Available via pipx or static binaries from GitHub releases.

### Core Functions

- Network reconnaissance and enumeration
- Credential dumping (SAM, LSA, NTDS, LSASS)
- Active Directory attacks (Kerberoasting, ASREProasting, delegation abuse)
- LAPS password retrieval
- File transfer operations
- Remote code execution

### Notable Features

- BloodHound ingestor support for attack path analysis
- DACL reading and permission analysis
- gMSA credential extraction
- Microsoft Teams cookie theft capability
- Vulnerability scanning (ZeroLogon, PetitPotam, noPAC)

## Common Attack Scenarios

The documentation covers domain controller compromise, privilege escalation through group membership abuse, and lateral movement techniques. It includes both automated module-based approaches and manual alternatives for credential access.

### Target Audience

Security professionals conducting internal penetration testing and red team operations on Windows/Active Directory environments.

## Getting Started

### Installation via pipx

```bash
pipx install netexec
```

### Basic Usage

```bash
# SMB enumeration
nxc smb <target> -u <username> -p <password>

# LDAP enumeration
nxc ldap <target> -u <username> -p <password>

# Credential dumping
nxc smb <target> -u <username> -p <password> --sam
nxc smb <target> -u <username> -p <password> --lsa
```

## Advanced Techniques

### Kerberoasting

Extract service account credentials by requesting TGS tickets:

```bash
nxc ldap <target> -u <username> -p <password> --kerberoasting
```

### ASREProasting

Target accounts without Kerberos pre-authentication:

```bash
nxc ldap <target> -u <username> -p <password> --asreproast
```

### BloodHound Integration

Collect data for BloodHound analysis:

```bash
nxc ldap <target> -u <username> -p <password> --bloodhound
```

## Security Considerations

This tool is designed for authorized security assessments only. Always ensure you have proper authorization before testing any network or system.

---

*NetExec is a powerful tool for security professionals. Use responsibly and ethically.*
