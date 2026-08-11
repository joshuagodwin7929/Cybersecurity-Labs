# Core Infrastructure — AD DS, DNS & DHCP

> Foundational Windows Server infrastructure for the Active Directory homelab, including Active Directory Domain Services, DNS, and DHCP.

**Parent Project:** [Active Directory Homelab](../)

---

## 📋 Overview

This module establishes the core infrastructure required for the Active Directory environment.

The objective was to deploy and validate the services that support:

- Identity management
- Domain communication
- Internal name resolution
- Automated network configuration

### Services Implemented

| Service | Purpose | Status |
|---|---|---|
| **Active Directory Domain Services (AD DS)** | Domain and identity management | 🟢 Complete |
| **DNS** | Internal name resolution and AD-integrated DNS | 🟢 Complete |
| **DHCP** | Automated IP address configuration | 🟢 Complete |

---

## 🧭 Quick Navigation

- [Lab Environment](#-lab-environment)
- [1. Active Directory Domain Services](#1-active-directory-domain-services)
- [2. DNS](#2-dns)
- [3. DHCP](#3-dhcp)
- [Troubleshooting & Lessons Learned](#-troubleshooting--lessons-learned)
- [Validation Summary](#-validation-summary)
- [Skills Demonstrated](#-skills-demonstrated)
- [Key Takeaways](#-key-takeaways)
- [Related Modules](#-related-modules)

---

## 🖥️ Lab Environment

| Component | Configuration |
|---|---|
| **Server** | `Joshua-Server2022` |
| **Operating System** | Windows Server 2022 |
| **Domain** | `joshua.local` |
| **Domain Controller** | `Joshua-Server2022` |
| **Directory Services** | Active Directory Domain Services |
| **DNS** | Windows Server DNS / AD-integrated |
| **DHCP** | Windows Server DHCP |
| **Virtualization** | VMware |

> **Note:** IP addressing details are documented only where they are confirmed by the lab configuration.

---

# 1. Active Directory Domain Services

## 🎯 Objective

Deploy the first Domain Controller and establish the Active Directory forest and domain that will support the remaining modules of the homelab.

---

## ⚙️ Configuration

The following configuration was completed:

- Installed the **Active Directory Domain Services (AD DS)** role.
- Promoted `Joshua-Server2022` to a Domain Controller.
- Created the Active Directory forest.
- Created the `joshua.local` domain.
- Configured the Domain Controller as the primary identity infrastructure for the lab.

### Result

The Windows Server environment was successfully established as the Domain Controller for the `joshua.local` domain.

---

## ✅ Validation

Domain Controller health was validated using Windows diagnostic tools.

### Domain Controller Diagnostics

```powershell
dcdiag
```

### Active Directory Replication

```powershell
repadmin /replsummary
```

These checks were used to verify that the Domain Controller was operating correctly and that Active Directory replication was healthy.

---

# 2. DNS

## 🎯 Objective

Provide reliable internal name resolution for the Active Directory domain.

Active Directory depends heavily on DNS for locating domain services and enabling communication between domain members and Domain Controllers.

---

## ⚙️ Configuration

The following DNS configuration was completed:

- Installed the **DNS Server** role.
- Hosted DNS on the Domain Controller.
- Created the forward lookup zone for `joshua.local`.
- Configured the zone as **Active Directory-integrated**.
- Enabled the DNS zone to participate in Active Directory replication.

### Result

The `joshua.local` DNS namespace was established and integrated with Active Directory.

---

## ✅ Validation

DNS resolution was tested using:

```powershell
nslookup joshua.local
```

and:

```powershell
Resolve-DnsName joshua.local
```

Successful resolution confirmed that the DNS service was able to resolve the internal Active Directory namespace.

---

# 3. DHCP

## 🎯 Objective

Provide automated network configuration to domain clients while maintaining separation between dynamically assigned addresses and statically assigned infrastructure.

---

## ⚙️ Configuration

The following DHCP configuration was completed:

- Installed the **DHCP Server** role.
- Authorized the DHCP server in Active Directory.
- Created a DHCP scope for the lab network.
- Configured the DHCP lease duration.
- Configured the default gateway option.
- Configured the DNS server option.
- Verified DHCP address assignment from a client.

### Result

Domain clients were able to obtain network configuration automatically through DHCP.

---

## ✅ Validation

Client network configuration was validated using:

```powershell
ipconfig /all
```

The client was checked for:

- IP address
- Subnet configuration
- Default gateway
- DNS server
- DHCP server
- DHCP lease information

Successful DHCP assignment confirmed that the service was functioning as expected.

---

# 🛠️ Troubleshooting & Lessons Learned

A major goal of this module was not only to deploy the infrastructure, but also to understand how to troubleshoot problems when the services did not behave as expected.

---

## Issue 1 — DNS Replication Delay

### 🔴 Symptom

After creating the Active Directory-integrated forward lookup zone, DNS resolution from a test client did not work immediately.

### 🔎 Investigation

The DNS configuration was reviewed first to determine whether the issue was caused by an incorrect zone or record configuration.

The configuration appeared correct, so Active Directory replication was investigated as a possible cause.

### 🛠️ Resolution

Active Directory replication was manually triggered using:

```powershell
repadmin /syncall
```

After replication completed, DNS resolution from the test client succeeded.

### Root Cause

The DNS information had not yet replicated to the test client.

### 💡 Lesson Learned

AD-integrated DNS changes are dependent on Active Directory replication and may not appear immediately on every domain member.

When troubleshooting DNS in an Active Directory environment, replication status should be checked before making unnecessary DNS configuration changes.

---

## Issue 2 — DHCP Scope IP Conflict

### 🔴 Symptom

A statically configured device experienced an IP address conflict after another client received the same address through DHCP.

### 🔎 Investigation

The DHCP scope was reviewed and the conflicting address was found to exist within the dynamic allocation range.

The affected device had been configured with a static IP address that overlapped with the DHCP scope.

### Root Cause

The static IP address existed inside the DHCP allocation range.

This allowed the DHCP server to potentially assign the same address to another client.

### 🛠️ Resolution

An exclusion range was configured within DHCP to prevent statically assigned infrastructure addresses from being dynamically allocated.

### 💡 Lesson Learned

Static addresses should be planned before creating the DHCP scope.

A reliable approach is to reserve a dedicated portion of the subnet for infrastructure and either:

- Keep static addresses outside the DHCP scope, or
- Explicitly configure DHCP exclusions.

This prevents address conflicts and makes network administration more predictable.

---

# 🧪 Validation Summary

The completed infrastructure was validated using both service-level and client-side testing.

| Validation | Method | Result |
|---|---|---|
| Domain Controller health | `dcdiag` | 🟢 Passed |
| Active Directory replication | `repadmin` | 🟢 Passed |
| DNS resolution | `nslookup` | 🟢 Passed |
| DNS resolution | `Resolve-DnsName` | 🟢 Passed |
| DHCP authorization | Active Directory / DHCP console | 🟢 Passed |
| DHCP address assignment | `ipconfig /all` | 🟢 Passed |
| Gateway assignment | `ipconfig /all` | 🟢 Passed |
| DNS configuration on client | `ipconfig /all` | 🟢 Passed |
| Domain connectivity | Client validation | 🟢 Passed |

---

# 🧠 Skills Demonstrated

This module demonstrates practical experience with Windows Server infrastructure, Active Directory, networking, and troubleshooting.

## Windows Server

- Windows Server administration
- Server role installation
- Domain Controller deployment
- Windows networking

## Active Directory

- Active Directory Domain Services
- Domain and forest creation
- Domain Controller administration
- Active Directory replication
- AD-integrated DNS

## Networking

- DNS configuration
- DHCP configuration
- IP address management
- Default gateway configuration
- Client network troubleshooting

## Troubleshooting

- Domain Controller health validation
- Active Directory replication troubleshooting
- DNS troubleshooting
- DHCP troubleshooting
- IP address conflict resolution
- Root-cause analysis

## Administrative Tools

```text
dcdiag
repadmin
nslookup
Resolve-DnsName
ipconfig
```

---

# 💡 Key Takeaways

This module established the infrastructure foundation for the rest of the Active Directory homelab.

The most important lessons were:

1. **Active Directory depends heavily on DNS.**
2. **AD-integrated DNS relies on Active Directory replication.**
3. **DHCP scope design must account for statically assigned infrastructure.**
4. **Validation should be performed after every major infrastructure change.**
5. **Troubleshooting should begin with evidence and verification rather than assumptions.**

These principles will be applied throughout the remaining Active Directory modules.

---

# 🔗 Related Modules

| Module | Description |
|---|---|
| [02 — Users & OUs](../02-Users-And-OUs/) | Organizational Units, users, groups, and department structure |
| [03 — Certificate Services](../03-Certificate-Services/) | Active Directory Certificate Services and PKI |
| [04 — Client Domain Join](../04-Client-Domain-Join/) | Joining Windows clients to the Active Directory domain |
| [05 — Group Policies](../05-Group-Policies/) | Security policies, account restrictions, and centralized configuration |
| [06 — File Server & Shares](../06-File-Server-Shares/) | Department shares and NTFS permissions |

---

## 🏠 Parent Project

[← Back to Active Directory Homelab](../)
