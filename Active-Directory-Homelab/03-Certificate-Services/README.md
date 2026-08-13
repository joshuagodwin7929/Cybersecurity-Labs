# 🔐 Active Directory Certificate Services (AD CS)

> Enterprise-style Public Key Infrastructure (PKI) implementation within an Active Directory environment, demonstrating certificate authority deployment, certificate issuance, trust management, certificate templates, and troubleshooting of certificate enrollment.

**Parent Project:** [← Active Directory Homelab](../)

---

## 📌 Project Overview

This module implements **Active Directory Certificate Services (AD CS)** within the Active Directory homelab.

The objective was to deploy an internal Enterprise Root Certification Authority (CA), configure certificate issuance, establish trust between the CA and domain-joined systems, and issue a certificate to a Windows 10 client.

The project also involved troubleshooting real certificate enrollment issues involving **certificate template permissions, Group Policy autoenrollment, and certificate trust propagation**.

---

# 1. 🏗️ What Did I Build?

I built an internal **Public Key Infrastructure (PKI)** using Active Directory Certificate Services.

The implementation included:

- An **Enterprise Root Certification Authority**
- Certificate authority configuration and cryptographic settings
- A certificate template for certificate enrollment
- Certificate issuance to a domain-joined Windows 10 client
- Certificate trust validation
- Certificate inspection using the Windows Certificates MMC snap-in
- Group Policy-based certificate autoenrollment

### Environment

| Component | Configuration |
|---|---|
| **Certificate Authority** | `JOSHUA-SERVER2022-CA` |
| **CA Server** | `JOSHUA-SERVER2022` |
| **CA Type** | Enterprise Root CA |
| **Client** | Windows 10 |
| **Key Length** | 2048-bit |
| **Hash Algorithm** | SHA-256 |
| **Key Storage Provider** | Microsoft Software Key Storage Provider |
| **Management Tool** | `certlm.msc` |

### Result

The Windows 10 client successfully enrolled for a certificate issued by the internal Enterprise Root CA.

The certificate was verified through the Windows certificate management interface, confirming the certificate chain and cryptographic configuration.

---

# 2. 🎯 Why Did I Build It?

The purpose of this module was to understand how organizations use **internal certificate authorities and PKI** to establish trust and support certificate-based security.

The project was designed to provide practical experience with:

- Certificate authorities
- Digital certificates
- Certificate templates
- Certificate enrollment
- Trust chains
- Certificate-based authentication concepts
- Group Policy certificate autoenrollment
- Certificate troubleshooting

From a security operations perspective, understanding PKI is important when investigating:

- Certificate enrollment failures
- Expired certificates
- Trust chain problems
- TLS-related security events
- Certificate-based authentication issues
- Misconfigured certificate templates
- Unauthorized certificate enrollment

This module therefore extends the Active Directory lab beyond identity management into **enterprise certificate and trust infrastructure**.

---

# 3. 🛠️ What Technologies Did I Use?

| Technology | Purpose |
|---|---|
| **Windows Server** | Hosted the Certificate Authority |
| **Active Directory Certificate Services** | Provided internal PKI and certificate issuance |
| **Enterprise Root CA** | Established the internal certificate trust hierarchy |
| **Active Directory** | Provided the domain environment and integration with AD CS |
| **Windows 10** | Domain-joined certificate enrollment client |
| **Group Policy** | Configured certificate autoenrollment |
| **Certificate Templates** | Defined certificate enrollment and permissions |
| **Certificates MMC (`certlm.msc`)** | Validated certificates installed on the client |
| **RSA** | Certificate public-key cryptography |
| **SHA-256** | Certificate hashing/signature algorithm |
| **Microsoft Software Key Storage Provider** | Provided cryptographic key storage |

---

# 4. ⚙️ How Did I Build It?

The implementation was completed in several stages.

## Step 1 — Install Active Directory Certificate Services

The **AD CS** server role was installed on:

```text
JOSHUA-SERVER2022
```

The server was configured to operate as an:

```text
Enterprise Root Certification Authority
```

---

## Step 2 — Configure the Certification Authority

The CA was configured with:

- CA name
- Certificate validity period
- 2048-bit RSA key
- SHA-256 hashing
- Microsoft Software Key Storage Provider

The resulting CA was:

```text
JOSHUA-SERVER2022-CA
```

---

## Step 3 — Configure a Certificate Template

A certificate template was configured to control certificate enrollment.

The template configuration included appropriate security permissions for the intended enrollment entities.

The relevant permissions included:

- Read
- Enroll
- Autoenroll where applicable

---

## Step 4 — Configure Certificate Enrollment

The Windows 10 client was configured to obtain a certificate from the internal CA.

Certificate enrollment was tested both through the configured certificate infrastructure and through Group Policy-based autoenrollment.

---

## Step 5 — Configure Group Policy Autoenrollment

Certificate autoenrollment was enabled through:

```text
Computer Configuration
└── Policies
    └── Windows Settings
        └── Security Settings
            └── Public Key Policies
                └── Certificate Services Client - Auto-Enrollment
```

The client policy was then refreshed using:

```text
gpupdate /force
```

---

## Step 6 — Validate Certificate Issuance

The client certificate was inspected using:

```text
certlm.msc
```

The certificate was verified for:

- Successful issuance
- Certificate chain
- Issuing CA
- RSA cryptography
- Microsoft Software Key Storage Provider

---

# 5. 🔐 What Security Concepts Did I Demonstrate?

This module demonstrates several important enterprise security concepts.

### Public Key Infrastructure

- Certificate Authorities
- Digital certificates
- Trust relationships
- Certificate chains
- Internal PKI

### Identity & Authentication

- Certificate-based identity
- Certificate enrollment
- Certificate trust
- Domain-integrated certificate services

### Access Control

- Certificate template permissions
- Read permissions
- Enroll permissions
- Autoenrollment permissions

### Policy Enforcement

- Group Policy
- Automated certificate enrollment
- Centralized certificate configuration

### Cryptography

- RSA public-key cryptography
- 2048-bit keys
- SHA-256
- Cryptographic key storage

### Security Operations

The implementation also provides practical context for investigating:

- Certificate enrollment failures
- Broken certificate trust chains
- Certificate template misconfiguration
- Autoenrollment failures
- TLS and certificate-related security events

---

# 6. 🧠 What Did I Learn?

This project demonstrated that certificate services are not an isolated Windows Server feature. They depend on multiple components working together correctly.

## Certificate Template Permissions

The Windows client initially could not enroll for the certificate.

Investigation showed that the relevant security permissions were not configured correctly on the certificate template.

The issue was resolved by adding the appropriate group to the template security configuration and granting:

```text
Read
Enroll
Autoenroll
```

where applicable.

### Lesson

Certificate enrollment depends not only on the existence of a certificate template, but also on correctly configured permissions.

---

## Group Policy Autoenrollment

After correcting the certificate template permissions, automatic enrollment still did not occur.

The issue was traced to Group Policy.

Certificate autoenrollment needed to be explicitly enabled through:

```text
Computer Configuration
→ Policies
→ Windows Settings
→ Security Settings
→ Public Key Policies
→ Certificate Services Client - Auto-Enrollment
```

After enabling the policy and running:

```text
gpupdate /force
```

the client successfully enrolled for the certificate.

### Lesson

Certificate enrollment can depend on several configuration layers. When troubleshooting, it is important to verify both certificate template permissions and Group Policy configuration.

---

## Certificate Trust Chain

A certificate initially displayed a broken trust path warning on the client.

The root CA certificate had not yet propagated to the client's:

```text
Trusted Root Certification Authorities
```

The issue was resolved after refreshing Group Policy and rechecking the certificate trust path.

### Lesson

Certificate trust depends on the client being able to establish a valid chain back to a trusted Certification Authority.

---

# 7. 🚀 What Would I Improve?

The current implementation establishes a functional internal PKI foundation, but there are several areas I would expand in a production-oriented version of the lab.

### Planned Improvements

- Add additional certificate templates for different use cases
- Expand certificate autoenrollment scenarios
- Document certificate template security in greater detail
- Test certificate renewal and expiration
- Test certificate revocation
- Investigate Certificate Revocation Lists (CRLs)
- Explore Online Certificate Status Protocol (OCSP)
- Test certificate-based authentication scenarios
- Monitor certificate-related Windows events
- Integrate certificate events into the security monitoring environment
- Map relevant certificate-related activity to MITRE ATT&CK where appropriate

### Security Improvement

A future iteration could also focus more heavily on **certificate template security**, particularly understanding how excessive enrollment permissions could introduce security risks within an Active Directory environment.

This would allow the lab to progress from simply deploying PKI to actively **assessing and monitoring PKI security**.

---

# 8. 📸 What Evidence Do I Have?

The implementation is supported by screenshots documenting the major configuration and validation stages.

Evidence is organized separately from the documentation:

```text
03-Certificate-Services/
│
├── README.md
│
└── evidence/
    ├── 01-ad-cs-installation.png
    ├── 02-enterprise-root-ca.png
    ├── 03-certificate-template.png
    ├── 04-certificate-template-permissions.png
    ├── 05-autoenrollment-policy.png
    ├── 06-client-certificate.png
    └── 07-certificate-trust-chain.png
```

## AD CS Installation

Evidence showing the installation and configuration of the Active Directory Certificate Services role.

![AD CS Installation](./evidence/01-ad-cs-installation.png)

---

## Enterprise Root CA

Evidence showing the Enterprise Root Certification Authority configuration.

![Enterprise Root CA](./evidence/02-enterprise-root-ca.png)

---

## Certificate Template

Evidence showing the configured certificate template.

![Certificate Template](./evidence/03-certificate-template.png)

---

## Certificate Template Permissions

Evidence showing the permissions used to control certificate enrollment.

![Certificate Template Permissions](./evidence/04-certificate-template-permissions.png)

---

## Autoenrollment Policy

Evidence showing the Group Policy configuration used to enable certificate autoenrollment.

![Certificate Autoenrollment Policy](./evidence/05-autoenrollment-policy.png)

---

## Client Certificate

Evidence showing the certificate successfully issued to the Windows 10 client.

![Client Certificate](./evidence/06-client-certificate.png)

---

## Certificate Trust Chain

Evidence showing the certificate chain and trusted CA relationship.

![Certificate Trust Chain](./evidence/07-certificate-trust-chain.png)

> **Evidence is included to demonstrate the actual implementation and validation of the environment rather than simply documenting theoretical configuration steps.**

---

# ✅ Validation Summary

| Validation | Result |
| --- | --- |
| AD CS role installed | 🟢 Passed |
| Enterprise Root CA configured | 🟢 Passed |
| Certificate template configured | 🟢 Passed |
| Certificate template permissions validated | 🟢 Passed |
| Group Policy autoenrollment configured | 🟢 Passed |
| Windows 10 client enrollment | 🟢 Passed |
| Certificate visible in `certlm.msc` | 🟢 Passed |
| Certificate trust validated | 🟢 Passed |
| RSA / SHA-256 configuration verified | 🟢 Passed |

---

# 🎯 Key Takeaways

This project provided hands-on experience implementing and troubleshooting an internal PKI environment using Active Directory Certificate Services.

The most important lessons were:

1. **Certificate enrollment depends on correctly configured template permissions.**
2. **Group Policy plays an important role in automated certificate enrollment.**
3. **Certificate trust depends on a valid chain to a trusted root CA.**
4. **PKI troubleshooting requires examining multiple infrastructure layers rather than assuming the CA itself is the problem.**
5. **Certificate services integrate closely with Active Directory, Group Policy, and domain clients.**
6. **Understanding PKI is valuable when investigating authentication, TLS, and certificate-related security events.**

---

# 🔗 Related Modules

| Module | Description |
| --- | --- |
| 01 — Core Infrastructure | Active Directory, DNS, and DHCP infrastructure |
| 02 — Users & OUs | Users, groups, and Organizational Unit structure |
| **03 — Certificate Services** | Internal PKI and certificate management |
| 04 — Client Domain Join | Windows client domain integration |
| 05 — Group Policies | Centralized security and configuration policies |
| 06 — File Server & Shares | Department shares and NTFS permissions |

---

## 🛡️ Project Summary

**Active Directory • PKI • Certificate Services • Authentication • Trust • Group Policy**

This module demonstrates the practical implementation of an internal Public Key Infrastructure using Active Directory Certificate Services, including CA deployment, certificate issuance, certificate template management, automated enrollment, trust validation, and troubleshooting.

The project demonstrates not only the ability to configure certificate services, but also the ability to **investigate failures, identify root causes, implement corrective actions, and validate the resulting security infrastructure.**
