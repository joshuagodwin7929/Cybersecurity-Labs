# 🏢 Active Directory Homelab

> Enterprise-style Windows identity and infrastructure lab designed to simulate a small organization's Active Directory, identity, access control, and Windows infrastructure.

![Windows Server](https://img.shields.io/badge/Windows%20Server-0078D4?style=flat-square&logo=windows&logoColor=white)
![Active Directory](https://img.shields.io/badge/Active%20Directory-Identity-blue?style=flat-square)
![VMware](https://img.shields.io/badge/VMware-Virtualization-607078?style=flat-square&logo=vmware&logoColor=white)
![Windows 10](https://img.shields.io/badge/Windows%2010-0078D4?style=flat-square&logo=windows&logoColor=white)

---

## 🎯 Project Overview

This project simulates an enterprise Active Directory environment built to develop practical skills in:

- Windows Server administration
- Active Directory Domain Services
- Identity and access management
- DNS and DHCP
- Group Policy
- Certificate Services
- File and folder permissions
- Windows client management
- Enterprise infrastructure design

The goal is to build the environment from the ground up while documenting the configuration, troubleshooting process, security considerations, and lessons learned.

---

## 🏗️ Lab Environment

| Component | Details |
|---|---|
| **Hypervisor** | VMware |
| **Server Operating System** | Windows Server |
| **Client Operating System** | Windows 10 |
| **Active Directory Domain** | `joshua.local` |
| **Users** | 60 |
| **Regions** | 3 |
| **Departments** | 5 |

---

## 🗺️ Lab Architecture

```text
                         ┌─────────────────────┐
                         │    Domain Admin     │
                         └──────────┬──────────┘
                                    │
                                    ▼
                    ┌────────────────────────────┐
                    │     Domain Controller      │
                    │                            │
                    │     AD DS • DNS • DHCP     │
                    └─────────────┬──────────────┘
                                  │
              ┌───────────────────┼───────────────────┐
              │                   │                   │
              ▼                   ▼                   ▼
       ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
       │ Users / OUs │     │    GPOs     │     │     PKI     │
       │             │     │             │     │             │
       │ Departments │     │ Security    │     │ AD CS       │
       │ Groups      │     │ Policies    │     │ Certificates│
       └──────┬──────┘     └──────┬──────┘     └──────┬──────┘
              │                   │                   │
              └───────────────────┼───────────────────┘
                                  │
                                  ▼
                       ┌────────────────────┐
                       │  Windows Clients   │
                       │                    │
                       │    Domain Joined   │
                       └─────────┬──────────┘
                                 │
                                 ▼
                       ┌────────────────────┐
                       │   File Services    │
                       │                    │
                       │ Department Shares  │
                       │ NTFS Permissions   │
                       └────────────────────┘
```

---

## 📚 Project Modules

The lab is divided into six major modules.

| # | Module | Description |
|---|---|---|
| **01** | [Core Infrastructure](./01-Core-Infrastructure/) | Active Directory Domain Services, DNS, and DHCP |
| **02** | [Users & OUs](./02-Users-And-OUs/) | Organizational Units, users, groups, and department structure |
| **03** | [Certificate Services](./03-Certificate-Services/) | Active Directory Certificate Services and PKI |
| **04** | [Client Domain Join](./04-Client-Domain-Join/) | Joining Windows 10 clients to the domain |
| **05** | [Group Policies](./05-Group-Policies/) | Password policies, account lockout, wallpaper, USB restrictions, and mapped drives |
| **06** | [File Server & Shares](./06-File-Server-Shares/) | Department file shares and NTFS permissions |

---

## 🔐 Security Concepts Demonstrated

### Identity & Access

- Identity management
- Authentication
- Authorization
- User management
- Group management
- Organizational Units
- Role-based access

### Windows Security

- Group Policy
- Password policies
- Account lockout
- Security configuration
- Windows administration
- NTFS permissions
- File permissions

### Infrastructure Security

- Active Directory Domain Services
- DNS
- DHCP
- Active Directory Certificate Services
- Public Key Infrastructure
- Domain-joined systems

### Enterprise Administration

- Centralized management
- Department-based organization
- Access control
- Policy enforcement
- Infrastructure documentation

---

## 🛠️ Technologies Used

| Technology | Purpose |
|---|---|
| **Windows Server** | Domain Controller and Windows infrastructure |
| **Windows 10** | Domain-joined client |
| **Active Directory** | Identity and access management |
| **DNS** | Domain name resolution |
| **DHCP** | Automated IP configuration |
| **Group Policy** | Centralized security and configuration management |
| **AD CS** | Certificate services and PKI |
| **VMware** | Virtualization platform |
| **NTFS** | File and folder permissions |

---

## 📸 Screenshots & Evidence

Screenshots and supporting evidence are stored in the [`Images`](./Images/) directory.

### Active Directory

Documented screenshots include:

- Domain Controller configuration
- Active Directory Users and Computers
- Organizational Units
- Users and groups
- DNS configuration
- DHCP configuration

### Group Policy

Documented screenshots include:

- Password policies
- Account lockout policies
- Security restrictions
- USB restrictions
- Wallpaper policies
- Network drive mapping

### File Services

Documented screenshots include:

- Department shares
- NTFS permissions
- Folder structure
- Access control

> **Tip:** Screenshots should be used as evidence of the configuration rather than simply decoration.

---

## 🧠 Skills Developed

This project provided hands-on experience with:

- Windows Server administration
- Active Directory administration
- Identity and access management
- User and group management
- Organizational Unit design
- DNS configuration
- DHCP configuration
- Group Policy administration
- Certificate Services
- PKI concepts
- Windows client administration
- File server administration
- NTFS permissions
- Access control
- Infrastructure troubleshooting
- Technical documentation

---

## 🔎 Security Considerations

Security was considered throughout the design of the environment.

Key areas include:

- Least-privilege access
- Role-based permissions
- Password policies
- Account lockout policies
- Group Policy enforcement
- NTFS permissions
- Department-based access control
- Centralized identity management
- Certificate-based security

---

## 🎓 What I Learned

Building this environment helped me understand how the different components of an enterprise Windows environment work together.

### Active Directory

I learned how to design and manage:

- Domains
- Organizational Units
- Users
- Groups
- Domain Controllers

### Windows Infrastructure

I gained practical experience with:

- DNS
- DHCP
- Windows Server
- Windows 10 clients
- Domain joining

### Security

I developed experience with:

- Group Policy
- Password policies
- Account lockout
- Access control
- NTFS permissions
- Certificate Services

### Troubleshooting

The lab also required troubleshooting issues involving:

- DNS
- Domain connectivity
- Authentication
- Group Policy
- Client configuration
- File permissions

---

## 🗂️ Repository Structure

```text
Active-Directory-Homelab/
│
├── 01-Core-Infrastructure/
│   ├── README.md
│   └── ...
│
├── 02-Users-And-OUs/
│   ├── README.md
│   └── ...
│
├── 03-Certificate-Services/
│   ├── README.md
│   └── ...
│
├── 04-Client-Domain-Join/
│   ├── README.md
│   └── ...
│
├── 05-Group-Policies/
│   ├── README.md
│   └── ...
│
├── 06-File-Server-Shares/
│   ├── README.md
│   └── ...
│
├── Images/
│   └── ...
│
└── README.md
```

---

## 📊 Project Status

| Component | Status |
|---|---|
| Core Infrastructure | 🟢 Completed |
| Users & OUs | 🟢 Completed |
| Certificate Services | 🟢 Completed |
| Client Domain Join | 🟢 Completed |
| Group Policies | 🟢 Completed |
| File Server & Shares | 🟢 Completed |
| Security Monitoring | 🟡 In Progress |
| Detection Engineering | 🔵 Planned |
| Incident Response | 🔵 Planned |

### Legend

- 🟢 **Completed**
- 🟡 **In Progress**
- 🔵 **Planned**

---

## 🗺️ MITRE ATT&CK

As security-focused scenarios are added to the lab, relevant MITRE ATT&CK techniques will be documented here.

| Technique | Description | Evidence |
|---|---|---|
| `T1059.001` | PowerShell | Planned |
| `T1078` | Valid Accounts | Planned |
| `T1110` | Brute Force | Planned |
| `T1098` | Account Manipulation | Planned |

> Techniques will only be listed when they are actually demonstrated or investigated within the lab.

---

## 🚀 Future Improvements

The environment will continue to evolve into a broader security monitoring and detection lab.

### Planned Additions

- [ ] Windows Event Forwarding
- [ ] Sysmon
- [ ] Wazuh
- [ ] SIEM integration
- [ ] Active Directory attack simulations
- [ ] Detection engineering
- [ ] MITRE ATT&CK mapping
- [ ] BloodHound analysis
- [ ] PowerShell automation
- [ ] Incident response exercises
- [ ] Windows security monitoring
- [ ] Threat hunting

---

## 💡 Why I Built This

Most of my early cybersecurity learning happened one concept at a time.

This project brings those concepts together into a single structured environment so I can understand how identity, access control, Windows infrastructure, and security operations work together.

The goal is not simply to follow tutorials, but to build, troubleshoot, document, and secure an environment that resembles the technologies used in real organizations.

---

## 🔗 Related Projects

| Project | Description |
|---|---|
| [📊 SIEM Lab – ELK Stack](../SIEM-Lab-ELK-Stack/) | Centralized security monitoring and log analysis |
| [🛡️ Homelabs](../) | View all cybersecurity homelab projects |

---

## 🛡️ Project Summary

**Identity • Windows • Infrastructure • Security**

This Active Directory homelab demonstrates hands-on experience building and managing a Windows enterprise environment from the ground up.

---

[← Back to Homelabs](../)
