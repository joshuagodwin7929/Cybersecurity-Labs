# Active Directory Homelab

Part of the [AD-Attack-Defense-Lab](../) repo.

This is the Windows identity and infrastructure lab the rest of the repo runs on. I built a small organization's Active Directory from the ground up, Domain Controller through to department file shares, and documented the configuration, the problems I hit, and how I fixed them. It's the environment the [ELK SIEM lab](../03-Active-Directory-ELK-SIEM-Lab/) later instruments and attacks.

## Lab environment

| Component | Details |
|---|---|
| Hypervisor | VMware |
| Server OS | Windows Server 2022 |
| Client OS | Windows 10 |
| Domain | `joshua.local` |
| Users | 60, across 3 regions and 5 departments |

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

## The modules

Six modules, each with its own write-up, the configuration, the screenshots, and whatever I had to troubleshoot.

| # | Module | What it covers |
|---|---|---|
| 01 | [Core Infrastructure](./01-Core-Infrastructure/) | AD Domain Services, DNS, and DHCP |
| 02 | [Users & OUs](./02-Users-And-OUs/) | OUs, 60 users, groups, department structure |
| 03 | [Certificate Services](./03-Certificate-Services/) | AD Certificate Services and an internal PKI |
| 04 | [Client Domain Join](./04-Client-Domain-Join/) | Joining a Windows 10 client to the domain |
| 05 | [Group Policies](./05-Group-Policies/) | Password policy, account lockout, wallpaper, USB block, mapped drives |
| 06 | [File Server & Shares](./06-File-Server-Shares/) | Department shares and NTFS permissions |

## What I took from it

The point wasn't to follow tutorials but to build, break and fix something that resembles a real organization's Windows environment. The through-line across the modules is how tightly the pieces depend on each other: AD leans on DNS, DNS leans on replication, domain join leans on DNS again, certificate enrollment leans on both template permissions and Group Policy, and file access leans on getting NTFS and share permissions to agree. Most of the real learning came from the failures, the domain join that couldn't find a DC, the GPOs that fought over a drive letter, the certificate that wouldn't enroll, rather than the parts that worked first time.

Throughout I kept security in mind: least privilege on shares and templates, password and lockout policy, department-scoped access, and centralized management through Group Policy.

## Status and what's next

All six modules are complete. The security monitoring, detection and attack-simulation work that builds on this domain lives in the [ELK SIEM lab](../03-Active-Directory-ELK-SIEM-Lab/), where I add Sysmon, Winlogbeat and Elastic, then run an attack chain against this environment and hunt for it.

## Related

| Project | Description |
|---|---|
| [SIEM Lab, ELK Stack](../02-SIEM-Lab-ELK-Stack/) | Centralized security monitoring and log analysis |
| [Active Directory ELK SIEM Lab](../03-Active-Directory-ELK-SIEM-Lab/) | This domain, instrumented and attacked end to end |

---

[← Back to AD-Attack-Defense-Lab](../)
