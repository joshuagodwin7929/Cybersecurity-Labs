# 🛡️ Active Directory ELK SIEM Lab

> A self-hosted Active Directory attack/defense lab built to simulate a real SOC workflow — instrument a domain with an Elastic Stack SIEM, then run a phased adversary emulation against it (credential access → attack path mapping → lateral movement → domain persistence), hunting for each technique in Kibana as it happens.

![Active Directory](https://img.shields.io/badge/Active%20Directory-Identity-blue?style=flat-square)
![Elastic Stack](https://img.shields.io/badge/Elastic%20Stack-8.12.0-005571?style=flat-square&logo=elasticsearch&logoColor=white)
![Sysmon](https://img.shields.io/badge/Sysmon-SwiftOnSecurity-0078D4?style=flat-square&logo=windows&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=flat-square&logo=docker&logoColor=white)
![Kali Linux](https://img.shields.io/badge/Kali%20Linux-Offensive-557C94?style=flat-square&logo=kalilinux&logoColor=white)

---

## 🎯 Project Overview

This project builds the detection layer first, then attacks it by mirroring the real relationship between red and blue teams. It simulates an enterprise domain, instruments it with a self-hosted SIEM, and then runs a full credential-access-to-domain-compromise chain against it, one technique at a time: **log first, attack second, hunt third.**

Skills developed:

- SIEM engineering (Elastic Stack: Elasticsearch, Kibana, Logstash, Winlogbeat)
- Windows/AD telemetry (Sysmon, PowerShell logging, Advanced Audit Policy)
- Adversary emulation (credential access, attack path mapping, lateral movement, persistence)
- Detection engineering and Kibana hunt-query writing
- Root-cause troubleshooting of real pipeline and configuration gaps

Every phase found at least one real pipeline or configuration gap that had to be diagnosed and fixed — that troubleshooting is as much the point of this lab as the attacks themselves.

---

## 🏗️ Lab Environment

| Component | Details |
|---|---|
| **Hypervisor** | VMware Workstation |
| **Domain Controller** | Windows Server 2022 (`Joshua-Server2022`) |
| **Domain** | `joshua.local` |
| **Client Endpoint** | Windows 10 (`MY-LAB-PC`) |
| **Attacker Host** | Kali Linux |
| **SIEM** | Elastic Stack 8.12.0 (Docker Compose, Ubuntu 22.04.5) |
| **Network** | VMnet2 (NAT, `192.168.18.0/24`) — AD DHCP as sole authority |

---

## 🗺️ Lab Architecture

```text
                    ┌────────────────────────────┐
                    │     Domain Controller      │
                    │   Joshua-Server2022         │
                    │   AD DS • Sysmon • Audit    │
                    └─────────────┬──────────────┘
                                  │ Winlogbeat (HTTPS)
              ┌───────────────────┼───────────────────┐
              │                   │                   │
              ▼                   ▼                   ▼
       ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
       │  MY-LAB-PC   │     │  Elastic    │     │ Kali Linux  │
       │  Windows 10  │────▶│  Stack      │◀────│  Attacker   │
       │  Sysmon      │     │  ES/Kibana/ │     │  Responder  │
       │  Winlogbeat  │     │  Logstash   │     │  Impacket   │
       └─────────────┘     └─────────────┘     │  BloodHound │
                                                 └─────────────┘
```

---

## 📚 Project Phases

The lab is divided into five phases, each following the same loop: instrument, attack, hunt.

| # | Phase | Description |
|---|---|---|
| **00** | [Visibility Foundation](./Phase-0-Visibility-Foundation/) | Sysmon, PowerShell logging, Advanced Audit Policy, and a validated Winlogbeat → Elasticsearch pipeline |
| **01** | [Recon & Credential Access](./Phase-1-Credential-Access/) | LLMNR/NBT-NS poisoning, password spraying, Kerberoasting, AS-REP roasting |
| **02** | [Attack Path Mapping](./Phase-2-Attack-Path-Mapping/) | SharpHound + self-hosted BloodHound CE to graph and confirm a real privilege-escalation path |
| **03** | [Lateral Movement & Escalation](./Phase-3-Lateral-Movement/) | Simulated GPO misconfiguration, SMB lateral movement, atexec code execution as SYSTEM |
| **04** | [Persistence: DCSync & Golden Ticket](./Phase-4-DCSync-Golden-Ticket/) | Credential dumping, DCSync, Golden Ticket forging, and the detection gap it exposes |

---

## 🔐 Techniques & MITRE ATT&CK Mapping

| Technique | ATT&CK ID | Phase | Detected in Kibana? |
|---|---|---|---|
| LLMNR/NBT-NS Poisoning | `T1557.001` | 1 | ⚠️ Partial (network-layer gap found) |
| Password Spraying | `T1110.003` | 1 | ✅ 4625 / 4740 |
| Kerberoasting | `T1558.003` | 1 | ✅ 4769 (RC4 ticket type) |
| AS-REP Roasting | `T1558.004` | 1 | ✅ 4768 (PreAuthType 0) |
| Attack Path Enumeration (BloodHound) | `T1069` / `T1087` | 2 | 🔵 Not instrumented (finding) |
| Valid Accounts / Local Admin Abuse | `T1078` | 3 | ✅ 4624 (Elevated Token) |
| Remote Services (SMB/atexec) | `T1021.002` | 3 | ✅ Sysmon EID 1 (process lineage) |
| OS Credential Dumping (LSASS) | `T1003.001` | 4 | 🔵 Not instrumented (finding) |
| DCSync | `T1003.006` | 4 | ❌ Zero events — audit gap found |
| Golden Ticket | `T1558.001` | 4 | ⚠️ One indistinguishable 4624 artifact |

> ✅ = confirmed in Kibana · ⚠️ = partially visible / gap documented · ❌ = fully invisible, documented as a finding · 🔵 = not instrumented this phase

---

## 🛠️ Technologies Used

| Technology | Purpose |
|---|---|
| **Windows Server 2022** | Domain Controller |
| **Windows 10** | Domain-joined client endpoint |
| **Elastic Stack (Elasticsearch, Kibana, Logstash)** | SIEM — log storage, search, and detection |
| **Winlogbeat / Filebeat** | Log shipping from endpoints to Elasticsearch |
| **Sysmon (SwiftOnSecurity config)** | Endpoint telemetry — process, network, and file events |
| **Group Policy** | PowerShell logging, Advanced Audit Policy, GPO-based misconfiguration simulation |
| **Kali Linux** | Attacker platform |
| **Responder** | LLMNR/NBT-NS poisoning |
| **NetExec** | Password spraying, lateral movement |
| **Impacket suite** | Kerberoasting, AS-REP roasting, secretsdump (DCSync), ticketer (Golden Ticket) |
| **John the Ripper** | Offline hash cracking |
| **SharpHound / BloodHound CE** | AD attack path enumeration and graph analysis (Docker, Neo4j, PostgreSQL) |
| **Docker / Docker Compose** | Hosting the Elastic Stack and BloodHound CE |

---

## 📸 Screenshots & Evidence

Screenshots and supporting evidence are stored per-phase in each phase's `/screenshots` directory.

Documented evidence includes:

- Kibana hunt queries and matching event fields for each detected technique
- Sysmon and Winlogbeat pipeline validation (data views, live hit counts)
- BloodHound attack path graphs (Cypher `shortestPath` results)
- Group Policy and Advanced Audit Policy configuration
- Impacket/NetExec/Responder attack output and resulting cracked/uncracked hash comparisons

> **Note:** passwords, hashes, and IPs are redacted or lab-only values before anything is posted publicly.

---

## 🧠 Skills Developed

- Elastic Stack deployment, TLS configuration, and Winlogbeat pipeline troubleshooting
- Sysmon and Windows Advanced Audit Policy configuration and validation
- Writing and validating Kibana/KQL hunt queries against real attack telemetry
- Credential access techniques: LLMNR poisoning, password spraying, Kerberoasting, AS-REP roasting
- AD attack path analysis with SharpHound/BloodHound, including Cypher querying
- Lateral movement and SYSTEM-level code execution via SMB/atexec
- Domain persistence via DCSync and Golden Ticket forging
- Root-cause troubleshooting across Windows GPO, firewall, networking, and log-shipping layers
- Translating offensive results into defensive findings and remediation recommendations

---

## 🔎 Security Considerations

Every phase paired an attack with an attempt to detect it — and, where detection failed, a documented reason why:

- Sysmon Event ID 3/22 gaps left LLMNR poisoning partially invisible at the network layer
- A misconfigured legacy Audit Policy silently overrode Advanced Audit Policy, breaking account-lockout logging
- AES-only Kerberos enforcement and CVE-2021-42287 PAC validation both blocked naive Golden Ticket attempts, but a correctly-forged AES256 ticket with a real account name still succeeded
- DCSync produced zero host-based events because Directory Service Access (4662) auditing was never enabled
- BloodHound's own collector missed newly-granted local admin rights due to MY-LAB-PC's default SAMR enumeration restriction — a blind spot in the tooling itself, not the attack

---

## 🎓 What I Learned

### Detection Engineering
Building the SIEM before attacking it showed how much of "having a SIEM" is really about which audit subcategories are enabled and which fields actually populate — not just having logs flowing.

### Offensive Techniques
Hands-on execution of the full AD credential-access-to-persistence chain, including how modern Server 2022 hardening (AES-only Kerberos, PAC account validation) changes classic attacks like Kerberoasting and Golden Ticket forging.

### The Detection Gap
The single biggest lesson of the project: a well-tuned host-based SIEM can still leave an attack — DCSync and Golden Ticket in particular — completely invisible. Closing that gap requires Directory Service Access auditing, network-layer detection (Defender for Identity, Zeek, Suricata), and baseline rules like "4769 with no preceding 4768."

### Troubleshooting
Real infrastructure issues surfaced constantly: stale IPs and interface names after a network migration, a commented-out Winlogbeat output block, a legacy audit policy silently overriding the modern one, and firewall rules blocking inbound SMB.

---

## 🗂️ Repository Structure

```text
Active-Directory-ELK-SOC-Lab/
│
├── Phase-0-Visibility-Foundation/
│   ├── README.md
│   └── screenshots/
│
├── Phase-1-Credential-Access/
│   ├── README.md
│   ├── llmnr-poisoning-writeup.md
│   ├── kerberoasting-linkedin-post.md
│   ├── asrep-roasting-linkedin-post.md
│   └── screenshots/
│
├── Phase-2-Attack-Path-Mapping/
│   ├── README.md
│   ├── writeups/
│   │   └── attack-path-explanation.md
│   └── screenshots/
│
├── Phase-3-Lateral-Movement/
│   ├── README.md
│   └── screenshots/
│
├── Phase-4-DCSync-Golden-Ticket/
│   ├── README.md
│   └── screenshots/
│
├── Phase-5-Detection-Engineering/
│   └── README.md
│   
├── Phase-6-Incident-Report/
│   └── README.md
│
└── README.md
```

---

## 📊 Project Status

| Phase | Status |
|---|---|
| Phase 0 — Visibility Foundation | 🟢 Completed |
| Phase 1 — Credential Access | 🟢 Completed |
| Phase 2 — Attack Path Mapping | 🟢 Completed |
| Phase 3 — Lateral Movement & Escalation | 🟢 Completed |
| Phase 4 — DCSync & Golden Ticket | 🟢 Completed |
| Network-Layer Detection (Zeek/Suricata) | 🔵 Planned |
| Automated Pipeline (SharpHound → BloodHound) | 🔵 Planned |
| krbtgt Rotation & Remediation Pass | 🔵 Planned |

### Legend

- 🟢 **Completed**
- 🟡 **In Progress**
- 🔵 **Planned**

---

## 🚀 Future Improvements

- [ ] Enable Directory Service Access (4662) auditing with replication GUID filters to close the DCSync blind spot
- [ ] Add network-layer detection (Zeek/Suricata or Defender for Identity) for LLMNR poisoning and Golden Ticket traffic
- [ ] Build a Kibana detection rule for "4769 with no preceding 4768" (forged ticket indicator)
- [ ] Automate the SharpHound → BloodHound collection pipeline end-to-end
- [ ] Rotate krbtgt twice (spaced by max ticket lifetime) and re-verify the attack path is closed
- [ ] Fix the Sysmon Event ID 3/22 gap on MY-LAB-PC for full LLMNR visibility
- [ ] Capture the full lab (VMs, network, Docker configs) as infrastructure-as-code for faster rebuilds

---

## 💡 Why I Built This

Most of my earlier lab work treated defense and offense as separate skills. This project deliberately fuses them: build the detection layer first, then attack it, so every finding is grounded in what a real SOC analyst would actually see — or not see — in Kibana.

The goal wasn't to run tools and get a hash; it was to trace each attack all the way through the logging pipeline and be honest about where visibility broke down.

---

## 🔗 Related Projects

| Project | Description |
|---|---|
| [🏢 Active Directory Homelab](../Active-Directory-Homelab/) | The enterprise-style AD identity and infrastructure environment this lab is built on top of |
| [🛡️ Cybersecurity-Labs](../) | View all cybersecurity homelab projects |

---

## 🛡️ Project Summary

**SIEM • Active Directory • Detection Engineering • Adversary Emulation**

This lab demonstrates end-to-end hands-on experience building a SIEM from scratch and using it to detect — and honestly assess the limits of detecting — a full AD attack chain from initial credential access through domain persistence.

---

[← Back to Cybersecurity-Labs](../)
