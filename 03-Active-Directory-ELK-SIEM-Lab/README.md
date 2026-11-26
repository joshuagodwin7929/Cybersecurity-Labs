# Active Directory ELK SIEM Lab

This is a self-hosted Active Directory attack and defense lab. I built a domain, instrumented it with an Elastic Stack SIEM, and then ran a phased adversary emulation against it (credential access, attack path mapping, lateral movement, domain persistence), hunting for each technique in Kibana as I went.

The order matters: I built the detection layer first and attacked it second, which is the real relationship between blue and red teams. My loop for each phase was log first, attack second, hunt third. Every phase turned up at least one real pipeline or configuration gap I had to diagnose and fix, and that troubleshooting is as much the point of the lab as the attacks.

## Lab environment

| Component | Details |
|---|---|
| Hypervisor | VMware Workstation |
| Domain Controller | Windows Server 2022 (`Joshua-Server2022`) |
| Domain | `joshua.local` |
| Client endpoint | Windows 10 (`MY-LAB-PC`) |
| Attacker | Kali Linux |
| SIEM | Elastic Stack 8.12.0 (Docker Compose, Ubuntu 22.04.5) |
| Network | VMnet2 (NAT, `192.168.18.0/24`), AD DHCP as sole authority |

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

## The phases

Seven phases. Phases 0 to 4 follow the instrument-attack-hunt loop. Phase 5 turns what I found into detections, and Phase 6 writes the whole thing up as an incident report.

| # | Phase | What it covers |
|---|---|---|
| 00 | [Visibility Foundation](./Phase-0-Visibility-Foundation/) | Sysmon, PowerShell logging, Advanced Audit Policy, and a validated Winlogbeat → Elasticsearch pipeline |
| 01 | [Recon & Credential Access](./Phase-1-Credential-Access/) | LLMNR/NBT-NS poisoning, password spraying, Kerberoasting, AS-REP roasting |
| 02 | [Attack Path Mapping](./Phase-2-Attack-Path-Mapping/) | SharpHound and self-hosted BloodHound CE to graph and confirm a real privilege-escalation path |
| 03 | [Lateral Movement & Escalation](./Phase-3-Lateral-Movement/) | A simulated GPO misconfiguration, SMB lateral movement, atexec code execution as SYSTEM |
| 04 | [Persistence: DCSync & Golden Ticket](./Phase-4-DCSync-Golden-Ticket/) | Credential dumping, DCSync, Golden Ticket forging, and the detection gap it exposes |
| 05 | [Detection Engineering](./Phase-5-Detection-Engineering/) | Hunt queries for every technique, then closing the DCSync and Golden Ticket gaps |
| 06 | [Incident Report](./Phase-6-Incident-Report/) | The full chain written up as an incident report with recommendations |

## Techniques and MITRE ATT&CK mapping

| Technique | ATT&CK ID | Phase | Detected in Kibana? |
|---|---|---|---|
| LLMNR/NBT-NS Poisoning | `T1557.001` | 1 | Partial (network-layer gap found) |
| Password Spraying | `T1110.003` | 1 | Yes (4625 / 4740) |
| Kerberoasting | `T1558.003` | 1 | Yes (4769, RC4 ticket type) |
| AS-REP Roasting | `T1558.004` | 1 | Yes (4768, PreAuthType 0) |
| Attack Path Enumeration (BloodHound) | `T1069` / `T1087` | 2 | Not instrumented (finding) |
| Valid Accounts / Local Admin Abuse | `T1078` | 3 | Yes (4624, Elevated Token) |
| Remote Services (SMB/atexec) | `T1021.002` | 3 | Yes (Sysmon EID 1, process lineage) |
| OS Credential Dumping (LSASS) | `T1003.001` | 4 | Not instrumented (finding) |
| DCSync | `T1003.006` | 4 | No events in Phase 4. Fixed in Phase 5B with 4662 auditing plus an alert rule validated by a live alert in November 2026 |
| Golden Ticket | `T1558.001` | 4 | One indistinguishable 4624 in Phase 4. Phase 5B adds a 4769-without-4768 correlation script |

## Tools

| Tool | Purpose |
|---|---|
| Windows Server 2022 | Domain Controller |
| Windows 10 | Domain-joined client |
| Elastic Stack (Elasticsearch, Kibana, Logstash) | SIEM: storage, search, detection |
| Winlogbeat | Log shipping from endpoints to Elasticsearch |
| Sysmon (SwiftOnSecurity config) | Endpoint telemetry: process, network, file events |
| Group Policy | PowerShell logging, Advanced Audit Policy, GPO misconfiguration simulation |
| Kali Linux | Attacker platform |
| Responder | LLMNR/NBT-NS poisoning |
| NetExec | Password spraying, lateral movement |
| Impacket | Kerberoasting, AS-REP roasting, secretsdump (DCSync), ticketer (Golden Ticket) |
| John the Ripper | Offline hash cracking |
| SharpHound / BloodHound CE | Attack path enumeration and graph analysis (Docker, Neo4j, PostgreSQL) |
| Docker / Docker Compose | Hosting the Elastic Stack and BloodHound CE |

Passwords, hashes and IPs are redacted or lab-only values before anything is posted publicly.

## What I took from it

**On detection engineering.** Building the SIEM before attacking it showed me how much of "having a SIEM" really comes down to which audit subcategories are enabled and which fields actually populate, not just having logs flowing.

**On the offensive side.** Running the full credential-access-to-persistence chain by hand taught me how modern Server 2022 hardening (AES-only Kerberos, PAC account validation) changes classic attacks like Kerberoasting and Golden Ticket forging. Two of my first Golden Ticket attempts failed to patched controls working as intended.

**On the detection gap, the biggest lesson.** A well-tuned host-based SIEM can still leave an attack completely invisible, DCSync and Golden Ticket in particular. Closing that gap needs Directory Service Access auditing, network-layer detection (Defender for Identity, Zeek, Suricata), and baseline rules like "4769 with no preceding 4768." I built the first and third of those in Phase 5B.

**On troubleshooting.** Real infrastructure problems surfaced constantly: stale IPs and interface names after a network migration, a commented-out Winlogbeat output block, a legacy audit policy silently overriding the modern one, firewall rules blocking inbound SMB, and BloodHound's own collector missing newly-granted local admin rights because of a SAMR enumeration restriction on the workstation.

## Status

Phases 0 to 6 are complete, and the rules from this lab were later validated with automated Caldera attacks in [Purple-Team-Automation](https://github.com/joshuagodwin7929/Purple-Team-Automation).

Still planned:

- Network-layer detection (Zeek/Suricata or Defender for Identity) for LLMNR poisoning and Golden Ticket traffic.
- Automating the SharpHound → BloodHound collection pipeline end to end.
- Rotating `krbtgt` twice (spaced by max ticket lifetime) and re-verifying the attack path is closed.
- Fixing the Sysmon Event ID 3/22 gap on `MY-LAB-PC` for full LLMNR visibility.
- Capturing the whole lab (VMs, network, Docker configs) as infrastructure-as-code for faster rebuilds.

## Related

| Project | Description |
|---|---|
| [Active Directory Homelab](../01-Active-Directory-Homelab/) | The AD identity and infrastructure environment this lab is built on |
| [Detection-Engineering](https://github.com/joshuagodwin7929/Detection-Engineering) | The Sigma rules these hunt queries became, with CI |
| [Purple-Team-Automation](https://github.com/joshuagodwin7929/Purple-Team-Automation) | Automated Caldera attacks that validated those rules with live alerts |

---

[← Back to AD-Attack-Defense-Lab](../)
