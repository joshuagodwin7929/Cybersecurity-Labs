# Phase 0 — Visibility Foundation: Building the Eyes Before the Fists

Part of a multi-phase Active Directory attack/defense home lab. This phase focused entirely on building detection visibility across a small AD environment (Domain Controller + Windows 10 endpoint) **before** any attack simulation began — feeding Sysmon, PowerShell, and Windows Security telemetry into the self-hosted Elastic Stack SIEM built in [SIEM-Lab-ELK-Stack](../SIEM-Lab-ELK-Stack).

> You can't detect what you can't see. Before running a single attack technique, this phase proves the domain can answer a basic question: *who logged into what, and when?*

---

## 📋 Table of Contents

- [What Did I Build?](#-what-did-i-build)
- [Why Did I Build It?](#-why-did-i-build-it)
- [What Technologies?](#-what-technologies)
- [Architecture](#-architecture)
- [How Did I Build It?](#-how-did-i-build-it)
- [What Security Concepts?](#-what-security-concepts)
- [What Did I Learn?](#-what-did-i-learn)
- [What Would I Improve?](#-what-would-i-improve)
- [What Evidence Do I Have?](#-what-evidence-do-i-have)
- [Screenshots](#-screenshots)
- [Roadmap](#-roadmap)

---

## 🏗 What Did I Build?

A domain-wide logging and telemetry pipeline across an Active Directory environment, shipping real-time endpoint and security event data into a self-hosted SIEM:

- **Sysmon** deployed on both the Domain Controller and a Windows 10 endpoint, capturing process creation, DNS queries, file activity, and more
- **PowerShell Script Block and Module Logging** enabled domain-wide via Group Policy
- **Advanced Audit Policy** configured across four categories: Logon/Logoff, Kerberos authentication, Account Management, and Object Access
- A **SACL (System Access Control List)** on a sensitive file share to audit file creation/deletion, paired with a **canary token** file as an independent tripwire
- **Winlogbeat** shipping all of the above from both hosts into Elasticsearch, over TLS
- A validated, searchable **Kibana** view proving the whole pipeline works end to end

## 🎯 Why Did I Build It?

Every later phase of this lab — credential attacks, lateral movement, persistence — depends on being able to see what happened afterward. Skipping straight to offense without instrumenting the environment first would mean generating attacks with no way to evaluate whether they were actually detectable. This phase exists to answer one question before anything else: **if a real attacker logged onto this domain right now, would I see it?**

This also mirrors how real SOC/detection engineering work is structured — visibility engineering and log source onboarding come before detection rule-writing, which comes before threat hunting.

## 🛠 What Technologies?

| Category | Tools |
|---|---|
| Endpoint telemetry | Sysmon (SwiftOnSecurity config) |
| Script logging | Windows PowerShell Script Block & Module Logging |
| Audit policy | Windows Advanced Audit Policy Configuration (GPO) |
| Log shipping | Winlogbeat 8.12.0 |
| SIEM backend | Elasticsearch & Kibana 8.12.0 (self-hosted, see [SIEM-Lab-ELK-Stack](../SIEM-Lab-ELK-Stack)) |
| Environment | Windows Server domain controller, Windows 10 domain-joined endpoint |
| Deception | Canary token file on a monitored file share |

## 🏗 Architecture

```
┌────────────────────┐        ┌────────────────────┐
│  Domain Controller  │        │  Windows 10 Client   │
│  (Joshua-Server2022)│        │  (MY-LAB-PC)         │
│                      │        │                      │
│  • Sysmon            │        │  • Sysmon            │
│  • PowerShell logging│        │  • PowerShell logging│
│  • Advanced Audit    │        │  • Winlogbeat         │
│    Policy + SACL     │        │                      │
│  • Winlogbeat         │        │                      │
└──────────┬───────────┘        └──────────┬───────────┘
           │        HTTPS (Winlogbeat → Elasticsearch)  │
           └───────────────────┬───────────────────────┘
                                ▼
                     ┌─────────────────────┐
                     │   Elasticsearch      │
                     │   (self-signed TLS)  │
                     └──────────┬───────────┘
                                ▼
                     ┌─────────────────────┐
                     │       Kibana         │
                     │  winlogbeat-* view   │
                     └─────────────────────┘
```

## ⚙️ How Did I Build It?

### 1. Sysmon Deployment
Installed on both hosts using [SwiftOnSecurity's sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config) — a curated, single-file baseline tuned to surface attacker-relevant behavior while filtering routine Windows noise.
```powershell
.\Sysmon64.exe -accepteula -i sysmonconfig-export.xml
```
Verified via `sc query sysmon64` and confirmed events appearing under `Applications and Services Logs > Microsoft > Windows > Sysmon > Operational`.

### 2. PowerShell Logging (GPO)
Enabled under **Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell**:
- Turn on Module Logging (`*`)
- Turn on PowerShell Script Block Logging

Validated by generating PowerShell activity and confirming **Event IDs 4103 and 4104** in the PowerShell Operational log.

### 3. Advanced Audit Policy (GPO)

| Category | Subcategories | Event IDs |
|---|---|---|
| Logon/Logoff | Audit Logon, Audit Logoff | 4624, 4625, 4634 |
| Account Logon | Kerberos Authentication Service, Kerberos Service Ticket Operations | 4768, 4769, 4771, 4776 |
| Account Management | User Account Management, Security Group Management | 4720, 4722, 4724, 4738 |
| Object Access | File System, File Share | 4663 |

Also enabled **"Audit: Force audit policy subcategory settings to override audit policy category settings"** — without this, legacy audit policy can silently override the modern Advanced Audit Policy settings above.

### 4. File Share SACL + Canary Token
Applied a SACL directly on a file server's **local folder path** (not the mapped drive — Windows blocks remote/mapped-drive auditing changes) auditing Create, Append, and Delete. A canary token file was placed inside the same share as an independent tripwire, so any interaction with it is a signal on its own, regardless of the SIEM.

### 5. Log Shipping — Winlogbeat → Elasticsearch
Installed on both hosts, shipping Application, System, Security, Sysmon, and PowerShell Operational logs directly to Elasticsearch:
```yaml
winlogbeat.event_logs:
  - name: Security
  - name: Microsoft-Windows-Sysmon/Operational
  - name: Microsoft-Windows-PowerShell/Operational

output.elasticsearch:
  hosts: ["https://<elk-host-ip>:9200"]
  ssl.verification_mode: none
  username: "elastic"
  password: "<redacted>"
```
> Elastic Stack 8.x enables TLS on Elasticsearch by default with a self-signed certificate — `ssl.verification_mode: none` is an accepted trade-off for an isolated lab, not production.

### 6. Validation
Created a `winlogbeat-*` data view in Kibana and confirmed live events from both hosts, then ran the exit-criteria search:
```
event.code:4624
```
A normal user logon returned — fully attributable to a user, host, and timestamp.

## 🔐 What Security Concepts?

- **Defense-in-depth logging** — no single log source tells the whole story; Sysmon, PowerShell logging, and Windows Security auditing each cover different attacker behavior
- **Audit policy precedence** — legacy vs. Advanced Audit Policy conflicts, and why forcing subcategory settings matters
- **The principle of "baseline before threat hunting"** — you must be able to recognize *normal* activity before you can recognize anomalous activity
- **Deception technology fundamentals** — a canary token as a low-cost, high-signal tripwire independent of log pipeline health
- **SACL vs. DACL** — auditing access is a separate control from granting access
- **TLS trust models** — self-signed certificates, and the operational trade-off of skipping verification in an isolated lab context

## 📚 What Did I Learn?

- Windows Event Viewer's "Access is denied" errors are almost always a UAC token/elevation issue, not a genuine permissions gap
- SACLs applied via a mapped network drive trigger a "remote setting" warning and strip inherited entries — set them on the real local folder path instead
- YAML is whitespace- and comment-position-sensitive: a `#` at the *end* of a line does nothing; it must be the first character to comment out a line
- A single misplaced comment character (`output.elasticsearch:` left commented while its child keys were active) produces a confusing "did not find the expected key" error that looks unrelated to the real cause
- Elastic Stack 8.x enables security and TLS by default — plan for `https://` and either proper CA-signed certs or an explicit verification bypass in a lab

## 🔧 What Would I Improve?

- Route Winlogbeat through Logstash (as originally planned) rather than direct-to-Elasticsearch, to enable field enrichment and consistent index naming (`winlogbeat-lab-*`) matching the existing `filebeat-lab-*` convention
- Replace the self-signed certificate + `ssl.verification_mode: none` with a proper internal CA, even in a lab, as a hardening exercise
- Investigate why Sysmon Event ID 3 (Network Connection) and 22 (DNS Query) did not consistently fire on the Windows 10 endpoint despite the SwiftOnSecurity config being loaded — a real gap worth root-causing before relying on network-layer Sysmon telemetry in later phases
- Set up Index Lifecycle Management (ILM) so `winlogbeat-*` doesn't grow unbounded
- Build a baseline Kibana dashboard (logon volume, top event codes) rather than relying solely on ad hoc searches

## 🧾 What Evidence Do I Have?

- Sysmon confirmed running and generating events (Process Create, DNS Query) on both hosts
- PowerShell Event IDs 4103/4104 captured with real script block content
- Event ID 4663 captured on the audited file share following a real create/delete test
- Live `winlogbeat-*` index in Kibana with hundreds of documents from both hosts within minutes of deployment
- A successful, attributable **Event ID 4624** search in Kibana — the phase's exit criteria — showing a specific user, host, and timestamp

---

## 📸 Screenshots

> Add screenshots to a `/screenshots` folder in this directory and reference them below.

| Description | Screenshot |
|---|---|
| Sysmon running with SwiftOnSecurity config loaded | `![sysmon running](screenshots/sysmon-running.png)` |
| PowerShell 4103/4104 events in Event Viewer | `![powershell logging](screenshots/powershell-logging.png)` |
| Advanced Audit Policy categories in GPME | `![audit policy gpo](screenshots/audit-policy-gpo.png)` |
| Event ID 4663 on the audited file share | `![event 4663](screenshots/event-4663.png)` |
| Kibana Discover — live winlogbeat-* data | `![kibana winlogbeat data](screenshots/kibana-winlogbeat-data.png)` |
| Event ID 4624 — exit criteria validation | `![event 4624 validation](screenshots/event-4624-validation.png)` |

---

## 🗺 Roadmap

- [x] Deploy Sysmon on DC + Windows 10 endpoint
- [x] Enable PowerShell Script Block & Module Logging via GPO
- [x] Configure Advanced Audit Policy across 4 categories
- [x] Apply a SACL and canary token on a file share
- [x] Ship logs via Winlogbeat into Elasticsearch
- [x] Validate a normal logon (4624) is searchable in Kibana
- [ ] Phase 1 — Recon & Credential Access techniques (LLMNR poisoning, password spraying, Kerberoasting, AS-REP roasting)
- [ ] Phase 2 — Attack Path Mapping with BloodHound
- [ ] Phase 3 — Lateral Movement & Escalation
- [ ] Phase 4 — Persistence (DCSync & Golden Ticket)

---

## 🔐 Security Disclaimer

This is a personal, isolated home lab built strictly for educational and skills-development purposes. All hostnames, IP addresses, and credentials referenced in this documentation are placeholders or have been redacted. No techniques described here were performed against any system without explicit authorization.
