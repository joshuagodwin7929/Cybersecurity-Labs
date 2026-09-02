# Phase 3: Lateral Movement & Privilege Escalation

**Part of the Active Directory Attack & Defense Home Lab series**
`Phase 0 (Visibility Foundation) → Phase 1 (Credential Access) → Phase 2 (Attack Path Mapping) → Phase 3 (Lateral Movement & Escalation) → Phase 4 (Persistence) → Phase 5 (Detection Engineering)`

![Status](https://img.shields.io/badge/status-complete-brightgreen)
![Stack](https://img.shields.io/badge/SIEM-Elastic%20Stack-005571)
![Focus](https://img.shields.io/badge/focus-Blue%20Team%20%2B%20Red%20Team-blue)

---

## Table of Contents
- [1. What Did I Build?](#1-what-did-i-build)
- [2. Why Did I Build It?](#2-why-did-i-build-it)
- [3. What Technologies?](#3-what-technologies)
- [4. How Did I Build It?](#4-how-did-i-build-it)
- [5. What Security Concepts?](#5-what-security-concepts)
- [6. What Did I Learn?](#6-what-did-i-learn)
- [7. What Would I Improve?](#7-what-would-i-improve)
- [8. What Evidence Do I Have?](#8-what-evidence-do-i-have)

---

## 1. What Did I Build?

Building on the credential-access techniques from Phase 1 and the attack-path map produced by BloodHound in Phase 2, this phase answers a single question:

> **Once an attacker has a low-privilege domain credential, how far can they actually move and does the SIEM built in Phase 0 catch it?**

I took a single low-privilege domain user, moved it onto a second machine (a Windows 10 workstation) over the network, escalated to `NT AUTHORITY\SYSTEM` on that machine, and then correlated every step of the chain back to raw events inside my self-hosted Elastic Stack (Elasticsearch + Kibana), fed by Sysmon and Winlogbeat.

The full attack chain achieved:

```
Standard Domain User (j.jenkins)
        │
        ▼  (BloodHound: no existing path found)
Simulated a realistic misconfiguration via GPO
        │
        ▼  (Local Admin on MY-LAB-PC)
Remote Authentication over SMB (NetExec)
        │
        ▼  (4624 Type 3 Network Logon — logged)
Remote Code Execution (WMI failed → fell back to atexec)
        │
        ▼  (Sysmon Event ID 1 — logged, 61ms after logon)
NT AUTHORITY\SYSTEM
```

---

## 2. Why Did I Build It?

Phase 2's BloodHound mapping showed *theoretical* attack paths. This phase exists to prove — hands-on, not just on a graph — that a path can be walked in practice, and more importantly, to test whether the detection pipeline built in Phase 0 actually produces usable evidence when it happens.

Real environments rarely hand attackers a clean lateral-movement path. More often, the path exists because of an everyday misconfiguration: a support or helpdesk account that quietly accumulated local admin rights it no longer needs. I wanted to simulate that specific, common scenario rather than an artificial "already have DA" shortcut, and then measure what a defender would actually see.

---

## 3. What Technologies?

| Category | Tools / Tech |
|---|---|
| Attacker tooling | Kali Linux, NetExec (CrackMapExec successor), Impacket suite |
| Attack path mapping | BloodHound Community Edition (self-hosted, Docker) |
| Target environment | Windows Server 2022 (Domain Controller), Windows 10 (domain-joined workstation) |
| Endpoint telemetry | Sysmon (SwiftOnSecurity config) |
| Log shipping | Winlogbeat |
| SIEM | Elasticsearch + Kibana (Elastic Stack 8.12.0, Docker Compose) |
| Directory changes | Active Directory Group Policy (Restricted Groups, Security Filtering) |
| Detection query language | KQL (Kibana Query Language) |

---

## 4. How Did I Build It?

### Step 1 — Confirm there's no existing path
Re-ran BloodHound against the domain. The compromised low-privilege account (`j.jenkins`, obtained via AS-REP Roasting in Phase 1) had **zero** local admin or execution rights anywhere in the environment — only the built-in `Administrator` account had local admin on the target workstation (`MY-LAB-PC`).

### Step 2 — Simulate a realistic misconfiguration
Rather than fabricate an artificial shortcut, I created a new, narrowly-scoped Group Policy Object (`Workstation-LocalAdmin-RestrictedGroups`) that grants a small set of standard user accounts local admin rights on `MY-LAB-PC` only — using **Security Filtering** (targeting the specific computer object, not an OU move) to avoid disturbing any other host or existing GPO in the domain.

### Step 3 — Find and fix a real blocker
Initial lateral movement attempts silently failed. Root cause: the **Domain-profile Windows Firewall rule for inbound SMB was disabled** on the workstation (the Private/Public profile copies were enabled, masking the problem). This is itself a legitimate hardening control working as intended — fixed via:
```powershell
Set-NetFirewallRule -DisplayName "File and Printer Sharing (SMB-In)" -Profile Domain -Enabled True
```

### Step 4 — Execute lateral movement
```bash
netexec smb <target-ip> -u j.jenkins -p '<redacted>' -d joshua.local
```
Result: `(Pwn3d!)` — confirmed admin-level SMB access, generating a **4624 Type 3 (network logon)** event on the target.

### Step 5 — Execute remotely and escalate
```bash
netexec smb <target-ip> -u j.jenkins -p '<redacted>' -d joshua.local -x whoami
```
The default WMI-based execution method failed (DCOM initialization error). NetExec automatically fell back to **atexec** — a technique that abuses the Windows Task Scheduler service (which runs inside a shared `svchost.exe -k netsvcs` process) to execute commands. Because Task Scheduler runs as SYSTEM, this single fallback delivered full `NT AUTHORITY\SYSTEM` execution.

### Step 6 — Hunt the evidence in Kibana
Correlated the full chain using KQL:
```
event.code:4624 and winlog.event_data.LogonType:"3" and winlog.event_data.TargetUserName:"j.jenkins"
```
```
event.code:1 and process.parent.name:"svchost.exe"
```
The resulting Sysmon Event ID 1 landed **61 milliseconds** after the logon event — a clean, millisecond-correlated timeline from initial access to code execution.

---

## 5. What Security Concepts?

- **Lateral movement** (MITRE ATT&CK T1021 — Remote Services)
- **Local admin rights abuse** as a real-world privilege escalation vector
- **Scheduled Task execution / atexec** (MITRE ATT&CK T1053.005), a lesser-documented alternative to PsExec/WMI with a distinct forensic signature
- **GPO Restricted Groups & Security Filtering** as both an attack surface (over-permissioning) and a precise administrative control
- **Windows Firewall profiles** (Domain vs. Private vs. Public) as a genuine lateral-movement control
- **Detection engineering**: correlating a logon event to a process-creation event via timestamp and host to reconstruct attacker behavior
- **Defense-in-depth thinking**: recognizing that detecting one technique (e.g. PsExec) doesn't mean lateral movement in general is covered

---

## 6. What Did I Learn?

- **A blocked path isn't the end of the exercise.** When BloodHound showed no viable path, the realistic next question asked constantly in real SOCs is usually "what misconfiguration would create one?" rather than treating the lab as complete.
- **Silent failures are the most valuable troubleshooting lessons.** The disabled Domain-profile SMB rule failed with zero error output from the attack tooling — tracking it down required checking the *target's* configuration, not just the attacker's syntax.
- **Tools have fallback behavior worth understanding.** NetExec's silent WMI → atexec fallback initially looked like a tool quirk. Digging into *why* it fell back, and what artifact that fallback leaves behind, was more educational than a clean one-shot success would have been.
- **Not every "attack signature" looks alarming in isolation.** `svchost.exe` spawning `cmd.exe` is not inherently malicious — legitimate scheduled tasks do this constantly. The context (timing correlation to a suspicious logon, the account behind it, redirect-to-temp-file behavior) is what makes it worth flagging, not the process tree alone.
- **Ground truth beats tooling assumptions.** When BloodHound's graph didn't reflect a GPO change I'd already verified at the OS level, I learned to trust `net localgroup administrators` and a live exploitation attempt over a single tool's output — and to investigate *why* the tool disagreed (a SAMR enumeration restriction) rather than assume the tool is always right.

---

## 7. What Would I Improve?

- **Enable remote SAMR enumeration** (`RestrictRemoteSAM`) intentionally in the lab so BloodHound's graph reflects live changes in real time, closing the gap between ground truth and graph visibility.
- **Tune Sysmon/detection rules specifically for atexec**, since most public detection content focuses on PsExec and WMI — a rule matching `svchost.exe -k netsvcs` spawning a shell with output redirected to `%WINDIR%\Temp\<random>` would catch this technique specifically.
- **Add network-layer visibility** (e.g. Zeek or Suricata) to complement host-based Sysmon/Winlogbeat telemetry, since this phase's evidence relied entirely on endpoint logs.
- **Automate the BloodHound collection → ingest workflow** (currently a manual scp + web upload), which cost significant time during troubleshooting.

---

## 8. What Evidence Do I Have?

> Screenshots below are redacted of internal IPs, hostnames where sensitive, and credentials, per this project's standard OPSEC practice for public write-ups.

### GPO Configuration
`screenshots/phase3/01-gpo-restricted-groups.png`
*Restricted Groups configuration granting scoped local admin rights on the target workstation only.*

### Security Filtering Scope
`screenshots/phase3/02-security-filtering.png`
*GPO Security Filtering limited to the target computer object, confirming no domain-wide impact.*

### Firewall Root Cause
`screenshots/phase3/03-firewall-rule-disabled.png`
*Domain-profile SMB-In rule found disabled — the actual blocker for initial lateral movement attempts.*

### Confirmed Admin Access
`screenshots/phase3/04-netexec-pwn3d.png`
*NetExec confirming `(Pwn3d!)` admin-level SMB access using the compromised low-privilege credential.*

### Remote Execution Fallback
`screenshots/phase3/05-atexec-fallback.png`
*WMI execution failure followed by automatic fallback to atexec, returning `nt authority\system`.*

### Kibana: Lateral Movement Logon (4624)
`screenshots/phase3/06-kibana-4624-logon.png`
*Type 3 network logon, Elevated Token: Yes, fully attributed to the compromised account.*

### Kibana: Process Creation Artifact (Sysmon Event ID 1)
`screenshots/phase3/07-kibana-sysmon-whoami.png`
*`whoami.exe` spawned by `cmd.exe`, spawned by `svchost.exe -k netsvcs`, output redirected to a random temp file — the atexec forensic signature — timestamped 61ms after the logon event.*

---

## Series Navigation

| Phase | Focus | Status |
|---|---|---|
| [Phase 0](../phase-0-Visibility-Foundation) | Visibility Foundation (Sysmon, Winlogbeat, Audit Policy) | ✅ Complete |
| [Phase 1](../phase-1-Credential-Access) | Credential Access (LLMNR, Spraying, Kerberoasting, AS-REP Roasting) | ✅ Complete |
| [Phase 2](../phase-2-Attack-Path-Mapping) | Attack Path Mapping (BloodHound) | ✅ Complete |
| **Phase 3** | **Lateral Movement & Escalation** | ✅ **Complete (this repo)** |
| [Phase 4](../phase-4-DCSync-Golden-Ticket) | Persistence (DCSync & Golden Ticket) | ✅ Complete |
| [Phase 5](../phase-5-) | Detection Engineering Write Up | ✅ Complete |
| [Phase 6](../phase-6-Incident Report) | ✅ Complete |

---

*This lab is a personal, fully isolated home environment built solely for educational and defensive-skills development purposes. No production systems, third-party networks, or real user data were involved.*
