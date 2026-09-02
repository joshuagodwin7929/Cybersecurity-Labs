# 🔐 Incident Report — Simulated Domain Compromise
## LLMNR Poisoning → DCSync → Golden Ticket

<div align="center">

![Status](https://img.shields.io/badge/Status-Simulation%20Complete-success?style=for-the-badge)
![Severity](https://img.shields.io/badge/Severity-Critical-red?style=for-the-badge)
![Domain](https://img.shields.io/badge/Domain-JOSHUA.LOCAL-0078D4?style=for-the-badge&logo=microsoft)
![Phases](https://img.shields.io/badge/Phases%20Covered-1%20through%204-purple?style=for-the-badge)

</div>

---

| Field | Detail |
|-------|---------|
| **Prepared for** | Engineering Manager Briefing |
| **Classification** | Internal — Lab Simulation (JOSHUA.LOCAL) |
| **Prepared by** | Okunnuwa Joshua Godwin |
| **Lab Activity** | Phases 1–4, Personal AD Attack/Defense Lab |
| **Report Type** | Post-Exercise Findings & Recommendations |

---

## 📋 Executive Summary

> Over a controlled, self-hosted lab exercise, I simulated a full domain compromise chain starting from a single **unauthenticated network position** and ending in **complete, undetected control of the domain controller.**

The chain succeeded end-to-end. Of the six major techniques used:

| Coverage | Count | What It Means |
|----------|-------|---------------|
| ✅ Fully detectable | 4 techniques | Strong templates for production detection rules |
| ❌ Left no host-based trace | 2 techniques | DCSync and Golden Ticket — headline finding |

**The headline finding:** My current logging posture would have stopped this attacker at the reconnaissance and credential-theft stages — but would not have detected the actual loss of domain control.

---

## ⏱️ Attack Timeline

| Step | Technique | MITRE ID | Detected? | Key Finding |
|------|-----------|----------|-----------|-------------|
| 1 | LLMNR/NBT-NS Poisoning | T1557.001 | ⚠️ Partial | Capture guaranteed by protocol — only consequence depends on password strength |
| 2 | Kerberoasting | T1558.003 | ✅ Yes | AES-only policy is a working mitigating control |
| 3 | BloodHound Enumeration | T1087.002 | ⚠️ Partial | Mapped exact 3-hop path to Domain Admin without touching credentials |
| 4 | Lateral Movement & SYSTEM | T1021.002 / T1053.005 | ✅ Yes | 61ms gap between logon and execution — detectable by SIEM rule |
| 5 | LSASS Dump + DCSync | T1003.001 / T1003.006 | ❌ None | Zero log entries — DS Access auditing never enabled |
| 6 | Golden Ticket | T1558.001 | ⚠️ One artifact | Single normal-looking network logon — indistinguishable from legitimate admin |

---

## 🔍 Detailed Narrative

### 1 — Initial Access: LLMNR/NBT-NS Poisoning

Positioned on the internal network with no credentials, I ran a poisoning tool that answered broadcast name-resolution fallbacks from domain-joined hosts. This captured NTLMv2 hashes for three real accounts — including `Administrator` — from ordinary background network noise.

> **No phishing. No exploit. Just listening.**

One hash cracked quickly due to a weak password. The others resisted cracking — which illustrates that **capture is guaranteed by the protocol; only the consequence depends on password strength.**

---

### 2 — Credential Access: Kerberoasting

Using a valid but low-privileged domain session, I requested a Kerberos service ticket for an SPN-registered account and cracked it offline. This is a living-off-the-land technique — no malware, no exploit, just a normal Kerberos feature abused.

> **Worth calling out:** This domain's AES-only policy required me to deliberately weaken an account's encryption settings to produce a crackable hash. **That policy is a genuine mitigating control and it is already working correctly.**

---

### 3 — Reconnaissance: BloodHound Attack Path Mapping

With one set of low-privilege credentials, I mapped the entire domain's trust and permission graph and found a directional path from a standard user account to Domain Admins.

> ⚠️ **This is the step most important for leadership to understand.**
>
> An attacker doesn't need to be lucky at every step if they can map the one path that works. This step doesn't touch credentials at all — it's pure information gathering — but it transformed *"I have one weak account"* into *"I know exactly which three hops get me to full domain control."*

---

### 4 — Lateral Movement & Privilege Escalation

The mapped path required local admin rights on a workstation. A realistic GPO misconfiguration granted that access. Code was then executed as `NT AUTHORITY\SYSTEM` via a Task Scheduler-based technique (atexec).

This step produced the **cleanest detection signal in the entire chain:**

```
4624 (Network logon, ElevatedToken)
  └── 61ms later
      └── Sysmon EID 1 (cmd.exe → whoami.exe, output to C:\Windows\Temp\[random])
```

> **That 61ms timing gap between logon and command execution is a detail a human analyst would never think to check — but a SIEM rule easily can.**

---

### 5 — Credential Theft: LSASS Dump & DCSync

From the SYSTEM foothold, I extracted a cached Administrator credential from lsass memory — after disabling endpoint protection, a step that would itself be a loud detection signal in production.

That credential was then used to impersonate Domain Controller replication rights and pull `krbtgt` keys directly from the live DC.

> ❌ **This step generated zero log entries.**
>
> Directory Service Access auditing — the one configuration that would have caught it — was never enabled. This is not a tooling failure. It is a configuration gap that almost certainly exists in many real environments by default.

---

### 6 — Persistence: Golden Ticket

With the `krbtgt` keys extracted, I forged a ticket granting Domain Admin access indefinitely — without knowing any real password and without needing to contact the DC again.

**Two patched security controls correctly rejected my first two attempts:**

| Attempt | Reason for Failure | Control Working |
|---------|-------------------|-----------------|
| Fake account (non-existent) | CVE-2021-42287 PAC validation | ✅ Yes |
| RC4-encrypted ticket | AES-only Kerberos enforcement | ✅ Yes |
| AES256 + real account | — | ❌ Succeeded |

> **The only artifact this leaves behind is a single, ordinary-looking network logon event — with no way to distinguish it from a legitimate administrator logging on remotely.**

---

## 💼 Business Impact

> Had this been a real environment:

The foothold achieved in **Step 4** alone would have been sufficient for an attacker to escalate to full domain control at any future time — without repeating any earlier steps. The forged ticket does not expire on its own and does not require the original compromised account to remain active.

```
Detecting steps 1–4      →  Chain interrupted before domain-level impact
As currently configured  →  Steps 5–6 would not have been interrupted
```

---

## ✅ Recommendations — Priority Order

### 🔴 Priority 1 — Immediate (Single Configuration Change)

**Enable Directory Service Access (4662) auditing** with SACLs scoped to the two DCSync-relevant replication rights.

This is the highest-leverage fix available. It converts an invisible step into a loud, alertable event — and it is a one-checkbox configuration change.

---

### 🟠 Priority 2 — Short Term (Compensating Controls)

**Deploy a network or identity-layer sensor** — Microsoft Defender for Identity or Zeek — as a compensating control for both the LLMNR poisoning and DCSync detection gaps.

Both are protocol-level abuses that host-based Sysmon logging is structurally not well-positioned to catch.

---

### 🟡 Priority 3 — Detection Rule Addition

**Add a "4769 without a preceding 4768" correlation rule** as a general-purpose tripwire for credential-replay and forged-ticket activity. This would have flagged the one surviving artifact from both Steps 5 and 6.

---

### 🟡 Priority 4 — Standing Hygiene Practice

**Rotate `krbtgt` on a schedule** — twice, spaced by the maximum ticket lifetime — as a standing hygiene practice, independent of whether a compromise is suspected.

---

### 🟢 Priority 5 — Follow-Up Detection Note

**Treat EDR-disabling as a first-class alert.** The credential-theft step only worked after disabling real-time protection. In production, that action — from the endpoint agent's own tamper-protection logging — should be one of the loudest signals available.

---

## 🎯 Closing Finding

> **The strongest finding from this exercise isn't any single technique.**
>
> It's that our detection coverage has a hard boundary exactly where the DC's own replication protocol is abused — and that boundary is **closable with one audit-policy change plus a network sensor**, not a wholesale re-architecture.

---

## 🔗 Related Lab Phases

| Phase | Focus | Link |
|-------|-------|------|
| Phase 0 | ELK Stack, Sysmon, Winlogbeat | [View →](../Phase0) |
| Phase 1 | LLMNR, Kerberoasting, AS-REP Roasting | [View →](../Phase1) |
| Phase 2 | BloodHound Enumeration | [View →](../Phase2) |
| Phase 3 | Lateral Movement, GPO Abuse | [View →](../Phase3) |
| Phase 4 | DCSync, Golden Ticket | [View →](../Phase4) |
| Phase 5 | Detection Engineering, KQL, Dashboard | [View →](../Phase5) |

---

<div align="center">

**Okunnuwa Joshua Godwin** | Security Operations | Detection Engineering | Active Directory

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-0077B5?style=flat-square&logo=linkedin)](https://www.linkedin.com/in/okunnuwa-joshua-godwin/)
[![GitHub](https://img.shields.io/badge/GitHub-Portfolio-181717?style=flat-square&logo=github)](https://github.com/joshua7929)

*This report documents a controlled simulation conducted entirely within a private isolated lab environment. No real systems were targeted.*

</div>
