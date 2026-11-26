# Incident Report: Simulated Domain Compromise

**LLMNR Poisoning to DCSync to Golden Ticket**

| Field | Detail |
|-------|--------|
| Prepared by | Okunnuwa Joshua Godwin |
| Scope | Phases 1 to 4, personal AD attack/defense lab (JOSHUA.LOCAL) |
| Type | Post-exercise findings and recommendations |

I wrote this report the way I'd brief an engineering manager after the exercise: what I did, what my own logging caught, and the one place it didn't.

## Summary

In a controlled, self-hosted lab, I ran a full domain compromise chain starting from an unauthenticated position on the network and ending in complete control of the domain controller. The chain worked end to end.

Of the six techniques I used, four left a clear host-based trace and two left almost nothing. The finding I'd put in front of leadership: my logging as configured would have stopped this attacker at the reconnaissance and credential-theft stages, but would not have detected the actual loss of domain control.

| Step | Technique | MITRE ID | Detected? | Note |
|------|-----------|----------|-----------|------|
| 1 | LLMNR/NBT-NS Poisoning | T1557.001 | Partial | Capture is guaranteed by the protocol; the consequence depends on password strength |
| 2 | Kerberoasting | T1558.003 | Yes | AES-only policy is a working mitigating control |
| 3 | BloodHound enumeration | T1087.002 | Partial | Mapped the exact 3-hop path to Domain Admin without touching credentials |
| 4 | Lateral movement and SYSTEM | T1021.002 / T1053.005 | Yes | 61 ms between logon and execution, detectable by a SIEM rule |
| 5 | LSASS dump and DCSync | T1003.001 / T1003.006 | No | Zero log entries; DS Access auditing never enabled |
| 6 | Golden Ticket | T1558.001 | One artifact | A single normal-looking logon, indistinguishable from a legitimate admin |

## What happened, step by step

### 1. Initial access: LLMNR/NBT-NS poisoning

With no credentials and just a position on the internal network, I ran a poisoning tool that answered broadcast name-resolution fallbacks from domain-joined hosts. It captured NTLMv2 hashes for three real accounts, including `Administrator`, from ordinary background network noise. No phishing, no exploit, just listening. One hash cracked quickly because the password was weak; the others held. Capture is guaranteed by the protocol, but whether it matters depends on password strength.

### 2. Credential access: Kerberoasting

From a valid but low-privileged session, I requested a Kerberos service ticket for an SPN-registered account and cracked it offline. No malware, no exploit, just a normal Kerberos feature abused. Worth calling out: the domain's AES-only policy meant I had to deliberately weaken an account's encryption settings to produce a crackable hash. That policy is a real control, and it was already working.

### 3. Reconnaissance: BloodHound attack-path mapping

With one low-privilege account I mapped the domain's trust and permission graph and found a directional path from a standard user to Domain Admins. This is the step I'd most want leadership to understand. An attacker doesn't need luck at every step if they can find the one path that works. It touches no credentials at all, but it turned "I have one weak account" into "I know exactly which three hops reach full domain control."

### 4. Lateral movement and privilege escalation

The mapped path needed local admin on a workstation, which a realistic GPO misconfiguration provided. I then executed code as `NT AUTHORITY\SYSTEM` through a Task Scheduler technique (atexec). This produced the cleanest detection signal in the whole chain:

```
4624 (Network logon, ElevatedToken)
  └── 61ms later
      └── Sysmon EID 1 (cmd.exe → whoami.exe, output to C:\Windows\Temp\[random])
```

That 61 ms gap between logon and command execution is something a human analyst would never think to check, but a SIEM rule can.

### 5. Credential theft: LSASS dump and DCSync

From the SYSTEM foothold I extracted a cached Administrator credential from lsass memory, after disabling endpoint protection, which in production would itself be a loud signal. I used that credential to impersonate DC replication rights and pull `krbtgt` keys directly from the live DC.

This step generated zero log entries. Directory Service Access auditing, the one setting that would have caught it, was never enabled. That isn't a tooling failure; it's a configuration gap that almost certainly exists by default in many real environments.

### 6. Persistence: Golden Ticket

With the `krbtgt` keys I forged a ticket granting Domain Admin access indefinitely, with no real password and no further contact with the DC. Two patched controls correctly rejected my first two attempts:

| Attempt | Why it failed | Control |
|---------|---------------|---------|
| Fake account (non-existent) | CVE-2021-42287 PAC validation | Working |
| RC4-encrypted ticket | AES-only Kerberos enforcement | Working |
| AES256 + real account | n/a | Succeeded |

The only artifact this leaves is a single ordinary-looking network logon, with no way to tell it apart from a legitimate admin logging on remotely.

## Business impact

Had this been real, the foothold from Step 4 alone would have been enough to escalate to full domain control at any later time, without repeating any earlier step. The forged ticket doesn't expire on its own and doesn't need the originally compromised account to stay active. Detecting steps 1 to 4 would interrupt the chain before domain-level impact; as configured, steps 5 and 6 would not have been interrupted.

## Recommendations, in priority order

1. **Enable Directory Service Access (4662) auditing** with SACLs scoped to the two DCSync-relevant replication rights. This is the highest-leverage fix: it turns an invisible step into an alertable event, and it's essentially one configuration change. (I implemented this in [Phase 5B Gap 1](../Phase-5-Detection-Engineering/5B-Closing-The-Detection-Gaps/Gap-1-DCSync-No-Audit-Trail/README.md).)
2. **Deploy a network or identity-layer sensor** (Microsoft Defender for Identity or Zeek) as a compensating control for both the LLMNR and DCSync gaps. Both are protocol-level abuses that host-based Sysmon logging is structurally not positioned to catch.
3. **Add a "4769 without a preceding 4768" correlation rule** as a general tripwire for credential-replay and forged-ticket activity. It would have flagged the one surviving artifact from steps 5 and 6. (Implemented in [Phase 5B Gap 2](../Phase-5-Detection-Engineering/5B-Closing-The-Detection-Gaps/Gap-2-Golden-Ticket-No-Tripwire/README.md).)
4. **Rotate `krbtgt` on a schedule**, twice, spaced by the maximum ticket lifetime, as standing hygiene regardless of whether a compromise is suspected.
5. **Treat EDR-disabling as a first-class alert.** The credential-theft step only worked after I disabled real-time protection. In production that action, from the agent's own tamper-protection logging, should be one of the loudest signals available.

## Closing finding

The strongest finding here isn't any single technique. It's that my detection coverage has a hard boundary exactly where the DC's own replication protocol is abused, and that boundary is closable with one audit-policy change plus a network sensor, not a rebuild.

## Related phases

| Phase | Focus |
|-------|-------|
| [Phase 0](../Phase-0-Visibility-Foundation) | ELK Stack, Sysmon, Winlogbeat |
| [Phase 1](../Phase-1-Credential-Access) | LLMNR, Kerberoasting, AS-REP Roasting |
| [Phase 2](../Phase-2-Attack-Path-Mapping) | BloodHound enumeration |
| [Phase 3](../Phase-3-Lateral-Movement) | Lateral movement, GPO abuse |
| [Phase 4](../Phase-4-DCSync-Golden-Ticket) | DCSync, Golden Ticket |
| [Phase 5](../Phase-5-Detection-Engineering) | Detection engineering, KQL, dashboard |

---

Back to the [lab overview](../README.md)

*This report documents a controlled simulation run entirely in a private, isolated lab. No real systems were targeted.*
