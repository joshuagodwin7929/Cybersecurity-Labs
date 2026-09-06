# Phase 1 — Recon & Credential Access
### Active Directory Attack & Defense Lab | Home SIEM Series

> **Series context:** This is Phase 1 of a multi-phase, self-hosted Active Directory attack/defense lab, built on top of a personal Elastic Stack (ELK) SIEM I stood up first ([see ../02-SIEM-Lab-ELK-STACK repo](#)). Every attack technique in this phase was executed against my own lab, then hunted for in Kibana using the logging pipeline I built. The goal of the series is to learn detection engineering by attacking my own environment and measuring what does and doesn't show up in the logs.

**Series roadmap:**
| Phase | Focus | Status |
|---|---|---|
| Phase 0 | Visibility Foundation (Sysmon, Winlogbeat, Audit Policy, ELK pipeline) | ✅ Complete |
| **Phase 1** | **Recon & Credential Access (this repo)** | ✅ **Complete** |
| Phase 2 | Attack Path Mapping (BloodHound) | ✅ Complete |
| Phase 3 | Lateral Movement & Escalation | ✅ Complete |
| Phase 4 | Persistence (DCSync & Golden Ticket) | ✅ Complete |

---

## 1. What Did I Build?

A fully instrumented Active Directory lab environment where I executed four real-world credential access techniques  **LLMNR/NBT-NS Poisoning, Password Spraying, Kerberoasting, and AS-REP Roasting**  against a domain I control, then used my own SIEM pipeline (Sysmon → Winlogbeat → Elasticsearch → Kibana) to determine whether each attack was detectable, and if not, why.

Each technique followed the same disciplined loop:

```
LOG FIRST  →  ATTACK SECOND  →  HUNT THIRD
(confirm visibility)   (execute the technique)   (write & validate a detection query)
```

This wasn't a "run a tool and watch it work" exercise  it was a detection-engineering exercise. Two of the four techniques exposed **real gaps** in my logging pipeline, which I root-caused and fixed as part of the work.

---

## 2. Why Did I Build It?

I'm building a career in cybersecurity and wanted to move past theory and certifications-only study into hands-on, evidence-based learning. Reading about Kerberoasting is one thing; watching my own SIEM either catch it or fail to catch it and understanding *why* is what actually builds the intuition that security teams need.

Specifically, I wanted to:
- Understand attacker tradecraft well enough to simulate it safely and legally in my own environment
- Learn how each technique actually looks in raw Windows Event Logs, not just in a tool's console output
- Practice the detection engineer's workflow: hypothesize a detection, test it against ground truth, and fix what doesn't work
- Build a portfolio of documented, reproducible work that demonstrates practical skill to employers

---

## 3. What Technologies?

| Category | Tools / Tech |
|---|---|
| **Domain Environment** | Windows Server 2022 (Domain Controller), Windows 10 (domain-joined endpoint) |
| **Attack Platform** | Kali Linux |
| **Attack Tooling** | Responder, NetExec (formerly CrackMapExec), Impacket (`GetUserSPNs`, `GetNPUsers`) |
| **Password Cracking** | John the Ripper (rockyou.txt wordlist, rule-based cracking) |
| **Endpoint Telemetry** | Sysmon (SwiftOnSecurity config), Windows Advanced Audit Policy, PowerShell Script Block/Module Logging |
| **Log Shipping** | Winlogbeat 8.12.0 |
| **SIEM Stack** | Elasticsearch, Kibana, Logstash (Elastic Stack 8.12.0, Docker Compose) |
| **Infrastructure** | VMware (VMnet2, NAT networking), Active Directory DHCP |

---

## 4. How Did I Build It?

### Setup
- 15 realistic domain user accounts were seeded across the domain to give password spraying and enumeration realistic scope
- The domain's Default Domain Password Policy was hardened first (lockout threshold set to 5 attempts / 30-minute observation window) so that spraying behavior would be representative of a real hardened environment, not a wide-open lab

### Technique 1 — LLMNR/NBT-NS Poisoning
- Launched **Responder** on the attack box to listen for and respond to broadcast name-resolution requests
- Captured **4 NTLMv2 hashes**: one from a planted test account, and three from real domain accounts (`Administrator`, `rose.diaz`, `sarah.connor`)
- Attempted to crack all captured hashes offline with John the Ripper against rockyou.txt
  - The test account's weak password cracked successfully
  - All three real-account hashes resisted the full wordlist
- **Pipeline gap found:** Sysmon Event ID 3 (Network Connection) and Event ID 22 (DNS Query) were not firing on the endpoint despite an active SwiftOnSecurity config — meaning this entire technique was currently invisible to host-based hunting. Documented as an open finding, with Zeek/Suricata flagged as a future network-layer visibility fix.

### Technique 2 — Password Spraying
- Ran a single-password spray with NetExec across all 15 domain accounts:
  ```
  netexec smb <DC_IP> -u users.txt -p 'Summer2026!'
  ```
- Result: zero successful authentications, and the account lockout policy triggered cleanly and correctly on two accounts after 4 failed attempts
- **Pipeline gap found and fixed:** the DC's Winlogbeat configuration had its Elasticsearch output entirely commented out, referenced a stale IP address left over from an earlier network migration, and contained duplicate configuration keys. Fixed the config and confirmed the DC's logs began flowing into Elasticsearch.
- **Detection gap found and root-caused:** failed logon events (4625) appeared correctly in Kibana, but the expected account-lockout event (4740) never landed. Root cause: the domain's legacy Audit Policy was silently overriding the Advanced Audit Policy GPO, because the "Force audit policy subcategory settings" security option was not enabled. Confirmed via `auditpol` and `Get-ADUser` that the lockout mechanism itself worked correctly — only the *logging* of that lockout was broken.

### Technique 3 — Kerberoasting
- Created a service account (`svc_sql`) with a Service Principal Name (SPN) to make it Kerberoastable
- Initial ticket requests failed with `KDC_ERR_ETYPE_NOSUPP` — root-caused to the domain enforcing AES-only Kerberos encryption by default. Temporarily enabled RC4 support on the account to reproduce a realistic (still common in the wild) attack path
- Requested a crackable service ticket using `impacket-GetUserSPNs`
- Validated the exact attack signature in Kibana:
  ```
  event.code:4769 and winlog.event_data.TicketEncryptionType:"0x17"
  ```
- Ran a controlled password-strength comparison:
  - Strong password (`<redacted>`) → resisted wordlist **and** rule-based cracking
  - Weak reset password (`<redacted>`) → cracked instantly
- Fixed an unrelated infrastructure issue found mid-phase: a `netplan` config on the ELK box referenced the wrong network interface name after an earlier VM network migration, which was silently breaking Kibana access

### Technique 4 — AS-REP Roasting
- Created a second account (`j.jenkins`) with Kerberos pre-authentication disabled (`DoesNotRequirePreAuth`)
- Requested the account's AS-REP hash with `impacket-GetNPUsers` — worked cleanly on the first attempt
- Ran the same before/after cracking comparison as Kerberoasting: strong password resisted, weak reset password cracked instantly
- Confirmed the attack's signature in the raw 4768 event (`Pre-Authentication Type: 0`, vs. `2` for a normal logon)
- Validated the detection query in Kibana on the first attempt:
  ```
  event.code:4768 and winlog.event_data.PreAuthType:"0"
  ```

---

## 5. What Security Concepts?

- **Kerberos authentication internals** — AS-REQ/AS-REP, TGS-REQ/TGS-REP, pre-authentication, ticket encryption types (RC4 vs. AES), and how each attack abuses a specific step in that exchange
- **NTLM relay/poisoning fundamentals** — how LLMNR and NBT-NS fall back to broadcast resolution and why that makes them exploitable by default on unhardened networks
- **Credential exposure vs. credential compromise** — a captured hash is not automatically a cracked password; cracking success depends entirely on password strength and wordlist coverage
- **Defense-in-depth auditing** — the difference between a control *working* (account lockout) and a control being *observable* (lockout events actually reaching the SIEM), and how legacy Group Policy settings can silently undermine modern Advanced Audit Policy
- **Detection engineering methodology** — hypothesize → validate against ground truth → fix pipeline gaps → re-validate, rather than assuming a SIEM is "just working"
- **Encryption downgrade attacks** — how AES-only environments still expose RC4-crackable tickets when service accounts are misconfigured

---

## 6. What Did I Learn?

- A password hash being captured says nothing about whether it's crackable — three of four real-world hashes in Technique 1 resisted a full wordlist attack, which reframed cracking as a password-strength problem, not just a capture problem
- Logging pipelines fail silently. Two of four techniques in this phase produced **no usable detection signal at all** until I found and fixed a real misconfiguration — a lesson that "the SIEM is set up" and "the SIEM is capturing what you think it's capturing" are very different claims
- Legacy Windows audit policy settings can override modern GPO-based Advanced Audit Policy without any visible error, which is a trap I now know to check for (`auditpol /get` vs. what the GPO editor shows) in any real environment
- Field names and event structures for the same logical event can vary in ways that aren't obvious from documentation — the AS-REP Roasting query worked first try, while the Kerberoasting query needed correction, teaching me to always validate a hunt query against a known-true positive before trusting it
- Strong, complex passwords are a genuinely effective control against offline cracking, even when the underlying protocol weakness (Kerberoasting, AS-REP Roasting) is fully exploitable — the before/after comparisons made this concrete rather than theoretical

---

## 7. What Would I Improve?

- Add network-layer visibility (Zeek and/or Suricata) to close the LLMNR/NBT-NS detection gap that host-based Sysmon logging alone could not cover
- Investigate and fix the root cause of Sysmon Event IDs 3 and 22 not firing, rather than working around the gap
- Build out a small detection-as-code repository of the validated Kibana queries from this phase so they can be version-controlled and reused across future phases
- Add automated alerting (Kibana/ElastAlert rules) on top of the hunt queries built here, rather than manually searching after the fact
- Extend the password-spray testing to cover multiple passwords per pass (more realistic spray behavior) while keeping the lockout policy in place, to study lockout-evasion timing

---

## 8. What Evidence Do I Have?

> Screenshots below are redacted of any real credentials, internal IP addressing beyond the lab's private ranges, and personal information, per my standard practice before publishing.

### LLMNR/NBT-NS Poisoning
| Evidence | Description |
|---|---|
| ![Responder capture](./screenshots/phase1/01-responder-capture.png) | Responder capturing NTLMv2 hashes |

<img width="641" height="381" alt="01-responder-capture-01" src="https://github.com/user-attachments/assets/181402b3-e23b-4eb9-bba8-1d657364a8e3" />

<img width="529" height="384" alt="01-responder-capture-02" src="https://github.com/user-attachments/assets/05321957-eb21-406d-a6ab-a7389062b3e2" />


| ![John cracking result](./screenshots/phase1/02-john-crack-result.png) | Cracking result: test account cracked, real accounts resisted |

<img width="535" height="383" alt="02-john-crack-result-01" src="https://github.com/user-attachments/assets/661f4e65-ceee-4547-94f6-7bc933902096" />

<img width="511" height="368" alt="02-john-crack-result-02" src="https://github.com/user-attachments/assets/78aff5e6-b4ee-410c-b282-be364fa3c629" />


### Password Spraying
| Evidence | Description |
|---|---|
| ![NetExec spray output](./screenshots/phase1/03-netexec-spray.png) | NetExec spray run with zero valid credentials and lockout messages |

<img width="607" height="378" alt="03-netexec-spray-01" src="https://github.com/user-attachments/assets/104ae5e3-b9f6-4b88-ae2f-3294583825f4" />


<img width="506" height="374" alt="03-netexec-spray-02" src="https://github.com/user-attachments/assets/677927d9-7dbe-4df8-bc42-34732b5a039d" />



| ![Kibana 4625 events](./screenshots/phase1/04-kibana-4625.png) | Failed logon (4625) events visible in Kibana |

<img width="1280" height="584" alt="04-kibana-4625" src="https://github.com/user-attachments/assets/6c006674-5699-46d3-a9a0-04274cdf0e2d" />


| ![auditpol legacy override](./screenshots/phase1/05-auditpol-fix.png) | Root cause: legacy audit policy override, before/after fix |

<img width="587" height="408" alt="05-auditpol-fix" src="https://github.com/user-attachments/assets/b826162f-94ae-45d2-8135-d30e8abaa315" />


### Kerberoasting
| Evidence | Description |
|---|---|
| ![GetUserSPNs ticket request](./screenshots/phase1/06-getuserspns.png) | Requesting the Kerberoastable service ticket |


<img width="496" height="376" alt="06-getuserspns" src="https://github.com/user-attachments/assets/5eaaa3a4-282b-4c1c-a262-119e111ec419" />


| ![Kibana 4769 RC4 query](./screenshots/phase1/07-kibana-4769.png) | Validated hunt query for RC4 ticket encryption |

<img width="2556" height="1474" alt="07-kibana-4769" src="https://github.com/user-attachments/assets/f87d2f15-a3a0-4685-802b-90d4d401fc76" />

| ![Crack comparison](./screenshots/phase1/08-crack-comparison.png) | Strong vs. weak password crack comparison |

<img width="1076" height="760" alt="08-crack-comparison-01" src="https://github.com/user-attachments/assets/f8a0848d-a752-42ca-8eb9-8c766fea141e" />

<img width="1074" height="754" alt="08-crack-comparison-02" src="https://github.com/user-attachments/assets/a1e591e8-967c-4bf6-b474-1836d7381751" />



### AS-REP Roasting
| Evidence | Description |
|---|---|
| ![GetNPUsers hash capture](./screenshots/phase1/09-getnpusers.png) | AS-REP hash capture for the pre-auth-disabled account |

<img width="1079" height="749" alt="09-getnpusers" src="https://github.com/user-attachments/assets/0a79309c-e8c6-43ca-95ed-3941199c9f61" />

| ![Kibana 4768 PreAuthType query](./screenshots/phase1/10-kibana-4768.png) | Validated hunt query on Pre-Authentication Type |

<img width="1273" height="1118" alt="10-kibana-4768" src="https://github.com/user-attachments/assets/e82a229f-85e5-4663-a871-afa24cb17d6d" />


---

## Related Write-Ups

- [LLMNR Poisoning — Full Write-Up](#)
- [Password Spraying & the Audit Policy Gap — Full Write-Up](#)
- [Kerberoasting — Full Write-Up](#)
- [AS-REP Roasting — Full Write-Up](#)

---

*Part of a self-directed home lab series exploring Active Directory attack and defense through the lens of a defender-built SIEM. All activity took place exclusively within an isolated, self-owned virtual lab environment for educational purposes.*
