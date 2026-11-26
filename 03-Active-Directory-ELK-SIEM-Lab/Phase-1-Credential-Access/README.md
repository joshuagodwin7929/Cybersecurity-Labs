# Phase 1: Recon and Credential Access

In this phase I ran four credential-access attacks against my own domain: LLMNR/NBT-NS poisoning, password spraying, Kerberoasting and AS-REP Roasting. For each one I then went looking for it in Kibana, using the logging from [Phase 0](../Phase-0-Visibility-Foundation).

I followed the same loop every time:

```
LOG FIRST  →  ATTACK SECOND  →  HUNT THIRD
(confirm visibility)   (execute the technique)   (write & validate a detection query)
```

Two of the four attacks turned up real problems in my logging, which I had to track down and fix before I could see anything.

## Lab setup

| | |
|---|---|
| Domain | Windows Server 2022 DC, Windows 10 domain-joined client |
| Attacker | Kali Linux |
| Attack tools | Responder, NetExec, Impacket (`GetUserSPNs`, `GetNPUsers`) |
| Cracking | John the Ripper with rockyou.txt and rules |
| Telemetry | Sysmon (SwiftOnSecurity config), Advanced Audit Policy, PowerShell logging |
| SIEM | Winlogbeat 8.12.0 into Elastic Stack 8.12.0 (Docker Compose) |
| Network | VMware VMnet2 (NAT), DHCP from Active Directory |

Before starting I added 15 domain users, so spraying and enumeration had something realistic to work against. I also set the Default Domain Password Policy to lock accounts after 5 attempts in a 30-minute window, so the spray would behave as it would against a hardened domain.

## 1. LLMNR/NBT-NS poisoning

I ran **Responder** on the Kali box to answer broadcast name-resolution requests. It captured **4 NTLMv2 hashes**: one from a test account I'd planted, and three from real domain accounts (`Administrator`, `rose.diaz`, `sarah.connor`).

I tried to crack all four with John the Ripper and rockyou.txt. The test account's weak password cracked. The three real accounts resisted the whole wordlist.

**What I couldn't see:** Sysmon Event IDs 3 (network connection) and 22 (DNS query) weren't firing on the endpoint, even with the SwiftOnSecurity config loaded. So this attack was invisible to host-based hunting. I've left it as an open finding. Network-level monitoring (Zeek or Suricata) is the likely fix.

## 2. Password spraying

I sprayed one password across all 15 accounts with NetExec:

```
netexec smb <DC_IP> -u users.txt -p 'Summer2026!'
```

No logins succeeded, and the lockout policy kicked in on two accounts as designed.

Getting this to show up in Kibana took two fixes:

1. **The DC wasn't shipping logs at all.** Its Winlogbeat config had the Elasticsearch output commented out, pointed at an old IP from an earlier network change, and had duplicate keys. Once I fixed it, the DC's logs started arriving.
2. **The lockout events never arrived.** Failed logons (4625) showed up fine, but the account-lockout event (4740) didn't. The legacy audit policy was silently overriding my Advanced Audit Policy GPO, because "Force audit policy subcategory settings" wasn't enabled. I confirmed with `auditpol` and `Get-ADUser` that the lockouts themselves were working. Only the logging of them was broken.

## 3. Kerberoasting

I created a service account, `svc_sql`, with a Service Principal Name to make it Kerberoastable.

My first ticket requests failed with `KDC_ERR_ETYPE_NOSUPP`. The domain enforces AES-only Kerberos by default, so I enabled RC4 on the account to reproduce the version of this attack that's still common in real networks. Then I requested a crackable ticket with `impacket-GetUserSPNs` and found the signature in Kibana:

```
event.code:4769 and winlog.event_data.TicketEncryptionType:"0x17"
```

I compared password strength: a strong password resisted both the wordlist and rule-based cracking, and a weak one I reset it to cracked instantly.

In the middle of this phase Kibana stopped loading. The ELK VM's `netplan` config still named the old network interface from an earlier migration. Fixing the interface name brought it back.

## 4. AS-REP Roasting

I created `j.jenkins` with Kerberos pre-authentication disabled (`DoesNotRequirePreAuth`). `impacket-GetNPUsers` pulled its AS-REP hash on the first try. Cracking went the same way as Kerberoasting: the strong password held, the weak one fell instantly.

In the raw 4768 event, the attack shows `Pre-Authentication Type: 0`, where a normal logon shows `2`. This query worked first time:

```
event.code:4768 and winlog.event_data.PreAuthType:"0"
```

## What I took from it

- **Capturing a hash isn't cracking it.** Three of my four captured hashes from Responder survived the full wordlist. Password strength decided the outcome.
- **Logging pipelines fail silently.** Two of the four attacks produced nothing usable until I found a real misconfiguration. "The SIEM is set up" and "the SIEM is capturing what I think" turned out to be different claims.
- **Check `auditpol /get`, not just the GPO editor.** The legacy audit policy overrode my settings with no visible error.
- **Test every hunt query against a known attack.** The AS-REP query worked first time; the Kerberoasting one needed fixing.
- **Strong passwords really do stop offline cracking,** even when the protocol weakness is fully exploitable.

## What I'd do next

- Add Zeek or Suricata to see LLMNR poisoning at the network level.
- Find out why Sysmon Event IDs 3 and 22 aren't firing, instead of working around it.
- Turn the validated queries into version-controlled detections. I did this later in [Detection-Engineering](https://github.com/joshuagodwin7929/Detection-Engineering).
- Add alerting on top of the hunt queries, so I'm not searching by hand after the fact. Also done later, in [Purple-Team-Automation](https://github.com/joshuagodwin7929/Purple-Team-Automation).
- Spray several passwords per pass, staying under the lockout threshold, to study how sprayers avoid lockouts.

## Evidence

Credentials, internal IPs outside the lab range, and personal details are redacted.

### LLMNR/NBT-NS poisoning

**Responder capturing NTLMv2 hashes**
<img width="641" height="381" alt="01-responder-capture-01" src="https://github.com/user-attachments/assets/181402b3-e23b-4eb9-bba8-1d657364a8e3" />

<img width="529" height="384" alt="01-responder-capture-02" src="https://github.com/user-attachments/assets/05321957-eb21-406d-a6ab-a7389062b3e2" />

**Cracking: the test account cracked, the real accounts didn't**
<img width="535" height="383" alt="02-john-crack-result-01" src="https://github.com/user-attachments/assets/661f4e65-ceee-4547-94f6-7bc933902096" />

<img width="511" height="368" alt="02-john-crack-result-02" src="https://github.com/user-attachments/assets/78aff5e6-b4ee-410c-b282-be364fa3c629" />

### Password spraying

**NetExec spray: no valid credentials, and lockout messages**
<img width="607" height="378" alt="03-netexec-spray-01" src="https://github.com/user-attachments/assets/104ae5e3-b9f6-4b88-ae2f-3294583825f4" />

<img width="506" height="374" alt="03-netexec-spray-02" src="https://github.com/user-attachments/assets/677927d9-7dbe-4df8-bc42-34732b5a039d" />

**Failed logons (4625) in Kibana**
<img width="1280" height="584" alt="04-kibana-4625" src="https://github.com/user-attachments/assets/6c006674-5699-46d3-a9a0-04274cdf0e2d" />

**The legacy audit policy override, before and after the fix**
<img width="587" height="408" alt="05-auditpol-fix" src="https://github.com/user-attachments/assets/b826162f-94ae-45d2-8135-d30e8abaa315" />

### Kerberoasting

**Requesting the service ticket**
<img width="496" height="376" alt="06-getuserspns" src="https://github.com/user-attachments/assets/5eaaa3a4-282b-4c1c-a262-119e111ec419" />

**The RC4 hunt query in Kibana**
<img width="2556" height="1474" alt="07-kibana-4769" src="https://github.com/user-attachments/assets/f87d2f15-a3a0-4685-802b-90d4d401fc76" />

**Strong vs. weak password**
<img width="1076" height="760" alt="08-crack-comparison-01" src="https://github.com/user-attachments/assets/f8a0848d-a752-42ca-8eb9-8c766fea141e" />

<img width="1074" height="754" alt="08-crack-comparison-02" src="https://github.com/user-attachments/assets/a1e591e8-967c-4bf6-b474-1836d7381751" />

### AS-REP Roasting

**The AS-REP hash for the pre-auth-disabled account**
<img width="1079" height="749" alt="09-getnpusers" src="https://github.com/user-attachments/assets/0a79309c-e8c6-43ca-95ed-3941199c9f61" />

**The PreAuthType hunt query in Kibana**
<img width="1273" height="1118" alt="10-kibana-4768" src="https://github.com/user-attachments/assets/e82a229f-85e5-4663-a871-afa24cb17d6d" />

---

Previous: [Phase 0](../Phase-0-Visibility-Foundation) · Next: [Phase 2: Attack Path Mapping](../Phase-2-Attack-Path-Mapping) · Back to the [lab overview](../README.md)

*Everything here ran in an isolated lab I own.*
