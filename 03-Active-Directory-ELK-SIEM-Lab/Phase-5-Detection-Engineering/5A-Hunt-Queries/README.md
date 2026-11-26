# Phase 5A: Hunt Queries

After running the attacks in Phases 1 to 4, I went back through each one and worked out what it left in my logs, then wrote a KQL hunt query against the real events. Some techniques gave me a clean, validated query. Others left nothing host-based logging could catch, and I've written those up as honest gaps rather than pretending I had a detection.

The lab: a Windows Server 2022 DC and a domain-joined Windows 10 endpoint, Sysmon (SwiftOnSecurity config), PowerShell script-block and module logging, and Advanced Audit Policy, all shipping to a self-hosted Elastic Stack 8.12.0 via Winlogbeat. Attacks came from Kali.

Each technique links back to the phase where I ran it:

| # | Technique | Phase |
|---|-----------|-------|
| 1 | LLMNR/NBT-NS Poisoning | [Phase 1](../../Phase-1-Credential-Access) |
| 2 | Password Spraying | [Phase 1](../../Phase-1-Credential-Access) |
| 3 | Kerberoasting | [Phase 1](../../Phase-1-Credential-Access) |
| 4 | AS-REP Roasting | [Phase 1](../../Phase-1-Credential-Access) |
| 5 | BloodHound/SharpHound enumeration | [Phase 2](../../Phase-2-Attack-Path-Mapping) |
| 6 | Lateral movement via atexec | [Phase 3](../../Phase-3-Lateral-Movement) |
| 7 | DCSync | [Phase 4](../../Phase-4-DCSync-Golden-Ticket) |
| 8 | Golden Ticket | [Phase 4](../../Phase-4-DCSync-Golden-Ticket) |

---

## 1. LLMNR/NBT-NS Poisoning

**MITRE ATT&CK:** T1557.001, Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay

I ran Responder on the lab subnet (192.168.18.0/24). When a domain host's DNS lookup failed, it fell back to LLMNR/NBT-NS broadcast, Responder answered claiming to be the host, and the machine authenticated to it, handing over an NTLMv2 hash. I captured 4 hashes: a planted test account and three real ones (`Administrator`, `rose.diaz`, `sarah.connor`). Only the weak test account cracked against rockyou. The three real hashes held. Capture is guaranteed by the protocol; whether you can crack it is a separate problem that depends on password strength.

This is the one technique in the lab with a real detection gap, and I've documented it rather than papered over it.

I'd expect this from Sysmon Event ID 3 (network connection) for the outbound attempt to the fallback name, and Event ID 22 (DNS query) for the failed lookup that preceded the broadcast. But Sysmon 3 and 22 weren't firing on `MY-LAB-PC`, even though the SwiftOnSecurity config ships with those rules enabled. I haven't fully isolated the cause yet (config not reloading cleanly, or a filtering rule suppressing the traffic), so it's an open finding. As configured today, this attack is invisible to the host-based pipeline. There is no Windows Security event that natively logs "a broadcast name-resolution protocol answered a query." This is a Layer 2/3 problem that host logging was never well suited to.

Once Sysmon 3/22 visibility is fixed, this would catch the failed lookup that precedes a fallback:

```
event.code:22 and winlog.event_data.QueryStatus:"9003" and
  not winlog.event_data.QueryName:*.joshua.local
```

(`QueryStatus 9003` is DNS name-not-found.) Paired with responses arriving from something that isn't the DC on LLMNR (UDP 5355) or NBT-NS (UDP 137):

```
event.code:3 and destination.port:(5355 or 137) and
  not source.ip:192.168.18.50
```

The real fix here is prevention: a network sensor (Zeek or Suricata) watching for LLMNR/NBT-NS responses from non-authoritative hosts, or just disabling LLMNR and NBT-NS by GPO where legacy apps allow it.

False positives: legitimate multicast name resolution is still common for print discovery and older file sharing, so a rule needs a baseline of expected responders. A single failed DNS lookup isn't suspicious on its own; the signal is volume plus the authentication that immediately follows.

---

## 2. Password Spraying

**MITRE ATT&CK:** T1110.003, Brute Force: Password Spraying

I used NetExec (`netexec smb 192.168.18.50 -u users.txt -p 'Summer2026!'`) to try one password against all 15 harvested usernames over SMB. No valid credentials. The lockout threshold of 5 fired cleanly on two accounts (`angela.martin`, `marcus.holloway`) after repeated failures: four `STATUS_LOGON_FAILURE` then `STATUS_ACCOUNT_LOCKED_OUT`, matching the policy.

The events:

- **4625** (failed logon) on the DC, one per sprayed user. Low volume per user spread across many usernames is the spray signature, as opposed to a brute force, which is high volume against one user.
- **4740** (account locked out) on the DC once the threshold is hit.
- Useful fields: `LogonType` (3 = network, consistent with SMB), `TargetUserName`, `IpAddress`.

```
event.code:4625 and winlog.event_data.LogonType:"3" and
  winlog.event_data.IpAddress:"<kali-ip>"
```

To see the spray pattern rather than a single failure, this needs a cardinality aggregation in a Lens or TSVB panel: distinct `TargetUserName` per source IP over a rolling 5-minute window. One source IP touching more than about 5 distinct usernames with only 1-2 failures each is the signature, not a raw 4625 count.

False positives: a service account with an expired password that many machines keep retrying creates a similar low-and-slow pattern, so filter those or correlate against a password-expiry report. A user who mistypes once and gets logged out of several cached sessions at once can trip a naive per-IP-per-user threshold; the distinct-username cardinality check is what separates spraying from ordinary error.

**The gap I hit here is worth stating on its own:** the DC's Winlogbeat config had `output.elasticsearch` fully commented out and a stale post-migration IP, so the 4625s from this exact attack never reached Kibana until I found and fixed it. A detection is only as good as the pipeline under it. The query above was correct from day one and useless while the beat wasn't forwarding. Confirming end-to-end pipeline health, not just query syntax, is now a standing check before I trust any "no hits" result as a true negative.

---

## 3. Kerberoasting

**MITRE ATT&CK:** T1558.003, Steal or Forge Kerberos Tickets: Kerberoasting

I created a service account (`svc_sql`) with an SPN (`MSSQLSvc/joshua-server2022.joshua.local:1433`) to have a legitimate target, then requested its ticket with `impacket-GetUserSPNs`. It failed first with `KDC_ERR_ETYPE_NOSUPP`, because the account's `msDS-SupportedEncryptionTypes` defaulted to AES-only. The domain doesn't hand out crackable RC4 tickets by default, which is itself a good finding. I force-enabled RC4 (`msDS-SupportedEncryptionTypes=4`) to get a crackable `$krb5tgs$23$` hash. It cracked instantly once I reset the password to a weak value; the original resisted both a plain rockyou pass and a rules-based John pass.

The events:

- **4769** (service ticket requested) on the DC, logged for every TGS-REQ, legitimate or not.
- Key field: `TicketEncryptionType`. `0x17` (RC4-HMAC) requested for a service account is the anomaly on an AES-enforced domain; `0x12`/`0x11` are AES256/AES128 and expected.
- Also useful: `ServiceName`. Repeated 4769s for many different SPNs from one account in a short window is the "enumerate every SPN" signature of a full roast sweep. This lab only requested one, so I didn't generate that pattern; worth simulating separately.

```
event.code:4769 and winlog.event_data.TicketEncryptionType:"0x17"
```

Validated live against the lab: it returned only the `svc_sql` RC4 request, zero false positives from normal traffic, which also confirmed the domain really is AES-only end to end.

For the sweep variant, aggregate the same query by `TargetUserName` (the requesting account) with a distinct count of `ServiceName`; a spike above 3-5 distinct SPNs per account per minute is the sweep.

False positives: legacy apps or printers that only support RC4 generate the same signal legitimately, so an allowlist of known-legacy SPNs avoids fatigue. A domain that hasn't enforced AES will see RC4 constantly and needs to pivot to ticket request fan-out instead of encryption type. A single RC4 4769 is low-signal in a mixed environment; it's high-signal here specifically because this domain enforces AES, so any RC4 request is a policy violation on its own.

---

## 4. AS-REP Roasting

**MITRE ATT&CK:** T1558.004, Steal or Forge Kerberos Tickets: AS-REP Roasting

I created `j.jenkins` with `DoesNotRequirePreAuth` set, simulating a misconfigured account, and ran `impacket-GetNPUsers`. Because pre-authentication was disabled, the KDC handed back an encrypted AS-REP without any prior proof of knowing the password, giving a crackable `$krb5asrep$` hash with none of my own credentials required (unlike Kerberoasting, which needs a valid login first). It cracked the same way: the real password held, a weak reset cracked instantly.

The events:

- **4768** (TGT requested) on the DC.
- Key field: `PreAuthType`. `0` means no pre-auth data was used, which is the roasting signature. Normal logons show `2` (encrypted timestamp pre-auth).

```
event.code:4768 and winlog.event_data.PreAuthType:"0"
```

Validated cleanly on the first try: 4 hits, all correctly attributed to `j.jenkins`, no field-name guessing needed (unlike the Kerberoasting query, where I had to confirm the exact field first).

False positives: this query has an unusually low false-positive rate. `PreAuthType:0` is almost never legitimate in a modern domain, so any hit deserves investigation. The rare legitimate case is a small number of intentionally pre-auth-disabled accounts kept for old Kerberos/UNIX clients; enumerate and allowlist those (`Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}`) so any other account triggering this is unambiguous. Because the attack needs no credentials at all, the real fix is prevention: find and eliminate `DoesNotRequirePreAuth` accounts domain-wide.

---

## 5. BloodHound/SharpHound AD Enumeration

**MITRE ATT&CK:** T1087.002 (Account Discovery), T1069.002 (Permission Groups Discovery), T1018 (Remote System Discovery). SharpHound's collection touches all three as it pulls users, groups, ACLs, sessions and trusts via LDAP and SAMR/RPC.

I ran SharpHound v2.14.0 (`-c All`) from a low-privileged domain-joined Windows 10 client, using only the access a compromised standard user would have. I moved the data by SCP to a self-hosted BloodHound CE instance on a separate Ubuntu box, then used a Cypher `shortestPath` query rather than the GUI pathfinder to confirm a directional path from a low-privileged user to Domain Admins. That finding shaped the rest of the chain.

This is the weakest detection surface in the lab, and I want to be honest about that. SharpHound's collection is almost entirely LDAP reads and SAMR/RPC enumeration, most of which looks identical to normal domain-joined-machine chatter.

- **4661** (handle to an object requested) with an `ObjectType` of `SAM_DOMAIN`/`SAM_GROUP`, generated on the DC when SAMR enumeration hits it.
- **5156** (WFP permitted connection) or firewall logs showing one workstation opening a high volume of LDAP (389) connections in a short window.
- If LDAP query auditing is enabled: search filters that enumerate `objectClass=user` or `objectClass=group` domain-wide in one session, rather than the narrow single-object lookups normal apps do.

```
event.code:4661 and winlog.event_data.ObjectType:("SAM_DOMAIN" or "SAM_GROUP")
```

Aggregate by `SubjectUserName` and source workstation, looking for one account generating an abnormally high count in a short window. A full SharpHound collection generates thousands of these in minutes; a normal user session generates a handful per hour at most.

False positives: legitimate AD-integrated tools (backup software, vulnerability scanners) do similarly broad enumeration, so you need an allowlist of known scanner service accounts and their schedule, or every recon run and every Nessus scan alerts identically. Volume thresholds need tuning per environment size. Honestly, the practical recommendation here is Microsoft Defender for Identity or equivalent, which is built to baseline LDAP/SAMR recon; a generic SIEM rule on raw event counts will be noisy in most real environments.

---

## 6. Lateral Movement via atexec

**MITRE ATT&CK:** T1021.002 (Remote Services: SMB/Windows Admin Shares) plus T1569.002 (Service Execution via the Task Scheduler fallback) and T1078.002 (Valid Accounts) for the local-admin abuse that made it possible.

I granted `j.jenkins` (and three others) local admin on `MY-LAB-PC` via a scoped GPO restricted by Security Filtering, after BloodHound showed no existing admin path. NetExec hit `Pwn3d!` confirming admin access, then tried WMIEXEC for code execution, which failed on DCOM, and auto-fell-back to atexec (abusing the Task Scheduler RPC interface via `svchost.exe -k netsvcs`) to run `whoami`, returning `NT AUTHORITY\SYSTEM`. I also found and fixed a real gap on the way: the Domain-profile SMB-In firewall rule was disabled on `MY-LAB-PC`, silently blocking the initial connection.

Three artifacts, chained by timestamp, make this one strong. No single one is conclusive alone:

1. **4624** (logon) on `MY-LAB-PC`, Type 3 (network), for `j.jenkins`, with `Elevated Token: Yes`, the tell that this network logon uses an administrative token.
2. **Sysmon Event ID 1** (process create) for `whoami.exe`, parent `cmd.exe`, grandparent `svchost.exe -k netsvcs -p`. That lineage is the atexec signature, distinct from a user running whoami by hand.
3. Sysmon's command line showing output redirected to a random filename under `\Windows\Temp`, which is how atexec retrieves output since Task Scheduler has no stdout channel.

In the lab, artifact 2 landed 61 milliseconds after artifact 1. That tight timing is itself a signal; a human logging on and running a command takes seconds, not milliseconds.

```
event.code:1 and process.parent.name:"svchost.exe" and
  process.parent.command_line:"*netsvcs*" and
  process.name:"cmd.exe"
```

Correlated against elevated-token network logons:

```
event.code:4624 and winlog.event_data.LogonType:"3" and
  winlog.event_data.ElevatedToken:"%%1842"
```

Joined on `TargetUserName` and a tight time window. Kibana doesn't join across indices in Discover, so this is best expressed as two panels on one dashboard with a shared time filter, or a transform/watcher if you want a single alert.

False positives: legitimate scheduled tasks and some monitoring agents also spawn `cmd.exe` under `svchost.exe -k netsvcs`, so baseline your own admin tooling first. An elevated-token Type 3 logon on its own is completely normal for remote-admin workflows (RSAT, SCCM, patching); it's only suspicious paired with the atexec lineage and an unexpected account. The `\Windows\Temp\<random>` redirection pattern is higher-confidence than the lineage alone, since legitimate tasks rarely redirect output that way.

---

## 7. DCSync

**MITRE ATT&CK:** T1003.006, OS Credential Dumping: DCSync

With `j.jenkins`'s local admin on `MY-LAB-PC`, I extracted the NTLM hash of a cached Administrator session via `lsassy` (I had to disable Defender real-time protection first; both lsassy and handlekatz failed against active EDR). I then Pass-the-Hash'd that hash into `impacket-secretsdump -just-dc-user krbtgt`, which impersonates a DC's replication rights to request `krbtgt`'s secrets from the real DC, extracting its NTLM, AES256 and AES128 keys plus the domain SID, without ever touching the real Administrator password.

This is the most important finding in the lab, and it's a negative result: **DCSync produced zero events.**

- I'd expect **4662** (operation on an object) on the DC, specifically for the `DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All` extended rights, the two permissions DCSync abuses.
- But Directory Service Access auditing was never enabled in this domain, so no 4662 was ever generated for this action, on this DC, by this account. This is a configuration gap, not a shipping bug like the earlier ones.
- What survived instead: exactly one artifact, a single normal-looking **4624 Type 3 Kerberos logon** from the Kali IP, with no preceding 4768 (the Pass-the-Hash/replication call doesn't request a ticket the way an interactive logon would). On its own, that event is indistinguishable from a legitimate admin logon.

Once 4662 auditing is enabled:

```
event.code:4662 and
  winlog.event_data.Properties:("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" or
                                 "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2")
```

(the two GUIDs are `DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All`) filtered to exclude the real DC computer accounts. Any account other than a legitimate DC requesting these rights is a DCSync attempt by definition.

The fix I later implemented (see [5B](../5B-Closing-The-Detection-Gaps/Gap-1-DCSync-No-Audit-Trail/README.md)):

1. Enable Directory Service Access auditing with an object-level SACL on the domain root, filtered to the two replication GUIDs, so the query above has data to run against.
2. Deploy a network or identity sensor (Microsoft Defender for Identity, or Zeek watching DRSUAPI/RPC). This is a protocol-level abuse of a legitimate DC-to-DC mechanism, and host logging on the victim workstation was never going to catch it, since the malicious call happens DC-side.
3. As a compensating control, add a 4769-without-preceding-4768 baseline rule, a general Pass-the-Hash heuristic that would have flagged this chain's surviving artifact.

False positives: real DC-to-DC replication uses these same rights constantly, so the query must exclude known DC computer accounts. Some AD-aware backup tools use DCSync-equivalent calls and need allowlisting by service account.

---

## 8. Golden Ticket

**MITRE ATT&CK:** T1558.001, Steal or Forge Kerberos Tickets: Golden Ticket

Using the `krbtgt` AES256 key and domain SID from DCSync, I forged a Golden Ticket with `impacket-ticketer`, granting full self-issued Domain Admin access with no knowledge of any real Administrator password. It took three attempts, and each failure taught me something:

1. A fake account name was rejected with `KDC_ERR_TGT_REVOKED`, because of CVE-2021-42287 (PAC account-existence validation), which is patched on this Server 2022 DC. A positive finding; an unpatched DC would have accepted a ticket for a made-up user.
2. An RC4-encrypted forged ticket was rejected because the domain enforces AES-only Kerberos (the same policy finding from Kerberoasting). Another control working as intended.
3. Success came only from the real `krbtgt` AES256 key plus a real, existing account name (`Administrator`).

A forged ticket never touches the DC's TGT issuance path; it's minted offline, so there's no 4768. The only artifact is what appears when the ticket is used: a single **4624 Type 3 Kerberos logon**, the same surviving artifact as DCSync, and the single point where this whole chain intersects host-based logging.

Since no forging-specific event exists, the only viable detection is the same cross-reference as DCSync:

```
event.code:4624 and winlog.event_data.LogonType:"3" and
  winlog.event_data.AuthenticationPackageName:"Kerberos"
```

Correlated against the absence of a matching 4768 for the same `TargetUserName` within a prior window (10 hours, the default ticket lifetime, or longer if `ticketer` was given a custom duration). Kibana can't express "absence of a correlated event" as a single KQL filter, so this needs a scheduled transform comparing two rolling counts, or a watcher with a lookback join. I ended up writing it as a Python script, documented in [5B Gap 2](../5B-Closing-The-Detection-Gaps/Gap-2-Golden-Ticket-No-Tripwire/README.md).

Defensive controls from this lab:

1. Rotate the `krbtgt` password twice, spaced by the max ticket lifetime, to invalidate outstanding forged tickets. This is the only true remediation once `krbtgt` is believed compromised.
2. Enable 4662 DS-Access auditing with replication-GUID filters (see DCSync) to catch the theft before it becomes a forged ticket.
3. Deploy the 4769-without-preceding-4768 rule as a compensating control for the whole ticket-forging class.
4. Enforce AES-only Kerberos domain-wide (already in place here). It didn't prevent the attack, but it added a real speed bump and would stop legacy tooling that can't forge AES tickets at all.

False positives: the 4624-without-4768 heuristic will also flag legitimate Kerberos logons using cached or renewed tickets whose original 4768 fell outside the lookback, so tune the window to exceed your max ticket lifetime. Some cross-forest trust logons also show Kerberos auth without a locally visible 4768, since the TGT was issued by a different DC; centralize logging across all DCs before trusting this rule alone.

---

## Building the Kibana dashboard

Kibana dashboards are built in the UI (Stack Management → Saved Objects can export/import them as NDJSON if you want the dashboard itself as a portfolio artifact, but the panels have to be built live against the `winlogbeat-*` data view). Here's the exact panel list to reproduce mine, since I can't create Kibana objects from code.

I built four panels, one per strong signal.

**Panel 1, Kerberoasting RC4 requests over time**
- Lens, vertical bar
- Query: `event.code:4769 and winlog.event_data.TicketEncryptionType:"0x17"`
- X-axis: `@timestamp` date histogram; Y-axis: Count; break down by `TargetUserName.keyword` (top 5)
- This is the validated, zero-false-positive query, so it's the clean win to lead with.

**Panel 2, AS-REP PreAuthType 0 requests**
- Lens, vertical bar
- Query: `event.code:4768 and winlog.event_data.PreAuthType:"0"`
- X-axis: date histogram; break down by `TargetUserName.keyword`

**Panel 3, password spray by source IP (cardinality)**
- Lens, table
- Query: `event.code:4625 and winlog.event_data.LogonType:"3"`
- Rows: `IpAddress.keyword`; metrics: Count and Unique Count of `TargetUserName.keyword`
- Sort by unique-user-count descending. A source IP touching 5+ distinct usernames is the spray signature, which a plain count-over-time chart hides.

**Panel 4, lateral movement (elevated logons + atexec)**
- Lens, vertical bar, two series:
  - A: `event.code:4624 and winlog.event_data.LogonType:"3" and winlog.event_data.ElevatedToken:"%%1842"`
  - B: `event.code:1 and process.parent.command_line:*netsvcs*`
- X-axis: date histogram, 1-minute interval, so the millisecond correlation is visible when zoomed to the attack window.

Dashboard-level:
- Set the default time range to cover the full attack timeline, so it tells a story when opened instead of showing an empty "last 15 minutes."
- Add a markdown panel at the top with a two or three line caption per detection. That's what turns four charts into a narrative for someone skimming.
- Skip DCSync and Golden Ticket from the dashboard itself. They produce no visualizable signal in the current config, and a panel that's empty by design reads as a bug unless captioned. Better to reference that gap in the [incident report](../../Phase-6-Incident-Report) than force an empty chart on.

To export: Stack Management → Saved Objects → find the dashboard → Export. That NDJSON is worth including alongside these write-ups; it lets anyone with an ELK stack import and see the dashboard, not just a screenshot.

---

Back to [Phase 5](../README.md) · Next: [5B: Closing the Detection Gaps](../5B-Closing-The-Detection-Gaps/README.md)
