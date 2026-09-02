Phase 5: Detection Engineering & Write-Up

A self-hosted Active Directory attack/defense lab (Sysmon + Winlogbeat + Elastic Stack)
covering credential access, attack-path mapping, lateral movement, and domain persistence
techniques, paired with the detections (and detection gaps) each one produces.

**Lab environment:** Windows Server 2022 DC + Windows 10 endpoint, domain-joined, Sysmon
(SwiftOnSecurity config) + PowerShell Script Block/Module Logging + Advanced Audit Policy,
shipping to a self-hosted Elastic Stack 8.12.0 (Elasticsearch + Kibana + Logstash) via
Winlogbeat. Attacks executed from Kali Linux.

## Table of Contents
- [Detection Notes](#detection-notes)

  - [1. LLMNR/NBT-NS Poisoning](../Phase-1-Credential-Access)
  - [2. Password Spraying](../Phase-1-Credential-Access)
  - [3. Kerberoasting](../Phase-1-Credential-Access)
  - [4. AS-REP Roasting](../Phase-1-Credential-Access)
  - [5. BloodHound/SharpHound AD Enumeration](../Phase-2-Attack-Path-Mapping)
  - [6. Lateral Movement via atexec](../Phase-3-Lateral-Movement)
  - [7. DCSync](../Phase-4-DCSync-Golden-Ticket)
  - [8. Golden Ticket](../Phase-4-DCSync-Golden-Ticket)
- [Kibana Dashboard Build Guide](../Phase-5-Detection-Engineering)
- [Incident Report — Full Attack Chain](../Incident-Report-Write-Up)

---

## Detection Notes

### 1. LLMNR/NBT-NS Poisoning


**MITRE ATT&CK:** T1557.001 — Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay

### What I Did (Attacker View)
From Kali, ran Responder in analyze/poison mode on the shared lab subnet
(192.168.18.0/24). When a domain host mistyped a share name or hostname
and the DNS lookup failed, it fell back to LLMNR/NBT-NS broadcast
resolution. Responder answered those broadcast queries claiming to be
the requested host, and the querying machine authenticated to it directly,
handing over an NTLMv2 hash. Captured 4 hashes total (a planted test
account plus three real accounts: `Administrator`, `rose.diaz`,
`sarah.connor`). Cracked only the intentionally weak test account against
`rockyou.txt` with John the Ripper — the three real-account hashes
resisted the full wordlist, confirming that **capture is guaranteed by the
protocol design; cracking success is a separate, password-strength-dependent
problem.**

### Log Source & Event ID
This is the one technique in the lab with an **honest detection gap**,
documented rather than papered over:

- **Intended source:** Sysmon Event ID 3 (Network Connection) for the
  outbound connection attempt to the fallback name, and Event ID 22
  (DNS Query) showing the failed forward-DNS lookup that preceded the
  broadcast fallback.
- **Actual status:** Sysmon Event ID 3 and 22 were **not firing** on the
  victim endpoint (`MY-LAB-PC`) despite the SwiftOnSecurity config
  shipping with NetworkConnect/DnsQuery rules enabled. Root cause not
  yet fully isolated (config not reloading cleanly, or a filtering rule
  suppressing the traffic) — logged as an open finding, not silently
  worked around.
- **Consequence:** as configured today, this attack is **invisible** to
  the host-based Winlogbeat → Elasticsearch pipeline. There is no
  Windows Security Event ID that natively logs "a broadcast name
  resolution protocol answered a query" — this is fundamentally a
  Layer 2/3 problem that host EDR was never well-suited to catch.

### KQL (once Sysmon 3/22 visibility is fixed)
```
event.code:22 and winlog.event_data.QueryStatus:"9003" and
  not winlog.event_data.QueryName:*.joshua.local
```
(`QueryStatus 9003` = DNS name not found, immediately preceding an
LLMNR/NBT-NS fallback.) Pair with:
```
event.code:3 and destination.port:(5355 or 137) and
  not source.ip:192.168.18.50
```
to catch responses arriving from a host that isn't the DC/DNS server on
LLMNR (UDP 5355) or NBT-NS (UDP 137).

### The Real Fix — Recommended Detection Architecture
Host logging alone cannot reliably catch this class of attack. The
correct control is a **network-layer sensor** (Zeek/Suricata) with a
signature for LLMNR/NBT-NS responses from non-authoritative hosts, or
simply **disabling LLMNR and NBT-NS via GPO** where legacy application
compatibility allows it — the strongest fix is prevention, not detection.

### False-Positive Considerations
- Legitimate multicast name resolution is common on networks that still
  rely on it for print discovery or older file-sharing tools; a poisoning
  detection rule needs a baseline of "expected responders" (print
  servers, NAS devices) to avoid alerting on every LLMNR reply.
- A single failed DNS lookup (QueryStatus 9003) is not itself suspicious;
  volume and the immediate authentication that follows it are the signal.


---

### 2. Password Spraying


**MITRE ATT&CK:** T1110.003 — Brute Force: Password Spraying

### What I Did (Attacker View)
From Kali, used NetExec (`netexec smb 192.168.18.50 -u users.txt -p
'Summer2026!'`) to try one password against all 15 harvested domain
usernames via SMB. Zero valid credentials found. The Default Domain
Password Policy lockout threshold of 5 triggered cleanly on two accounts
(`angela.martin`, `marcus.holloway`) after repeated failed attempts —
4x `STATUS_LOGON_FAILURE` then `STATUS_ACCOUNT_LOCKED_OUT`, matching the
configured policy.

### Log Source & Event ID
- **Event ID 4625** (An account failed to log on) on the Domain
  Controller — one per sprayed user per password. Low volume per user,
  distributed across many usernames, is the spray signature (as opposed
  to a brute force, which is high volume against one user).
- **Event ID 4740** (A user account was locked out) — should fire on
  the DC once the threshold is hit.
- **Field of interest:** `winlog.event_data.LogonType` (3 = network,
  consistent with SMB), `winlog.event_data.TargetUserName`,
  `winlog.event_data.IpAddress` (source of the spray).

### Kibana/KQL Query
```
event.code:4625 and winlog.event_data.LogonType:"3" and
  winlog.event_data.IpAddress:"<kali-ip>"
```
To surface the spray *pattern* rather than a single failure, this needs
a **cardinality aggregation** in a Kibana Lens/TSVB panel: count of
distinct `winlog.event_data.TargetUserName` values per source IP over a
rolling 5-minute window. A single source IP touching more than ~5 distinct
usernames in a short window, each with only 1–2 failures, is the spray
signature — not a raw `event.code:4625` count.

### False-Positive Considerations
- Service accounts with an expired password that many machines still try
  to use can create a similar low-and-slow, multi-target failure pattern
  — filter these accounts or correlate against a password-expiry report.
- Users who mistype their password once and get logged out of multiple
  cached sessions simultaneously (VPN + email + VDI) can trip a naive
  per-IP-per-user threshold; the distinct-username cardinality check
  is what actually separates spraying from ordinary user error.

### Operational Note (from this lab)
I hit a real detection gap here worth writing up on its own: the DC's
Winlogbeat shipping config had `output.elasticsearch` fully commented
out plus a stale post-migration IP, so the 4625s from this exact attack
never reached Kibana until I found and fixed the pipeline. **A detection
is only as good as the shipping pipeline underneath it** — the query
above was correct from day one, but useless while the beat wasn't
actually forwarding data. Confirming end-to-end pipeline health (not
just query syntax) is now a standing checklist item before trusting any
"no hits" result as a true negative.


---

### 3. Kerberoasting


**MITRE ATT&CK:** T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting

### What I Did (Attacker View)
Created a service account (`svc_sql`) with an SPN
(`MSSQLSvc/joshua-server2022.joshua.local:1433`) to have a legitimate
target, then requested its service ticket with `impacket-GetUserSPNs`
for offline cracking. Hit `KDC_ERR_ETYPE_NOSUPP` initially because the
account's `msDS-SupportedEncryptionTypes` defaulted to AES-only — this
domain doesn't hand out crackable RC4 tickets by default, which is
itself a positive security finding. Force-enabled RC4
(`msDS-SupportedEncryptionTypes=4`) to obtain a crackable
`$krb5tgs$23$` hash. Cracked it instantly once the account's password
was reset to a weak value (`Password1!`); the original password
(`Summer2026!`) resisted both a plain rockyou pass and a rules-based
John pass.

### Log Source & Event ID
- **Event ID 4769** (A Kerberos service ticket was requested) on the DC
  — logged for every TGS-REQ, legitimate or not.
- **Key field:** `winlog.event_data.TicketEncryptionType`. A value of
  `0x17` (RC4-HMAC) requested for a service account is the anomaly on an
  AES-enforced domain; `0x12`/`0x11` are AES256/AES128 and expected.
- **Also useful:** `winlog.event_data.ServiceName` — repeated 4769s for
  many *different* SPNs from a single requesting account in a short
  window is the "enumerate every SPN in the domain" signature of a full
  Kerberoast sweep (this lab only requested one, so that pattern wasn't
  generated here — worth simulating separately).

### Kibana/KQL Query
```
event.code:4769 and winlog.event_data.TicketEncryptionType:"0x17"
```
Validated live against this lab — correctly and only returned the
`svc_sql` RC4 ticket request, with zero false positives from normal
domain traffic (confirming the domain really is AES-only end to end).

For the sweep variant:
```
event.code:4769 and winlog.event_data.TicketEncryptionType:"0x17"
```
aggregated by `winlog.event_data.TargetUserName` (the requesting
account) with a distinct-count of `winlog.event_data.ServiceName` — a
spike above 3–5 distinct SPNs per account per minute is the roast sweep.

### False-Positive Considerations
- Legacy applications or older printers/appliances that only support
  RC4 will generate the same ticket-encryption-type signal legitimately
  — an allowlist of known-legacy SPNs avoids alert fatigue.
- Environments that haven't enforced AES-only Kerberos (unlike this lab)
  will see RC4 constantly and need to pivot the detection to *ticket
  request volume/fan-out* instead of encryption type alone.
- A single 4769 with RC4 for one account is low-signal in a mixed
  environment; it becomes high-signal specifically because this domain
  enforces AES by policy, making any RC4 request a policy violation on
  its own.


---

### 4. AS-REP Roasting


**MITRE ATT&CK:** T1558.004 — Steal or Forge Kerberos Tickets: AS-REP Roasting

### What I Did (Attacker View)
Created an account (`j.jenkins`) with `DoesNotRequirePreAuth` set,
simulating a misconfigured account. Ran `impacket-GetNPUsers` against
the domain — because Kerberos pre-authentication was disabled, the KDC
handed back an encrypted AS-REP without requiring any prior proof of
knowing the password, giving a crackable `$krb5asrep$` hash with **zero
credentials of my own required** (unlike Kerberoasting, which needs a
valid login first). Cracked it the same way: real password
(`Autumn2026!`) resisted wordlist+rules; reset to `Password1!` cracked
instantly.

### Log Source & Event ID
- **Event ID 4768** (A Kerberos authentication ticket (TGT) was
  requested) on the DC.
- **Key field:** `winlog.event_data.PreAuthType`. A value of `0` means
  no pre-authentication data was used — the AS-REP roasting signature.
  Normal logons show `2` (encrypted timestamp pre-auth).

### Kibana/KQL Query
```
event.code:4768 and winlog.event_data.PreAuthType:"0"
```
Validated cleanly on first try in this lab — 4 hits, all correctly
attributed to `j.jenkins`, no field-name guessing needed (unlike the
Kerberoasting query, which required confirming the exact field name
first).

### False-Positive Considerations
- This query has an unusually low false-positive rate compared to most
  Kerberos detections: `PreAuthType:0` is almost never legitimate in a
  modern, correctly configured domain. Any hit deserves investigation.
- The rare legitimate case is a small number of intentionally
  pre-auth-disabled accounts kept for compatibility with old
  Kerberos/UNIX clients that don't support pre-auth — these should be
  enumerated and allowlisted (`Get-ADUser -Filter
  {DoesNotRequirePreAuth -eq $true}`) so any *other* account triggering
  this is unambiguous.
- Because the attack requires no valid credentials at all, the true fix
  is prevention: audit for and eliminate `DoesNotRequirePreAuth` accounts
  domain-wide rather than relying on detection alone.


---

### 5. BloodHound/SharpHound AD Enumeration


**MITRE ATT&CK:** T1087.002 (Account Discovery: Domain Account) /
T1069.002 (Permission Groups Discovery: Domain Groups) /
T1018 (Remote System Discovery) — SharpHound's collection touches all
three as it pulls users, group memberships, ACLs, sessions, and trust
data via LDAP and SAMR/RPC.

### What I Did (Attacker View)
Ran SharpHound v2.14.0 (`-c All`, full collection) from a low-privileged
domain-joined Windows 10 client — deliberately using only the access
level a compromised standard user session would have. Data was moved
host-to-host via SCP to a self-hosted BloodHound CE instance (Neo4j +
PostgreSQL, Docker Compose) on a separate Ubuntu box. Used a Cypher
`shortestPath` query rather than the GUI pathfinder to confirm a
directional privilege-escalation path from a low-privileged user to
Domain Admins — the finding that shaped the rest of the attack chain
(Phase 3 onward).

### Log Source & Event ID
SharpHound's collection is almost entirely **LDAP reads and SAMR/RPC
session/group enumeration** — most of it looks identical to normal
domain-joined-machine chatter (GPO processing, Group Policy refresh,
account lookups), which is what makes this technique hard to catch and
a good one to be honest about in a write-up.
- **Event ID 4661** (A handle to an object was requested) with an
  `ObjectType` of `SAM_DOMAIN`/`SAM_GROUP`, generated on the DC when
  SAMR enumeration hits it.
- **Event ID 5156** (Windows Filtering Platform permitted connection)
  or firewall logs showing a single workstation opening a high volume
  of LDAP (389) connections in a short window.
- **LDAP-specific field of interest** (if LDAP query auditing/`Directory
  Service Changes` diagnostics logging is enabled): search filters that
  enumerate `objectClass=user` or `objectClass=group` domain-wide in one
  session, rather than the narrow single-object lookups normal
  applications perform.

### Kibana/KQL Query
```
event.code:4661 and winlog.event_data.ObjectType:("SAM_DOMAIN" or "SAM_GROUP")
```
aggregated by `winlog.event_data.SubjectUserName` and source workstation,
looking for a single account generating an abnormally high count in a
short window (SharpHound's full collection generates thousands of these
in minutes — a normal user session generates a handful per hour at most).

### False-Positive Considerations
- Legitimate AD-integrated tools (backup software, vulnerability
  scanners, other security tooling) perform similarly broad LDAP/SAMR
  enumeration — an allowlist of known scanner service accounts and
  their expected schedule is necessary, or every recon run and every
  Nessus scan will alert identically.
- Volume-based thresholds need tuning per environment size; a 500-user
  domain and a 50,000-user domain generate very different "normal"
  enumeration baselines from IT tooling.
- This is the weakest detection surface in the whole chain — the
  practical recommendation is **Microsoft Defender for Identity** or
  equivalent, which is purpose-built to baseline LDAP/SAMR reconnaissance
  patterns; a generic SIEM rule on raw event counts will be noisy in
  most real environments.


---

### 6. Lateral Movement via atexec


**MITRE ATT&CK:** T1021.002 (Remote Services: SMB/Windows Admin Shares)
+ T1569.002 (System Services: Service Execution, via the Task Scheduler
fallback) — plus T1078.002 (Valid Accounts: Domain Accounts) for the
local-admin abuse that made it possible.

### What I Did (Attacker View)
Simulated a real-world misconfiguration: granted `j.jenkins` (plus three
other accounts) local admin on `MY-LAB-PC` via a scoped GPO restricted
by Security Filtering, after BloodHound showed no existing admin path.
Ran NetExec against `MY-LAB-PC` as `j.jenkins` — first hit "Pwn3d!"
confirming admin access, then NetExec attempted `WMIEXEC` for code
execution, which failed on DCOM, and **auto-fell-back to `atexec`**
(abuses the Task Scheduler RPC interface via `svchost.exe -k netsvcs`)
to run `whoami`, returning `NT AUTHORITY\SYSTEM`. Also found and fixed a
real gap along the way: the Domain-profile "File and Printer Sharing
(SMB-In)" firewall rule was disabled on `MY-LAB-PC`, silently blocking
the initial SMB connection until corrected.

### Log Source & Event ID
Three artifacts, chained by timestamp, is what makes this detection
strong — no single one is fully conclusive alone:
1. **Event ID 4624** (Logon) on `MY-LAB-PC`, Logon Type 3 (Network), for
   `j.jenkins`, with `Elevated Token: Yes` — the tell that this network
   logon is using an administrative token, not a standard one.
2. **Sysmon Event ID 1** (Process Create) for `whoami.exe`, with parent
   `cmd.exe` and grandparent `svchost.exe -k netsvcs -p` — this specific
   process lineage (svchost spawning cmd spawning the executed command)
   is the atexec/Task Scheduler signature, distinct from a user
   double-clicking whoami or a normal script running it.
3. Sysmon's command-line field showing **output redirected to a random
   filename under `\Windows\Temp`** — atexec's mechanism for retrieving
   command output, since Task Scheduler itself has no stdout channel.

In this lab, artifact #2 landed **61 milliseconds** after artifact #1 —
that tight timing correlation is itself a detection signal (a human
admin logging on and then manually running a command takes seconds, not
milliseconds).

### Kibana/KQL Query
```
event.code:1 and process.parent.name:"svchost.exe" and
  process.parent.command_line:"*netsvcs*" and
  process.name:"cmd.exe"
```
Correlated in a second panel/query against:
```
event.code:4624 and winlog.event_data.LogonType:"3" and
  winlog.event_data.ElevatedToken:"%%1842"
```
(elevated-token network logons), joined on `winlog.event_data.TargetUserName`
and a tight time window (Kibana doesn't natively join across indices in
Discover — this pairing is best expressed as two panels on one
dashboard with a shared time filter, or a transform/watcher if you want
a single alert).

### False-Positive Considerations
- Legitimate scheduled tasks and some monitoring agents also spawn
  `cmd.exe` under `svchost.exe -k netsvcs` — baseline your own admin
  tooling's process trees before treating every instance as malicious.
- An elevated-token Type 3 logon by itself is completely normal for any
  legitimate remote-admin workflow (RSAT, SCCM, patch management) — it's
  only suspicious paired with the atexec process-lineage signature and
  an account that isn't a known admin-tooling service account.
- The specific `\Windows\Temp\<random>` output-redirection pattern is a
  higher-confidence indicator than the process lineage alone, since
  legitimate scheduled tasks rarely redirect output that way.


---

### 7. DCSync


**MITRE ATT&CK:** T1003.006 — OS Credential Dumping: DCSync

### What I Did (Attacker View)
With `j.jenkins`'s local admin foothold on `MY-LAB-PC`, extracted the
NTLM hash of a cached Administrator session via `lsassy` (had to
manually disable Defender real-time protection first — both `lsassy`
and `handlekatz` failed outright against active EDR). Pass-the-Hash'd
that Administrator hash into `impacket-secretsdump -just-dc-user krbtgt`,
which impersonates a Domain Controller's replication rights to request
the `krbtgt` account's secrets from the real DC — extracting its
NTLM, AES256, and AES128 keys plus the domain SID, all without ever
touching the real Administrator password.

### Log Source & Event ID — Honest Gap
This is the **most important finding in the entire lab**, and it's a
negative result: **DCSync produced zero events.**
- **Intended source:** Event ID 4662 (An operation was performed on an
  object) on the DC, specifically for the `DS-Replication-Get-Changes`
  and `DS-Replication-Get-Changes-All` extended rights — the two
  permissions DCSync actually abuses.
- **Actual status:** Directory Service Access auditing was **never
  enabled** in this domain's audit policy, so no 4662 was ever generated
  for this action, on this DC, by this account. This is a genuine
  configuration gap, not a pipeline/shipping bug (unlike the earlier
  gaps in this lab).
- **What survived instead:** exactly one artifact — a single, entirely
  normal-looking **Event ID 4624 Type 3 (Network) Kerberos logon** from
  the Kali IP, with **no preceding 4768** to pair it with (because the
  Pass-the-Hash/replication call doesn't request a ticket the way an
  interactive logon would). On its own, this event is **forensically
  indistinguishable from a legitimate admin logon.**

### Kibana/KQL Query (once 4662 auditing is enabled)
```
event.code:4662 and
  winlog.event_data.Properties:("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" or
                                 "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2")
```
(the two GUIDs are `DS-Replication-Get-Changes` and
`DS-Replication-Get-Changes-All`) filtered to
`not winlog.event_data.SubjectUserName:(the real DC computer accounts)`
— any account other than a legitimate DC requesting these rights is a
DCSync attempt by definition.

### Recommended Fix (documented, not yet implemented in this lab)
1. Enable **Directory Service Access** auditing with an object-level
   SACL on the domain root filtered to the two replication GUIDs above,
   so the query above actually has data to run against.
2. Deploy a network-layer or identity-layer sensor (Microsoft Defender
   for Identity, or Zeek watching DRSUAPI/RPC traffic) — this is a
   protocol-level abuse of a legitimate DC-to-DC mechanism, and
   host-based Sysmon logging on the victim workstation was never going
   to catch it, since the actual malicious call happens DC-side.
3. As a compensating control, add a baseline rule: **4769 (TGS request)
   without a preceding 4768 (TGT request) from the same session** — a
   heuristic for credential replay/Pass-the-Hash generally, not DCSync
   specifically, but it would have flagged this chain's surviving
   artifact.

### False-Positive Considerations
- Legitimate replication traffic between real Domain Controllers uses
  these same rights constantly — the query above must exclude known DC
  computer accounts, or every AD replication cycle triggers an alert.
- Backup software (some AD-aware backup tools use DCSync-equivalent
  calls to back up AD) is a known legitimate source of this rights
  usage and needs to be allowlisted by service account.


---

### 8. Golden Ticket


**MITRE ATT&CK:** T1558.001 — Steal or Forge Kerberos Tickets: Golden Ticket

### What I Did (Attacker View)
Using the `krbtgt` AES256 key and domain SID extracted via DCSync,
forged a Golden Ticket with `impacket-ticketer`, granting full,
self-issued Domain Admin access with **zero knowledge of any real
Administrator password**. Took 3 attempts to get right, and each
failure was itself informative:
1. A fake/non-existent account name was rejected with
   `KDC_ERR_TGT_REVOKED`, due to **CVE-2021-42287** (PAC
   account-existence validation), which is patched on this Server 2022
   DC — a positive finding, since older/unpatched DCs would have
   accepted a ticket for a made-up user.
2. An RC4-encrypted forged ticket was rejected because this domain
   enforces AES-only Kerberos (the same policy finding from the
   Kerberoasting write-up) — another positive control working as
   intended.
3. Success only came from combining the real `krbtgt` AES256 key with a
   **real, existing account name** (`Administrator`).

### Log Source & Event ID — Same Gap as DCSync
A forged Golden Ticket, by design, never touches the real DC's TGT
issuance path — it's minted entirely offline. There is no 4768 for it to
generate. The only artifact is what appears when the ticket is *used*:
a single **Event ID 4624 Type 3 (Network) Kerberos logon**, which is
exactly the same surviving artifact documented in the DCSync note, and
is **the single point where this entire attack chain intersects with
host-based logging.**

### Kibana/KQL Query — Baseline Heuristic
Since no ticket-forging-specific event exists, the only viable detection
is the same cross-reference recommended in the DCSync note:
```
event.code:4624 and winlog.event_data.LogonType:"3" and
  winlog.event_data.AuthenticationPackageName:"Kerberos"
```
correlated against **the absence of a matching 4768** for the same
`TargetUserName` within a reasonable prior window (e.g. 10 hours — the
default Kerberos ticket lifetime, or longer if `ticketer` was given a
custom `-duration`). Kibana can't express "absence of a correlated
event" as a single KQL filter — this needs either a scheduled
Elasticsearch transform comparing two rolling counts, or a Watcher/
Detection Rule with a lookback join.

### Recommended Defensive Controls (documented findings from this lab)
1. **Rotate the `krbtgt` password twice**, spaced apart by the maximum
   Kerberos ticket lifetime, to invalidate any outstanding forged
   tickets — the only true remediation once `krbtgt` is believed
   compromised.
2. Enable 4662 DS-Access auditing with replication-GUID filters (see
   DCSync note) to catch the theft *before* it becomes a forged ticket.
3. Deploy a **4769-without-preceding-4768** baseline rule as a
   compensating control for the whole ticket-forging class, not just
   this one variant.
4. Enforce AES-only Kerberos domain-wide (already in place here) — it
   didn't prevent the attack, but it did add a real speed bump (attempt
   #2 above) and would stop unpatched/legacy tooling that can't forge
   AES tickets at all.

### False-Positive Considerations
- The 4624-without-4768 heuristic will also flag legitimate Kerberos
  logons using cached/renewed tickets whose original 4768 fell outside
  the lookback window — tune the window to comfortably exceed your
  domain's max ticket lifetime and renewal policy to avoid this.
- Some legitimate cross-forest/cross-domain trust logons can also show
  Kerberos authentication without a locally-visible 4768, since the TGT
  was issued by a different DC than the one you're monitoring —
  centralize logging across all DCs before trusting this rule alone.


---

## Kibana Dashboard Build Guide


Kibana dashboards are built in the UI (Stack Management → Saved Objects
can export/import them as NDJSON if you want the dashboard itself as a
portfolio artifact, but the panels themselves have to be built live
against your winlogbeat-* data view). Here's the exact panel list and
config to reproduce this, since I can't create Kibana objects directly.

### Recommended: 4 panels, one per your strongest signals

### Panel 1 — Kerberoasting: RC4 Ticket Requests Over Time
- **Type:** Lens, Bar (vertical, stacked by count)
- **Data view:** `winlogbeat-*`
- **Query:** `event.code:4769 and winlog.event_data.TicketEncryptionType:"0x17"`
- **X-axis:** `@timestamp` (Date histogram, auto interval)
- **Y-axis:** Count
- **Break down by:** `winlog.event_data.TargetUserName.keyword` (top 5)
- Why this panel: your validated, zero-false-positive query — the
  strongest "clean win" to lead the dashboard with.

### Panel 2 — AS-REP Roasting: PreAuth Type 0 Requests
- **Type:** Lens, Bar (vertical)
- **Query:** `event.code:4768 and winlog.event_data.PreAuthType:"0"`
- **X-axis:** Date histogram on `@timestamp`
- **Break down by:** `winlog.event_data.TargetUserName.keyword`

### Panel 3 — Password Spray: Failed Logons by Source IP (Cardinality)
- **Type:** Lens, Table
- **Query:** `event.code:4625 and winlog.event_data.LogonType:"3"`
- **Rows:** `winlog.event_data.IpAddress.keyword`
- **Metrics:** Count of events, **Unique Count** of
  `winlog.event_data.TargetUserName.keyword`
- Sort descending by unique-user-count — a source IP touching 5+
  distinct usernames is the spray signature, which this table surfaces
  directly (a plain count-over-time chart hides this pattern).

### Panel 4 — Lateral Movement: Elevated Network Logons + atexec Chain
- **Type:** Lens, Bar (vertical), two saved queries as separate series
  via "Add layer," or two side-by-side panels in the same row:
  - Series A: `event.code:4624 and winlog.event_data.LogonType:"3" and winlog.event_data.ElevatedToken:"%%1842"`
  - Series B: `event.code:1 and process.parent.command_line:*netsvcs*`
- **X-axis:** Date histogram, small interval (1 minute) so the
  millisecond-level correlation between the two series is visually
  obvious when you zoom the time range to the attack window.

### Dashboard-level settings
- Set the dashboard's default time range to a window covering your full
  attack timeline (e.g. the day you ran Phases 1–4) so it tells a story
  when opened, rather than showing an empty "last 15 minutes."
- Add a **Markdown panel** at the top with a 2-3 line caption per
  detection ("Panel 1: Kerberoasting — validated, zero FPs. Panel 3:
  password spray — cardinality view, not raw count.") — this is what
  turns four charts into a narrative for someone skimming your portfolio.
- **Skip DCSync/Golden Ticket from the dashboard itself** — you
  documented that they produce no visualizable signal in this lab's
  current config, and a panel that's empty by design reads as a bug
  unless captioned; better to reference that gap in the incident report
  (below) than force an empty chart onto the dashboard.

### Exporting for your portfolio
Once built: **Stack Management → Saved Objects → find your dashboard →
Export.** That NDJSON file is a good thing to include in the folder
alongside these write-ups — it lets anyone with an ELK stack import and
literally see your dashboard, not just a screenshot of it.


---

## Incident Report — Simulated Domain Compromise: LLMNR Poisoning to DCSync


**Prepared for:** Engineering Manager Briefing
**Classification:** Internal / Lab Simulation (JOSHUA.LOCAL domain)
**Prepared by:** [Analyst Name]
**Date of Activity:** Phases 1–4, personal AD attack/defense lab

### Executive Summary
Over a controlled, self-hosted lab exercise, I simulated a full domain
compromise chain starting from a single unauthenticated network position
and ending in complete, undetected control of the domain controller. The
chain succeeded end-to-end. Of the six major techniques used, **four
were fully detectable** with a correctly configured Sysmon + Winlogpbeat
+ ELK pipeline, and the write-ups for those are strong templates for
production detection rules. **The final two steps — DCSync and Golden
Ticket forging — left essentially no host-based trace**, which is the
headline finding this report exists to communicate: our current logging
posture would have stopped this attacker at the reconnaissance and
credential-theft stages, but would not have detected the actual loss of
domain control.

### Timeline of the Attack

**1. Initial Access — LLMNR/NBT-NS Poisoning.**
Positioned on the internal network with no credentials, I ran a
poisoning tool that answered broadcast name-resolution fallbacks from
domain-joined hosts. This captured NTLMv2 hashes for three real
accounts, including `Administrator`, from ordinary background network
noise — no phishing, no exploit, just listening. One hash cracked
quickly due to a weak password; the others resisted cracking, which
illustrates that **capture is guaranteed by the protocol; only the
consequence depends on password strength.**

**2. Credential Access — Kerberoasting.**
Using a valid (if low-privileged) domain session, I requested a Kerberos
service ticket for an account with a Service Principal Name and cracked
it offline. This is a "living off the land" technique — it requires no
malware and abuses a normal Kerberos feature. This domain's AES-only
policy meant I had to deliberately weaken an account's encryption
settings to make the ticket crackable at all, which is a genuine
mitigating control worth calling out as already working correctly.

**3. Reconnaissance — BloodHound Attack Path Mapping.**
With one set of low-privilege credentials, I mapped the entire domain's
trust and permission graph using SharpHound and found a directional path
from a standard user to Domain Admins. This step doesn't touch
credentials at all — it's pure information gathering — but it's what
transformed "I have one weak account" into "I know exactly which three
hops get me to full domain control." This is the step I'd most want
leadership to internalize: **an attacker doesn't need to be lucky at
every step if they can map the one path that works.**

**4. Lateral Movement & Privilege Escalation.**
The mapped path required local admin rights on a workstation. I
simulated a realistic misconfiguration (an over-permissive GPO) to grant
that access, then used it to execute code as SYSTEM on the target
machine via a Task Scheduler-based technique. This step produced the
cleanest detection signal in the whole chain: a network logon carrying
an elevated token, followed 61 milliseconds later by a process spawned
in the specific pattern that technique leaves behind. **That millisecond
timing gap between "someone logged on" and "a command executed" is a
detail a human analyst would never think to check, but a SIEM rule
easily can.**

**5. Credential Theft — LSASS Access & DCSync.**
From the SYSTEM-level foothold, I extracted a cached Administrator
credential from memory (after disabling endpoint protection — a step
that would itself be a strong detection point in a production
environment, and is worth a follow-up write-up on its own). I then used
that credential to impersonate a Domain Controller's replication rights
and pull the domain's most sensitive secret — the `krbtgt` account's
keys — directly from the real DC. **This step generated zero log
entries**, because Directory Service Access auditing, the one setting
that would have caught it, was never enabled. This is not a tooling
failure; it's a configuration gap that almost certainly exists in many
real environments by default.

**6. Persistence — Golden Ticket.**
With the `krbtgt` keys in hand, I forged a ticket that grants Domain
Admin access indefinitely, without ever knowing a real password and
without needing to touch the DC again. Two patched security controls
on this domain (PAC validation against CVE-2021-42287, and AES-only
Kerberos enforcement) both correctly rejected my first two forging
attempts — genuinely good news, and proof those controls work as
designed. The third attempt, using a real account name and the correct
key type, succeeded. **The only artifact this leaves behind is a single,
ordinary-looking network logon event, with no way to distinguish it from
a legitimate administrator logging on remotely.**

### Business Impact (Framed for a Real Environment)
Had this been a real environment, the endpoint reached in step 4 would
have been enough, if the attacker chose to stop there, to escalate to
full domain control at will, at any future time, without needing to
repeat any of the earlier steps — the forged ticket doesn't expire on
its own and doesn't require the original compromised account to remain
active. Detecting steps 1–4 would have interrupted this chain well
before that point. As configured, none of our current tooling would
have interrupted steps 5–6.

### Recommendations, in Priority Order
1. **Enable Directory Service Access (4662) auditing** with SACLs
   scoped to the two DCSync-relevant replication rights. This is a
   single configuration change and it is the highest-leverage fix
   available — it converts an invisible step into a loud one.
2. **Deploy a network/identity-layer sensor** (Microsoft Defender for
   Identity, or Zeek) as a compensating control for both the LLMNR
   poisoning and DCSync detection gaps — both are protocol-level abuses
   that host-based Sysmon logging is structurally not well positioned to
   catch.
3. **Add a "4769 without a preceding 4768" correlation rule** as a
   general-purpose tripwire for credential-replay and forged-ticket
   activity — it would have caught the one surviving artifact from both
   step 5 and step 6.
4. **Rotate `krbtgt` on a schedule** (twice, spaced by the maximum
   ticket lifetime) as a standing hygiene practice, independent of
   whether a compromise is suspected.
5. **Treat EDR-disabling as a first-class alert.** The credential-theft
   step in this chain only worked after disabling real-time protection —
   in a production environment, that action itself, from an endpoint
   agent's own tamper-protection logging, should be one of the loudest
   signals available, and is worth its own detection note in a future
   pass.

### Closing Note
The strongest finding from this exercise isn't any single technique —
it's that **our detection coverage has a hard boundary exactly where the
DC's own replication protocol is abused**, and that boundary is closable
with one audit-policy change plus a network sensor, not a wholesale
re-architecture.
