## Incident Report — Simulated Domain Compromise: LLMNR Poisoning to DCSync


**Prepared for:** Engineering Manager Briefing

**Classification:** Internal / Lab Simulation (JOSHUA.LOCAL domain)

**Prepared by:** [OKUNNUWA JOSHUA GODWIN]

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
headline finding this report exists to communicate: my current logging
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
