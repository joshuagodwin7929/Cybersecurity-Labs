# Gap 1: DCSync, no audit trail

In Phase 4, DCSync left zero log entries, because Directory Service Access auditing was off and there was no SACL on the domain root. The attack was invisible to the whole pipeline even though Sysmon and Advanced Audit Policy were configured everywhere else. This page is how I closed that gap, and the mistake I made in the alert rule on top of it.

## Turning on the auditing

**Enable Directory Service Access auditing on the DC.** I set it by GPO and confirmed with `auditpol`, not from the GPO UI alone. The account-lockout problem in Phase 1 taught me that "configured" in Group Policy isn't the same as "applied."

```
auditpol /get /subcategory:"Directory Service Access"
→ Success
```

<img width="520" height="386" alt="Enable DS Access auditing" src="https://github.com/user-attachments/assets/d34be650-8387-4a3b-a39b-3c8cfa1c354e" />

<img width="505" height="302" alt="DS Access auditing confirmed" src="https://github.com/user-attachments/assets/40f84db8-e773-4f4e-a4c5-0283dec874ad" />

**Add a SACL on the domain root.** In ADUC with Advanced Features on: right-click `joshua.local` → Properties → Security → Advanced → Auditing → Add:

| Field | Value |
|---|---|
| Principal | Everyone |
| Type | Success |
| Applies to | This object only |
| Permission | All Extended Rights |

This tells Windows to log any exercise of an extended right on the domain root, which covers both DCSync GUIDs (`1131f6aa` Replicating Directory Changes and `1131f6ad` Replicating Directory Changes All) plus any other control-access abuse against the domain object.

<img width="532" height="438" alt="SACL on domain root" src="https://github.com/user-attachments/assets/91428dc3-cad7-422f-afb7-19beb8c6b31e" />

## Reproducing the attack as a realistic misconfiguration

Rather than run DCSync as a Domain Admin (which is expected and a weaker detection story), I granted `j.jenkins`, a regular service account, the replication rights directly with `dsacls`:

```cmd
dsacls "DC=joshua,DC=local" /G "JOSHUA\j.jenkins:CA;Replicating Directory Changes"
dsacls "DC=joshua,DC=local" /G "JOSHUA\j.jenkins:CA;Replicating Directory Changes All"
```

This is an over-permissioned service account, one of the most common real-world AD misconfigurations, rather than a Domain Admin doing something Domain Admins sometimes legitimately do.

Then I re-ran DCSync as `j.jenkins`:

```bash
impacket-secretsdump -just-dc-user krbtgt joshua.local/j.jenkins:'Password1!'@192.168.18.50
```

<img width="410" height="134" alt="Impacket-Secretdump" src="https://github.com/user-attachments/assets/65c88c43-b563-447b-ace5-b756acbdaf9e" />

This time I got **three Event ID 4662s in Kibana**, all from `Joshua-Server2022`:

| Field | Value |
|---|---|
| `winlog.event_data.SubjectUserName` | j.jenkins |
| `winlog.task` | Directory Service Access |
| `winlog.event_data.AccessListDescription` | Control Access |
| `message` (Properties field) | `{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}` (the DCSync GUID) |

<img width="1272" height="688" alt="Kibana-Event-4662" src="https://github.com/user-attachments/assets/8361cf74-4f31-4287-adcf-42cabc571ce0" />

One thing worth noting: Winlogbeat 8.12.0 parses the replication GUIDs into the raw `message` field, not a dedicated `winlog.event_data.Properties` field, so the alert query targets `message`. I only found this by checking the actual captured events rather than trusting the documentation.

## Building the alert rule, and getting it wrong

Stack Management → Rules → Create rule → Elasticsearch query, KQL.

What I built first (this query never matches, see below):

```
event.code:4662 and message:*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*
```

The corrected rule:

```
event.code:4662 and message:"1131f6ad-9c07-11d1-f79f-00c04fc2dcd2" and not winlog.event_data.SubjectUserName:*$
```

| Setting | Value |
|---|---|
| Index | winlogbeat-* |
| Threshold | IS ABOVE 0 |
| Check every | 5 minutes |
| Look back | 15 minutes (originally 5) |
| Action | Server log connector |

<img width="1274" height="736" alt="Kibana Alert Rule" src="https://github.com/user-attachments/assets/8bd5cd29-d14f-4b3d-8a4a-5539939c4ab8" />

When I first validated it, I re-ran DCSync and saw this after one check interval:

```
Last response: Succeeded
Success ratio: 100%
```

I originally wrote that this proved the rule matched the attack. It didn't.

<img width="1279" height="731" alt="Kibana Alert Rule" src="https://github.com/user-attachments/assets/02065ff5-c0df-46b5-9cb4-794212869af8" />

### The correction (November 2026)

"Succeeded" only means the rule ran without an error. Whether it matched anything shows in the **Active alerts** count, and in November I found this rule had raised **0 alerts in 57 runs**. Two things were wrong:

1. **The wildcard query can never match.** `message` is a text field, so Elasticsearch splits it into words at every hyphen before storing it. A wildcard is checked against one word at a time, and no single word contains the hyphenated GUID. Searching the GUID as a quoted phrase fixed it: on the same day's events, the wildcard query returned 0 hits and the phrase query returned 2.
2. **A 5-minute look-back is too tight.** If events arrive late, they're already outside the window when the rule runs. I moved it to 15 minutes.

With both fixed, the rule raised a real alert about a minute after a DCSync run on 25 November 2026. The full investigation is in [Purple-Team-Automation](https://github.com/joshuagodwin7929/Purple-Team-Automation/blob/main/validation/detection-results.md), and the rule definition is in [Detection-Engineering](https://github.com/joshuagodwin7929/Detection-Engineering/blob/main/rules/elastic/LAB-OVERRIDES.md).

The audit setup earlier on this page was right all along. The 4662 events were in Elastic; only the rule on top of them was broken.

## Notes

The GUID `1131f6ad` (Replicating Directory Changes All) is the more sensitive of the two, because it includes secret attributes like password hashes. Filtering to this GUID rather than "All Extended Rights" cuts noise from unrelated control-access events (password resets and the like) that the broad SACL also logs.

Legitimate DCSync is done by Domain Controllers during normal replication, so filtering out `SubjectUserName` ending in `$` excludes machine accounts. Any non-DC, non-machine account triggering this rule is a genuine finding.

---

Back to [Phase 5B](../README.md) · Next: [Gap 2: Golden Ticket, no tripwire](../Gap-2-Golden-Ticket-No-Tripwire/README.md)
