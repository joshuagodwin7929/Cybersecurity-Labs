### Detection 1: DCSync — Event ID 4662 Alert Rule ###

**Gap closed:** Recommendation 1 — "Enable Directory Service Access
(4662) auditing with SACLs scoped to the two DCSync-relevant
replication rights."

#### What was missing (and why)

The original Phase 4 DCSync attack generated **zero log entries**
because Directory Service Access auditing was not enabled and no SACL
existed on the domain root object. The attack was completely invisible
to the Winlogbeat → Elasticsearch pipeline despite Sysmon and Advanced
Audit Policy being configured everywhere else.

#### What was built

**Step 1 — Enable Directory Service Access auditing on the DC.**

Configured via Group Policy and verified with auditpol (not assumed from
GPO UI alone — the Account Lockout incident from Phase 1 taught that
GPO "configured" ≠ "applied"):

```
auditpol /get /subcategory:"Directory Service Access"
→ Success ✅
```

<img width="520" height="386" alt="Enable DS Access auditing" src="https://github.com/user-attachments/assets/d34be650-8387-4a3b-a39b-3c8cfa1c354e" />


<img width="505" height="302" alt="DS Access auditing confirmed" src="https://github.com/user-attachments/assets/40f84db8-e773-4f4e-a4c5-0283dec874ad" />



**Step 2 — Add a SACL on the domain root object.**

In ADUC (Advanced Features enabled): right-click `joshua.local` →
Properties → Security → Advanced → Auditing → Add:

| Field | Value |
|---|---|
| Principal | Everyone |
| Type | Success |
| Applies to | This object only |
| Permission | All Extended Rights |

This tells Windows to log any exercise of an extended right on the
domain root — covering both DCSync-relevant GUIDs
(`1131f6aa` Replicating Directory Changes and
`1131f6ad` Replicating Directory Changes All) plus any other
control-access abuse against the domain object.


<img width="532" height="438" alt="SACL on domain root" src="https://github.com/user-attachments/assets/91428dc3-cad7-422f-afb7-19beb8c6b31e" />



**Step 3 — Simulate a realistic misconfiguration.**

Rather than re-using the Domain Admin account for DCSync (which is
expected and less interesting as a detection story), granted j.jenkins —
a regular service account — the replication right directly via `dsacls`:

```cmd
dsacls "DC=joshua,DC=local" /G "JOSHUA\j.jenkins:CA;Replicating Directory Changes"
dsacls "DC=joshua,DC=local" /G "JOSHUA\j.jenkins:CA;Replicating Directory Changes All"
```

This simulates a real-world over-permissioned service account — one of
the most common misconfigurations in enterprise AD environments —
rather than a Domain Admin doing what Domain Admins sometimes legitimately do.

**Step 4 — Confirm the 4662 event in Kibana.**

Re-ran DCSync as j.jenkins:

```bash
impacket-secretsdump -just-dc-user krbtgt joshua.local/j.jenkins:'Password1!'@192.168.18.50
```


<img width="410" height="134" alt="Impacket-Secretdump" src="https://github.com/user-attachments/assets/65c88c43-b563-447b-ace5-b756acbdaf9e" />



Result: **3 × Event ID 4662 in Kibana**, all from `Joshua-Server2022`,
all showing:

| Field | Value |
|---|---|
| `winlog.event_data.SubjectUserName` | j.jenkins |
| `winlog.task` | Directory Service Access |
| `winlog.event_data.AccessListDescription` | Control Access |
| `message` (Properties field) | `{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}` ← DCSync GUID |


<img width="1272" height="688" alt="Kibana-Event-4662" src="https://github.com/user-attachments/assets/8361cf74-4f31-4287-adcf-42cabc571ce0" />


Note: Winlogbeat 8.12.0 parses the replication GUIDs into the raw
`message` field rather than a dedicated `winlog.event_data.Properties`
field — the alert query targets `message` not `event_data.Properties`
for this reason. Always verify field names from actual captured events,
not documentation.

**Step 5 — Build a live Kibana alert rule.**

Stack Management → Rules → Create rule → Elasticsearch query → KQL or Lucene:

```
event.code:4662 and message:*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*
```

| Setting | Value |
|---|---|
| Index | winlogbeat-* |
| Threshold | IS ABOVE 0 |
| Check every | 5 minutes |
| Look back | 5 minutes |
| Action | Server log connector |


<img width="1274" height="736" alt="Kibana Alert Rule" src="https://github.com/user-attachments/assets/8bd5cd29-d14f-4b3d-8a4a-5539939c4ab8" />



**Step 6 — Validate the rule fired.**

Re-ran DCSync. After one check interval:

```
Last response: Succeeded ✅
Success ratio: 100% ✅
```

The rule evaluated, matched the attack events, and executed the action
— not just a saved query, but a confirmed firing detection.

<img width="1279" height="731" alt="Kibana Alert Rule Fired" src="https://github.com/user-attachments/assets/02065ff5-c0df-46b5-9cb4-794212869af8" />


#### Detection note

The GUID `1131f6ad` (Replicating Directory Changes All) is the more
sensitive of the two — it includes secret attributes (password hashes).
Filtering to this GUID rather than "All Extended Rights" reduces noise
from unrelated control-access events (password resets, etc.) that the
broad SACL will also log.

#### False-positive considerations

Legitimate DCSync is performed by Domain Controllers during normal AD
replication — filter on `SubjectUserName` ending in `$` to exclude
machine accounts. Any non-DC, non-machine account triggering this rule
is a genuine finding.

---

