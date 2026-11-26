# Phase 5B: Closing the Detection Gaps

In Phase 4, two attacks left almost nothing in my logs. This part closes both gaps, following the recommendations in my [Phase 6 incident report](../../Phase-6-Incident-Report).

| Gap | Problem | What I built |
|---|---|---|
| [Gap 1: DCSync, no audit trail](Gap-1-DCSync-No-Audit-Trail/README.md) | DCSync produced zero events, because Directory Service Access auditing was off and the domain root had no SACL. | Enabled 4662 auditing with a SACL for the replication rights, then built a Kibana alert rule on top. The first version of that rule never matched; the page includes the correction and the fix. |
| [Gap 2: Golden Ticket, no tripwire](Gap-2-Golden-Ticket-No-Tripwire/README.md) | A forged ticket produced one 4624 logon that looks like any admin logon. | A Python script that flags a service ticket (4769) with no matching TGT request (4768) in the previous 10 hours, writing hits to an alerts index. Kibana's query rules can't express "A without B," so this had to be code. |

[← Back to Phase 5](../README.md)
