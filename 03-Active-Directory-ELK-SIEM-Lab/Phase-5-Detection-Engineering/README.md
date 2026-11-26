# Phase 5: Detection Engineering

After running every attack in Phases 1 to 4, I went back over the telemetry each one left behind. This phase has two parts.

| Part | What it covers |
|---|---|
| [5A: Hunt Queries](5A-Hunt-Queries/README.md) | A KQL hunt query for each technique, written against the real events the attack produced, plus the techniques that left nothing to hunt for. |
| [5B: Closing the Detection Gaps](5B-Closing-The-Detection-Gaps/README.md) | Fixing the two attacks that were invisible in Phase 4: DCSync and the Golden Ticket. |

The hunt queries here became the Sigma rules in my [Detection-Engineering](https://github.com/joshuagodwin7929/Detection-Engineering) repo. I later validated those rules with automated attacks in [Purple-Team-Automation](https://github.com/joshuagodwin7929/Purple-Team-Automation).

[← Phase 4: DCSync and Golden Ticket](../Phase-4-DCSync-Golden-Ticket) · [Phase 6: Incident Report →](../Phase-6-Incident-Report)
