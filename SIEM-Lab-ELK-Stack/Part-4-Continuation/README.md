

Readme phase2 · MD
# SIEM-Lab-ELK-Stack — Part 4: Access Control, Lifecycle Management, Dashboards & Backups
 
**A continuation of the [ELK Stack Setup, Elasticsearch and Kibana Deployment](./README.md) project.**
 
The part 1, 2, 3 covered building and hardening the stack itself: Docker Compose deployment, end-to-end TLS, and a live log ingestion pipeline from a real Linux host. This phase picks up exactly where that left off — moving from "the stack works" to "the stack is operated the way a real SIEM environment would be."
 
---
 
## 📋 Table of Contents
 
- [What This Phase Covers](#-what-this-phase-covers)
- [1. Named, Least-Privilege Users & Roles](#1-named-least-privilege-users--roles)
- [2. Index Lifecycle Management (ILM)](#2-index-lifecycle-management-ilm)
- [3. Dashboards](#3-dashboards)
- [4. Identifying Suspicious Authentication Activity](#4-identifying-suspicious-authentication-activity)
- [5. Snapshot-Based Backups](#5-snapshot-based-backups)
- [Lessons Learned](#-lessons-learned)
- [Screenshots](#-screenshots)
---
 
## ✅ What This Part Covers
 
By the end of part 1, the stack was secured and ingesting real system logs (`filebeat-lab-*`) but was still being operated entirely as the `elastic` superuser, with no lifecycle management, no visualizations, no analysis practice, and no backup strategy. This phase closes all five of those gaps.
 
---
 
## 1. Named, Least-Privilege Users & Roles
 
**Goal:** stop using the `elastic` superuser for day-to-day work, and scope access to exactly what's needed — nothing more.
 
**What was built:**
- A custom role, `my_siem_log_viewer`, scoped to the real `filebeat-lab-*` index with only `read` and `view_index_metadata` privileges.
- Kibana feature privileges restricted to **Discover (Read)**, **Dashboard (Read)**, and **Data View Management (Read)** — everything else (Dev Tools, Advanced Settings, Security, Stack Management) set to `None`.
- A named user assigned only this role — no `superuser` privileges attached.
**Verification:** logged out of `elastic`, logged in as the new named user, and confirmed:
- Discover correctly displayed real `filebeat-lab-*` data (51 hits).
- Broad admin/security screens (Roles, Users, Index Management) were inaccessible.
📸 *[Screenshot: role privilege summary showing Discover/Dashboard = Read, everything else = None]*
<img width="1280" height="738" alt="Role Privilege Summary" src="https://github.com/user-attachments/assets/8217d8f0-1287-46c2-84d6-e8ae75922683" />

 📸 *[Screenshot: lShowing newly created user]*
<img width="899" height="738" alt="User Created" src="https://github.com/user-attachments/assets/ba0d18af-3429-47bf-bad5-698c34b47a7f" />

 
📸 *[Screenshot: logged in as the restricted user, Discover showing real log data]*
<img width="635" height="550" alt="New Kibana Users" src="https://github.com/user-attachments/assets/85e80cda-a6bf-4d3a-90a2-4a052d059702" />


 
> 📝 **Note on Active Directory:** a fully functioning AD lab already exists separately and could be integrated via Elasticsearch's `active_directory` realm (mapping AD groups → Elastic roles). This requires a **paid Gold/Platinum license** (native/file realms are the only free-tier auth realms) — deferred for now in favor of native roles, but documented as a future upgrade path.
 
---
 
## 2. Index Lifecycle Management (ILM)
 
**Goal:** prevent `filebeat-lab-*` indices from accumulating forever and consuming disk space indefinitely.
 
**What was built:** an ILM policy (`filebeat-lab-policy`) with:
- **Hot phase** — default rollover settings (30 days or 50GB), left as-is since lab data volume is low.
- **Warm/Cold phases** — left disabled; unnecessary at this data scale.
**What didn't get finished:** the **Delete phase** — the actual mechanism that would auto-delete old indices — could not be configured. Its section never rendered in the Kibana ILM policy editor, confirmed via:
- Scrolling and toggling Cold phase on/off (no effect).
- Browser `Ctrl+F` search for both "Delete phase" and "delete" across the fully-loaded page (zero matches either time).
The policy was saved with just the Hot phase active — functionally a no-op for now, but it exists and can be edited later without starting over.
 
📸 *[Screenshot: ILM policy editor showing Hot/Warm/Cold phases, no Delete phase visible]*
<img width="626" height="735" alt="ILM Policy" src="https://github.com/user-attachments/assets/7f0b189a-8315-4b1e-9eb8-babbfcfb41e7" />

 
**Documented next step (not yet applied):** set the delete phase directly via the Elasticsearch API instead of the Kibana UI:
```bash
curl -k -u elastic:<password> -X PUT "https://localhost:9200/_ilm/policy/filebeat-lab-policy" \
  -H "Content-Type: application/json" -d '{
  "policy": {
    "phases": {
      "hot": { "min_age": "0ms", "actions": {} },
      "delete": { "min_age": "30d", "actions": { "delete": {} } }
    }
  }
}'
```
 
---
 
## 3. Dashboards
 
**Goal:** move from raw log entries to at-a-glance visual insight.
 
**What was built:** a dashboard ("SIEM Lab Overview") with two panels, built using Kibana's Lens editor:
 
- **Log Volume Over Time** — a line chart, `@timestamp` (X-axis) vs. Count of records (Y-axis), on a 30-minute interval. Makes volume spikes immediately visible.
- **My Log Volume by Source** — a donut chart broken down by `log.file.path.keyword`, revealing the actual split: **76.47% from `/var/log/auth.log`, 23.53% from `/var/log/syslog`** — i.e., most captured activity is authentication/session-related, not general system noise.
📸 *[Screenshot: Log Volume Over Time line chart panel]*
<img width="1280" height="738" alt="Log Volume Over Line Chart Panel" src="https://github.com/user-attachments/assets/05e0442d-4cbb-4b0c-87d4-f2e658e565c5" />

 
📸 *[Screenshot: Log Volume by Source donut chart panel]*
<img width="1280" height="738" alt="Donut Chart Panel" src="https://github.com/user-attachments/assets/84b204a1-ae57-43f2-abea-8c28e6e68f9f" />


 
📸 *[Screenshot: full dashboard view with both panels]*
<img width="1269" height="734" alt="Full Dashboard with both panels" src="https://github.com/user-attachments/assets/73997b9c-bb3c-40f9-b4d1-d14720805e62" />

 
> 📝 **Workflow tip:** Lens' "Suggestions" row at the bottom of the chart editor offers one-click chart type conversions based on the fields already assigned — often faster than manually hunting through the chart-type dropdown.
 
---
 
## 4. Identifying Suspicious Authentication Activity
 
**Goal:** practice the actual analyst skill of reading real auth data, not just visualizing it.
 
**Searches run in Discover against real `auth.log`/`syslog` data:**
 
| Search | Result | Interpretation |
|---|---|---|
| `message: "Failed password"` | 0 hits | No brute-force attempts — expected for a personal, non-internet-facing lab |
| `message: "session opened for user root"` | 7 hits | All `CRON[...]` entries — automatic scheduled tasks, not human logins. Normal noise. |
| `message: "sudo"` | 6 hits | Real, traceable privileged activity — see below |
 
**The key finding:** one `sudo` entry read:
```
sudo: ubuntuadmin : TTY=pts/0 ; PWD=/home/ubuntuadmin/elk-stack ; USER=root ; COMMAND=/usr/sbin/sysctl -w vm.max_map_count=262144
```
This was matched directly to a real, known action: re-applying the `vm.max_map_count` kernel setting after a VM reboot caused Elasticsearch to fail its healthcheck. `TTY=pts/0` confirmed it came from an interactive SSH session, not an automated script.
 
📸 *[Screenshot: Discover search results for "sudo" showing the traced command]*
<img width="1280" height="736" alt="Sudo" src="https://github.com/user-attachments/assets/b94f71ed-03ec-45cb-83e2-ce0fb5f7e767" />

 
**The core lesson:** the first question when reviewing privileged activity isn't *"is this bad?"* — it's **"can I account for this?"** Activity traceable to a known, legitimate action (a real command, a real timestamp, a real reason) is resolved. Activity that *can't* be explained is what actually warrants escalation.
 
---
 
## 5. Snapshot-Based Backups
 
**Goal:** establish a real disaster-recovery story — without this, losing the `es_data` Docker volume means losing everything.
 
**What was built:**
1. Mounted a host folder into Elasticsearch: `./elasticsearch/snapshots:/usr/share/elasticsearch/snapshots`, and added `path.repo=/usr/share/elasticsearch/snapshots` to its environment (required — Elasticsearch blocks filesystem repositories unless explicitly allow-listed).
2. Registered a **Shared file system** repository, `siem_lab_backups`, pointing at that path.
3. **Verified** the repository — status returned `Connected`, confirming Elasticsearch could actually read/write to the mounted path, not just that the config looked valid.
4. Created an automated **Snapshot Lifecycle Management (SLM) policy**, `daily_siem_lab_backups`:
   - Schedule: daily at 01:30 (`0 30 1 * * ?`)
   - Scope: all indices, including global state (cluster settings/templates)
   - Retention: delete after 14 days, keep a minimum of 5 and maximum of 10 snapshots
5. Ran the policy manually to confirm it works before waiting for the schedule.
**Result: 2 snapshots taken, 0 failures.**
 
📸 *[Screenshot: repository verification status showing "Connected"]*
<img width="630" height="731" alt="Snapshot Showing connected" src="https://github.com/user-attachments/assets/b1e382c3-6865-4f65-a694-8bb70e5b101e" />

 
📸 *[Screenshot: snapshot policy summary — 2 taken, 0 failures, next snapshot scheduled]*
<img width="1096" height="662" alt="Policy summary" src="https://github.com/user-attachments/assets/5cd77c2d-425e-4c6a-ba5e-9c40895a7864" />

 
---
 
## 🎓 Lessons Learned
 
- **Least privilege should be built the moment real data exists, not before.** Waiting until `filebeat-lab-*` had real documents made scoping the role's index pattern and testing it far more accurate than guessing in advance.
- **A UI section not rendering isn't always visible as an "error."** The ILM Delete phase silently failing to appear — with no error message, no console warning shown to the user — is a reminder to verify with an independent method (browser search, or bypass the UI via the API) rather than assuming a missing feature means "read more carefully."
- **Lens' chart suggestions are a shortcut, not a guarantee.** Clicking a suggested chart type can behave differently than manually selecting the same type from the dropdown — worth double-checking the result rather than assuming the click landed correctly.
- **"Can I account for this?" beats "is this suspicious?" as the first triage question.** Nearly all privileged activity in a personal lab is explainable by the operator's own actions — the skill is building the habit of actually checking, not assuming.
- **A verified backup is not the same as a configured one.** The repository verification step (`Connected` status) and the manual "run now" trigger were both necessary to confirm the backup pipeline actually works end-to-end, not just that the settings were saved without error.
- **Filesystem-based Elasticsearch repositories require an explicit allow-list (`path.repo`).** This is a deliberate security control, not a bug — Elasticsearch refuses to write snapshots to arbitrary paths without it.
---
 
## 📸 Screenshots
 
> Add screenshots to a `/screenshots` folder in this repo and reference them below.
 
| Description | Screenshot |
|---|---|
| Role privilege summary (`my_siem_log_viewer`) | `![role privileges](screenshots/role-privileges.png)` |
| Logged in as restricted user, Discover working | `![restricted user discover](screenshots/restricted-user-discover.png)` |
| ILM policy editor (Delete phase missing) | `![ilm policy](screenshots/ilm-policy.png)` |
| Dashboard: Log Volume Over Time | `![log volume chart](screenshots/log-volume-chart.png)` |
| Dashboard: Log Volume by Source | `![log source donut](screenshots/log-source-donut.png)` |
| Auth log search results (sudo activity) | `![auth log search](screenshots/auth-log-search.png)` |
| Snapshot repository verification (Connected) | `![repo verified](screenshots/repo-verified.png)` |
| Snapshot policy summary (2 taken, 0 failures) | `![snapshot policy](screenshots/snapshot-policy.png)` |
 
---
 
## 🔐 Security Disclaimer
 
This is a personal lab environment. Passwords, certificates, and configurations shown here are for demonstration only and should never be reused in a production environment.
 

