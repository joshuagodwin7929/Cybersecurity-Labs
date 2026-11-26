# Part 4: Access Control, Lifecycle Management, Dashboards and Backups

A continuation of the [ELK Stack setup](../README.md).

Parts 1 to 3 built and hardened the stack: Docker Compose, end-to-end TLS, and a live ingestion pipeline from a real Linux host. By the end of that, the stack worked but I was still running everything as the `elastic` superuser, with no lifecycle management, no dashboards, no analysis practice and no backups. This part closes those five gaps, moving from "the stack works" to "the stack is operated like a real SIEM."

## 1. Named, least-privilege users and roles

I wanted to stop using `elastic` for day-to-day work and scope access to exactly what's needed.

I made a custom role, `my_siem_log_viewer`, scoped to the `filebeat-lab-*` index with only `read` and `view_index_metadata`. Its Kibana feature privileges are limited to Discover (Read), Dashboard (Read) and Data View Management (Read); everything else (Dev Tools, Advanced Settings, Security, Stack Management) is set to None. Then I created a named user with only this role and no superuser rights.

To check it, I logged out of `elastic`, logged in as the new user, and confirmed Discover showed the real `filebeat-lab-*` data (51 hits) while the admin and security screens (Roles, Users, Index Management) were inaccessible.

<img width="1280" height="738" alt="Role Privilege Summary" src="https://github.com/user-attachments/assets/8217d8f0-1287-46c2-84d6-e8ae75922683" />

<img width="899" height="738" alt="User Created" src="https://github.com/user-attachments/assets/ba0d18af-3429-47bf-bad5-698c34b47a7f" />

<img width="635" height="550" alt="New Kibana Users" src="https://github.com/user-attachments/assets/85e80cda-a6bf-4d3a-90a2-4a052d059702" />

I already have a working AD lab separately, and I could integrate it through Elasticsearch's `active_directory` realm (mapping AD groups to Elastic roles). That needs a paid Gold/Platinum license though, since the native and file realms are the only free-tier auth realms, so I left it as native roles for now and noted AD integration as a future upgrade.

## 2. Index Lifecycle Management

I didn't want `filebeat-lab-*` indices piling up forever. I created an ILM policy, `filebeat-lab-policy`, with the hot phase on default rollover (30 days or 50GB), left as-is given the low data volume, and the warm and cold phases disabled since they're unnecessary at this scale.

The delete phase, the part that would actually auto-delete old indices, I couldn't configure from the UI. Its section never rendered in the Kibana ILM editor. I ruled out my own oversight by toggling the cold phase on and off (no effect) and using the browser's Ctrl+F for both "Delete phase" and "delete" across the fully loaded page (zero matches either time). I saved the policy with just the hot phase, which is effectively a no-op for now but exists and can be edited later.

<img width="626" height="735" alt="ILM Policy" src="https://github.com/user-attachments/assets/7f0b189a-8315-4b1e-9eb8-babbfcfb41e7" />

The next step I've documented is to set the delete phase directly through the Elasticsearch API instead of the UI:

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

## 3. Dashboards

To get from raw log entries to something I can read at a glance, I built a "SIEM Lab Overview" dashboard with two Lens panels.

The first, Log Volume Over Time, is a line chart of `@timestamp` against record count on a 30-minute interval, which makes volume spikes obvious. The second, Log Volume by Source, is a donut broken down by `log.file.path.keyword`, and it showed the actual split: 76.47% from `/var/log/auth.log` and 23.53% from `/var/log/syslog`. So most of what I'm capturing is authentication and session activity, not general system noise.

<img width="1280" height="738" alt="Log Volume Over Line Chart Panel" src="https://github.com/user-attachments/assets/05e0442d-4cbb-4b0c-87d4-f2e658e565c5" />

<img width="1280" height="738" alt="Donut Chart Panel" src="https://github.com/user-attachments/assets/84b204a1-ae57-43f2-abea-8c28e6e68f9f" />

<img width="1269" height="734" alt="Full Dashboard with both panels" src="https://github.com/user-attachments/assets/73997b9c-bb3c-40f9-b4d1-d14720805e62" />

One handy thing: Lens' "Suggestions" row at the bottom of the chart editor offers one-click chart-type changes based on the fields already assigned, usually faster than hunting through the chart-type dropdown.

## 4. Reading the authentication data

I wanted to practice the actual analyst skill of reading real auth data, not just charting it. I ran a few searches in Discover against the real `auth.log` and `syslog`:

| Search | Result | What it means |
|---|---|---|
| `message: "Failed password"` | 0 hits | No brute-force attempts, expected for a personal, non-internet-facing lab |
| `message: "session opened for user root"` | 7 hits | All `CRON[...]` entries, automatic scheduled tasks, not human logins. Normal noise. |
| `message: "sudo"` | 6 hits | Real, traceable privileged activity, see below |

The interesting one was a `sudo` entry:

```
sudo: ubuntuadmin : TTY=pts/0 ; PWD=/home/ubuntuadmin/elk-stack ; USER=root ; COMMAND=/usr/sbin/sysctl -w vm.max_map_count=262144
```

I could tie this straight to a real action of my own: re-applying the `vm.max_map_count` kernel setting after a VM reboot caused Elasticsearch to fail its healthcheck. `TTY=pts/0` confirmed it came from an interactive SSH session, not an automated script.

<img width="1280" height="736" alt="Sudo" src="https://github.com/user-attachments/assets/b94f71ed-03ec-45cb-83e2-ce0fb5f7e767" />

The lesson I took from this is that the first question about privileged activity isn't "is this bad?" but "can I account for this?" Activity I can trace to a known action, a real command, timestamp and reason, is resolved. Activity I can't explain is what warrants escalation.

## 5. Snapshot backups

Without backups, losing the `es_data` Docker volume means losing everything, so I set up a real recovery path.

I mounted a host folder into Elasticsearch (`./elasticsearch/snapshots:/usr/share/elasticsearch/snapshots`) and added `path.repo=/usr/share/elasticsearch/snapshots` to its environment, which is required because Elasticsearch refuses filesystem repositories unless they're explicitly allow-listed. I registered a shared-filesystem repository, `siem_lab_backups`, pointing at that path, and verified it, the status came back `Connected`, confirming Elasticsearch could actually read and write there rather than just that the config looked valid.

Then I created an SLM policy, `daily_siem_lab_backups`: daily at 01:30 (`0 30 1 * * ?`), covering all indices including global state, with retention set to delete after 14 days while keeping a minimum of 5 and a maximum of 10 snapshots. I ran it manually to confirm it works before waiting on the schedule. Result: 2 snapshots taken, 0 failures.

<img width="630" height="731" alt="Snapshot Showing connected" src="https://github.com/user-attachments/assets/b1e382c3-6865-4f65-a694-8bb70e5b101e" />

<img width="1096" height="662" alt="Policy summary" src="https://github.com/user-attachments/assets/5cd77c2d-425e-4c6a-ba5e-9c40895a7864" />

## What I took from this part

- Build least privilege the moment real data exists, not before. Scoping the role's index pattern against actual `filebeat-lab-*` documents was far more accurate than guessing in advance.
- A UI section failing to render isn't always a visible error. The ILM delete phase silently never appeared, with no message or console warning, which is a reminder to verify with an independent method (browser search, or the API) rather than assuming I'm misreading the screen.
- Lens' chart suggestions are a shortcut, not a guarantee. A suggested chart type can behave differently from selecting the same type manually, so it's worth checking the result.
- "Can I account for this?" beats "is this suspicious?" as the first triage question. Almost all privileged activity in a personal lab is explainable by my own actions; the skill is building the habit of actually checking.
- A verified backup isn't the same as a configured one. The `Connected` verification and the manual run were both needed to confirm the pipeline works end to end, not just that the settings saved.
- Filesystem Elasticsearch repositories need an explicit `path.repo` allow-list. That's a deliberate security control, not a bug.

---

This is a personal lab. The passwords, certificates and configs shown are for demonstration only and should never be reused in production.

[← Back to the SIEM Lab](../README.md)
