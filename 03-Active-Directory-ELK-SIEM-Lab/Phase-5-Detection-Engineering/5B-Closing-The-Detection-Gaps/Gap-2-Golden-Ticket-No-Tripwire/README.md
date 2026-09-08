### Detection 2: Golden Ticket — Python-based 4769/4768 Correlation ###
 
**Gap closed:** Recommendation 3 — "Add a '4769 without a preceding
4768' correlation rule as a general-purpose tripwire for
credential-replay and forged-ticket activity."
 
#### Why this can't be a Kibana rule
 
Kibana's built-in Elasticsearch query rule type matches a single query, it cannot natively express "event A exists without event B preceding
it for the same principal." This is an absence-based, join-style
detection that requires either a dedicated SIEM with sequence support
(Elastic SIEM's EQL, Splunk correlation searches) or a custom script.
For this homelab, a Python script against the Elasticsearch API was
built.
 
#### The logic in plain English
 
Every normal Kerberos authentication produces two events in order:
1. **Event 4768** — TGT issued (the "master ticket" the KDC hands out at login)
2. **Event 4769** — TGS issued (a "service ticket" granted using the TGT)
A Golden Ticket is a **forged TGT** — the attacker created it
themselves using the krbtgt hash. The KDC never issued it, so:
 
- ❌ No 4768 — the attacker never actually logged in
- ✅ 4769 appears — Windows sees a valid-looking ticket and serves the request
**4769 with no 4768 in the preceding 10 hours (Kerberos ticket
lifetime) = forged ticket.**
 
#### What was built
 
**Script:** `golden-ticket-detect.py`
 
```python
#!/usr/bin/env python3
"""
Golden Ticket Detection Script
Detects Event 4769 (TGS request) with no preceding Event 4768 (TGT request)
for the same account within the last 10 hours (default Kerberos ticket lifetime).
Runs every 10 minutes via cron. Writes alerts to alerts-golden-ticket index.
"""
 
from elasticsearch import Elasticsearch
from datetime import datetime, timezone, timedelta
 
ES_HOST    = "https://elasticsearch:9200"
ES_USER    = "elastic"
ES_PASS    = "<redacted>"
INDEX      = "winlogbeat-*"
ALERT_INDEX = "alerts-golden-ticket"
TGT_WINDOW_HOURS   = 10
LOOK_BACK_MINUTES  = 10
 
es = Elasticsearch(ES_HOST, basic_auth=(ES_USER, ES_PASS), verify_certs=False)
 
now        = datetime.now(timezone.utc)
look_back  = now - timedelta(minutes=LOOK_BACK_MINUTES)
tgt_window = now - timedelta(hours=TGT_WINDOW_HOURS)
 
# Step 1 — Get all 4769 events in the look-back window
resp_4769 = es.search(index=INDEX, body={
    "size": 100,
    "query": {"bool": {"must": [
        {"term":  {"event.code": "4769"}},
        {"range": {"@timestamp": {"gte": look_back.isoformat()}}}
    ]}},
    "_source": ["@timestamp","winlog.event_data.TargetUserName",
                "winlog.computer_name","winlog.event_data.ServiceName"]
})
 
for hit in resp_4769["hits"]["hits"]:
    src     = hit["_source"]
    user    = src.get("winlog",{}).get("event_data",{}).get("TargetUserName","")
    service = src.get("winlog",{}).get("event_data",{}).get("ServiceName","")
    host    = src.get("winlog",{}).get("computer_name","")
    ts      = src.get("@timestamp","")
 
    if user.endswith("$") or user.lower() in ["","krbtgt"]:
        continue   # skip machine accounts and krbtgt itself
 
    # Step 2 — Check for a matching 4768 within the ticket-lifetime window
    resp_4768 = es.search(index=INDEX, body={
        "size": 1,
        "query": {"bool": {"must": [
            {"term":  {"event.code": "4768"}},
            {"term":  {"winlog.event_data.TargetUserName": user}},
            {"range": {"@timestamp": {"gte": tgt_window.isoformat()}}}
        ]}}
    })
 
    if resp_4768["hits"]["total"]["value"] == 0:
        print(f"[!] ALERT: 4769 with no 4768 — User: {user} | "
              f"Service: {service} | Host: {host} | Time: {ts}")
 
        # Step 3 — Write alert document to Elasticsearch
        es.index(index=ALERT_INDEX, body={
            "@timestamp":        now.isoformat(),
            "alert.type":        "golden_ticket_suspected",
            "alert.description": "TGS request (4769) with no matching TGT "
                                 "request (4768) in the last 10 hours",
            "user":              user,
            "service":           service,
            "host":              host,
            "event_time":        ts,
            "mitre.technique":   "T1558.001",
            "mitre.tactic":      "Credential Access"
        })
```
 
**Deployment notes:**
 
The script runs inside a lightweight Docker container on the elk-net
Docker network — this is required because the Elasticsearch container
uses TLS with an internal CA, and the cert is only valid for the
hostname `elasticsearch` (resolvable only inside the Docker network,
not from the Ubuntu host directly). The container approach avoids
modifying the ELK stack's TLS configuration.
 
```dockerfile
FROM python:3.10-slim
RUN pip install "elasticsearch>=8,<9"
COPY golden-ticket-detect.py /tmp/golden-ticket-detect.py
CMD ["python", "/tmp/golden-ticket-detect.py"]
```
 
Build: `docker build --network host -t gt-detect -f ~/Dockerfile.gtdetect ~`

<img width="1274" height="767" alt="Docker Image" src="https://github.com/user-attachments/assets/b506ccd4-98e5-4d4f-a5c7-b6f6d2940e85" />

 
Wrapper script (`run-gt-detect.sh`):
```bash
#!/bin/bash
docker run --rm --network elk-stack_elk-net gt-detect >> /home/ubuntuadmin/gt-detect.log 2>&1
```

<img width="1112" height="648" alt="image" src="https://github.com/user-attachments/assets/dcd41e8a-2263-4ea3-9036-af44fd1b22b6" />


Cron job (runs every 10 minutes):
```
*/10 * * * * /home/ubuntuadmin/run-gt-detect.sh
```
<img width="767" height="407" alt="cron-1 (1)" src="https://github.com/user-attachments/assets/8d2b00bb-e6f4-461d-85c3-c386fe7311e5" />


#### Positive test validation
 
Forged a Golden Ticket from Kali using the krbtgt AES256 key dumped
during DCSync:
 
```bash
impacket-ticketer \
  -aesKey b7e5d34062a5239bc10c33e0a0924cfde4609fd8cb677938bf6e77721e32afa9 \
  -domain-sid S-1-5-21-1811309030-1299588060-3855944835 \
  -domain joshua.local Administrator
 
export KRB5CCNAME=Administrator.ccache
impacket-smbclient -k -no-pass joshua.local/Administrator@joshua-server2022.joshua.local
```
 
The forged ticket authenticated to the DC and generated a 4769 for
`Administrator` with no preceding 4768. On the next cron run:
 
```
[*] Found 1 4769 events in the last 10 minutes
[!] ALERT: 4769 with no 4768 — User: Administrator@JOSHUA.LOCAL |
    Service: JOSHUA-SERVER20$ | Host: Joshua-Server2022.Joshua.local |
    Time: 2026-09-08T01:27:04.287Z
[+] Alert written to alerts-golden-ticket index ✅
```


<img width="1271" height="443" alt="Event 4769 captured" src="https://github.com/user-attachments/assets/46104fc6-f0e4-4c00-9168-db876c9c9ea3" />


#### Negative test validation
 
Normal interactive domain logon (j.jenkins logging into MY-LAB-PC) was
verified to produce a 4768 before 4769, the script correctly output
`[ok] j.jenkins has a valid 4768 — legitimate ticket` with no alert
written. No false positives generated on normal Kerberos activity.
 
#### False-positive considerations
 
- **Machine accounts** (ending in `$`) are explicitly excluded — DCs
  and member computers generate 4769s during normal background
  operations with no user-initiated 4768.
- **krbtgt itself** is excluded for the same reason.
- **Accounts with tickets from before the look-back window** could
  theoretically appear as false positives if the 4768 is older than 10
  hours — acceptable in this homelab context; a production deployment
  would adjust `TGT_WINDOW_HOURS` to match the environment's actual
  Kerberos ticket lifetime policy.
---
 
### Summary: Recommendations Closed
 
| Recommendation (from Incident Report) | Status |
|---|---|
| 1. Enable 4662 auditing with DCSync SACLs | ✅ Built, confirmed firing |
| 3. Add 4769-without-4768 correlation rule | ✅ Built, positive + negative test validated |
 
The two gaps that made DCSync and Golden Ticket "invisible" in the
original lab run are now instrumented. Both detections write evidence to
Elasticsearch — the DCSync rule via Kibana alerting, the Golden Ticket
via a custom Python script writing to `alerts-golden-ticket` index —
giving a future SOC analyst a query target for both.
