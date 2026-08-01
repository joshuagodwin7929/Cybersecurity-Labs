# Home SOC Lab — Phase 0: Visibility Foundation
 
A personal SIEM/detection lab built around a small Active Directory environment (Domain Controller + Windows 10 endpoint) feeding into an ELK stack (Elasticsearch, Logstash, Kibana). This repo documents **Phase 0**, the visibility foundation that every later phase (attack simulation, detection engineering) depends on.
 
> **Principle:** you can't detect what you can't see. Before running any attacks, build the eyes.
 
## Lab Architecture
 
- **Domain Controller** — Windows Server 2022, domain-joined AD environment
- **Endpoint** — Windows 10, domain-joined
- **SIEM backend** — Elastic Stack (Elasticsearch, Kibana) via Docker Compose on Ubuntu 22.04
- **Log shipper** — Winlogbeat on both Windows hosts

## Phase 0 Objectives
 
1. Deploy Sysmon on both hosts for granular process, network, and file telemetry
2. Enable PowerShell Script Block and Module Logging via Group Policy
3. Configure Advanced Audit Policy for logon/logoff, Kerberos, account management, and object access
4. Set a SACL on a file share to audit file creation/deletion, plus a canary token as a tripwire
5. Ship all logs into Elasticsearch and validate visibility in Kibana
**Exit criteria:** search Kibana for a normal user logon and find it. If you can't find a benign logon, you won't find a malicious one either.
 
## 1. Sysmon Deployment
 
Installed on both the DC and the Windows 10 endpoint using [SwiftOnSecurity's sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config) — a well-documented, single-file baseline that balances signal (attacker-relevant behavior) against noise (routine Windows/background activity).
 
```powershell
.\Sysmon64.exe -accepteula -i sysmonconfig-export.xml
```
 
Verified via:
```powershell
sc query sysmon64
Get-Service Sysmon64
```
 [Screenshot:Sysmon service running and generating events](./screenshots/sysmon-running.png)

 
 <img width="365" height="196" alt="Sysmon WIN10" src="https://github.com/user-attachments/assets/c25ae283-375d-45ba-9413-b88117b22632" />

 
## 2. PowerShell Logging (GPO)
 
Enabled via **Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell**:
 
- **Turn on Module Logging** — Module Names: `*`
- **Turn on PowerShell Script Block Logging** — Enabled
Validated by generating PowerShell activity and confirming Event IDs **4103** (pipeline execution) and **4104** (script block text) in `Microsoft-Windows-PowerShell/Operational`.

[Screenshot:PowerShell 4103/4104 events in Event Viewer](./screenshots/powershell-logging.png)


<img width="509" height="361" alt="Event ID 4103" src="https://github.com/user-attachments/assets/66a6b06c-ef90-4c9b-881c-ed2598c51039" />



[Screenshot:PowerShell 4103/4104 events in Event Viewer](./screenshots/powershell-logging.png)


<img width="511" height="359" alt="Event ID 4104" src="https://github.com/user-attachments/assets/18396c99-10b1-4315-8c7a-a26537aabf1e" />



 
## 3. Advanced Audit Policy (GPO)
 
Configured under **Computer Configuration > Windows Settings > Security Settings > Advanced Audit Policy Configuration**:
 
| Category | Subcategories | Event IDs |
|---|---|---|
| Logon/Logoff | Audit Logon, Audit Logoff | 4624, 4625, 4634 |
| Account Logon | Kerberos Authentication Service, Kerberos Service Ticket Operations | 4768, 4769, 4771, 4776 |
| Account Management | User Account Management, Security Group Management | 4720, 4722, 4724, 4738 |
| Object Access | File System, File Share | 4663 |

[Screenshot:Advanced Audit Policy categories configured in Group Policy Management Editor](./screenshots/audit-policy-gpo.png)


<img width="589" height="402" alt="All Audit Policy" src="https://github.com/user-attachments/assets/2d3cd735-8d7c-4a9a-8894-e2bcff598e30" />

 
Also enabled: **"Audit: Force audit policy subcategory settings to override audit policy category settings"** under Security Options — required so legacy policy doesn't silently override the advanced settings above.
 
### File Share Auditing (SACL)
 
A SACL was applied directly to a departmental share (on its local folder path, not the mapped drive — remote/mapped-drive auditing changes are blocked by Windows unless done locally) auditing:
- Create files / write data
- Create folders / append data
- Delete / Delete subfolders and files
A canary token file was also placed in the share as a lightweight, independent tripwire.
Validated by creating/deleting a test file and confirming **Event ID 4663** in the Security log.

[Screenshot: Audit File Share]


<img width="589" height="419" alt="Audit File Share" src="https://github.com/user-attachments/assets/fe3877f6-33c8-42f1-ba49-47ce4449b21d" />

 

[Screenshot: Event 4663 confirming file share object access auditing](./screenshots/event-4663.png)


<img width="587" height="407" alt="EventViewer 4663" src="https://github.com/user-attachments/assets/86798751-4085-4faf-b6cf-e34f06a449ee" />


 
## 4. Log Shipping — Winlogbeat → Elasticsearch
 
Winlogbeat (matched to the Elastic Stack version in use) installed on both hosts, configured to ship:
 
```yaml
winlogbeat.event_logs:
  - name: Application
  - name: System
  - name: Security
  - name: Microsoft-Windows-Sysmon/Operational
  - name: Microsoft-Windows-PowerShell/Operational
```

[Screenshot:Kibana Discover showing live winlogbeat-* data]


<img width="584" height="452" alt="winlogbeat yml" src="https://github.com/user-attachments/assets/2f0c8847-7c30-4689-8943-7da65656c4c1" />

 
Output configured directly to Elasticsearch (bypassing Logstash for simplicity):
 
```yaml
output.elasticsearch:
  hosts: ["https://<elk-host-ip>:9200"]
  ssl.verification_mode: none
  username: "elastic"
  password: "<redacted>"
```
 
> **Note:** Elastic Stack 8.x enables TLS on Elasticsearch by default with a self-signed certificate. `ssl.verification_mode: none` is acceptable for an isolated home lab — not recommended for production without proper CA-signed certs.
 
Installed and started as a Windows service:
```powershell
.\install-service-winlogbeat.ps1
Start-Service winlogbeat
```
 
## 5. Validation
 
In Kibana, created a `winlogbeat-*` data view and confirmed:
- Live Sysmon events (process create/terminate, DNS queries) streaming from both hosts
- **Event ID 4624** (successful logon) searchable and attributable to a specific user, host, and time
```
event.code:4624
```
[Screenshot: Kibana Discover showing live winlogbeat-* data](./screenshots/kibana-winlogbeat-data.png


<img width="1280" height="735" alt="Winlogbeat Liveview" src="https://github.com/user-attachments/assets/bcaa0dd5-2381-40ff-96ec-e60a8c8a93e7" />


This confirmed the core Phase 0 exit criteria: full "who logged into what, when" visibility across the domain.



[Screenshot: Event 4624]


<img width="1280" height="734" alt="event 4624" src="https://github.com/user-attachments/assets/96c1d42e-d119-4c5c-8435-e89728939b9f" />

 


 
## Screenshots
 
> Screenshots below are organized by step. Replace the placeholder paths with your own images (recommend a `/screenshots` folder in this repo, referenced as `./screenshots/filename.png`).
 
### Sysmon Deployment
![Sysmon service running and generating events](./screenshots/sysmon-running.png)
*Sysmon installed with the SwiftOnSecurity config, actively logging process creation and DNS query events.*
 
### PowerShell Logging
![PowerShell 4103/4104 events in Event Viewer](./screenshots/powershell-logging.png)
*Script Block Logging (4104) and Module Logging (4103) confirmed in the PowerShell Operational log.*
 
### Advanced Audit Policy — GPO Configuration
![Advanced Audit Policy categories configured in Group Policy Management Editor](./screenshots/audit-policy-gpo.png)
*Logon/Logoff, Kerberos, Account Management, and Object Access categories enabled.*
 
### File Share SACL & Event ID 4663
![Event 4663 confirming file share object access auditing](./screenshots/event-4663.png)
*A create/delete on an audited file share generating a searchable Security log event.*
 
### Winlogbeat → Elasticsearch Pipeline
![Kibana Discover showing live winlogbeat-* data](./screenshots/kibana-winlogbeat-data.png)
*Live Sysmon and Security events flowing from both hosts into the winlogbeat-* index.*
 
### Final Validation — Event ID 4624
![Kibana search for event.code:4624 returning a logon event](./screenshots/event-4624-validation.png)
*A normal user logon, fully searchable — meeting Phase 0's exit criteria.*
 
## Lessons Learned
 
- Event Viewer's "Access is denied" errors are almost always a UAC token/elevation issue, not a real permissions gap — running as Administrator explicitly resolves most of them.
- SACLs on a mapped network drive (`Y:\`) will trigger a "remote setting" warning that strips inherited entries — set them on the actual local folder path on the file server instead.
- YAML is whitespace- and comment-position-sensitive. A `#` at the end of a line does nothing; it must be the very first character to comment out a line.
- Elastic Stack 8.x defaults to TLS-enabled Elasticsearch — plan for `https://` and either proper certs or `ssl.verification_mode: none` in a lab context.
## Next Steps
 
With visibility now established, the next phases move into controlled attack simulation and building/validating detections against the telemetry captured here.
 
---
 
*This is a personal home lab for education and skills development. All hostnames, IPs, and credentials referenced in configuration examples are placeholders/redacted.*
 


