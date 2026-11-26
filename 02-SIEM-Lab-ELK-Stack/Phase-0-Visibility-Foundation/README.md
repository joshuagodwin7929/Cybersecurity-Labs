# Home SOC Lab, Phase 0: Visibility Foundation

This is the visibility foundation for my SIEM and detection lab: a small Active Directory environment (Domain Controller and a Windows 10 endpoint) feeding an ELK stack. Every later phase, attack simulation and detection engineering, depends on this one. The principle behind it is simple: you can't detect what you can't see, so before running any attacks I built the eyes.

## Lab architecture

- Domain Controller: Windows Server 2022, domain-joined
- Endpoint: Windows 10, domain-joined
- SIEM backend: Elastic Stack (Elasticsearch, Kibana) in Docker Compose on Ubuntu 22.04
- Log shipper: Winlogbeat on both Windows hosts

What I set out to do in this phase: deploy Sysmon on both hosts, turn on PowerShell script-block and module logging by GPO, configure Advanced Audit Policy for logon/logoff, Kerberos, account management and object access, put a SACL on a file share plus a canary file as a tripwire, and ship everything into Elasticsearch and confirm it in Kibana.

My exit criterion was deliberately mundane: search Kibana for a normal user logon and find it. If I can't find a benign logon, I won't find a malicious one either.

## 1. Sysmon

I installed Sysmon on both the DC and the Windows 10 endpoint using [SwiftOnSecurity's sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config), a well-documented single-file baseline that balances signal against noise.

```powershell
.\Sysmon64.exe -accepteula -i sysmonconfig-export.xml
```

Verified with:

```powershell
sc query sysmon64
Get-Service Sysmon64
```

<img width="365" height="196" alt="Sysmon WIN10" src="https://github.com/user-attachments/assets/c25ae283-375d-45ba-9413-b88117b22632" />

*Sysmon installed with the SwiftOnSecurity config, logging process creation and DNS query events.*

## 2. PowerShell logging (GPO)

Enabled under Computer Configuration → Administrative Templates → Windows Components → Windows PowerShell:

- Turn on Module Logging, with Module Names set to `*`
- Turn on PowerShell Script Block Logging

I validated it by generating some PowerShell activity and confirming Event IDs 4103 (pipeline execution) and 4104 (script block text) in `Microsoft-Windows-PowerShell/Operational`.

<img width="509" height="361" alt="Event ID 4103" src="https://github.com/user-attachments/assets/66a6b06c-ef90-4c9b-881c-ed2598c51039" />

<img width="511" height="359" alt="Event ID 4104" src="https://github.com/user-attachments/assets/18396c99-10b1-4315-8c7a-a26537aabf1e" />

## 3. Advanced Audit Policy (GPO)

Configured under Computer Configuration → Windows Settings → Security Settings → Advanced Audit Policy Configuration:

| Category | Subcategories | Event IDs |
|---|---|---|
| Logon/Logoff | Audit Logon, Audit Logoff | 4624, 4625, 4634 |
| Account Logon | Kerberos Authentication Service, Kerberos Service Ticket Operations | 4768, 4769, 4771, 4776 |
| Account Management | User Account Management, Security Group Management | 4720, 4722, 4724, 4738 |
| Object Access | File System, File Share | 4663 |

<img width="589" height="402" alt="All Audit Policy" src="https://github.com/user-attachments/assets/2d3cd735-8d7c-4a9a-8894-e2bcff598e30" />

*Logon/Logoff, Kerberos, Account Management and Object Access categories enabled.*

I also turned on "Audit: Force audit policy subcategory settings to override audit policy category settings" under Security Options, which is required so the legacy policy doesn't silently override these advanced settings. (In the later [03 lab](../../03-Active-Directory-ELK-SIEM-Lab/) I learned exactly what happens when it's off: account-lockout logging went missing.)

### File share auditing (SACL)

I applied a SACL directly to a departmental share, on its local folder path rather than the mapped drive, because Windows blocks SACL changes made over a mapped/remote drive unless you do them locally. It audits create files/write data, create folders/append data, and delete/delete subfolders and files. I also dropped a canary token file in the share as a lightweight, independent tripwire.

Validated by creating and deleting a test file and confirming Event ID 4663 in the Security log.

<img width="589" height="419" alt="Audit File Share" src="https://github.com/user-attachments/assets/fe3877f6-33c8-42f1-ba49-47ce4449b21d" />

<img width="587" height="407" alt="EventViewer 4663" src="https://github.com/user-attachments/assets/86798751-4085-4faf-b6cf-e34f06a449ee" />

*A create/delete on the audited share generating a searchable Security log event.*

## 4. Log shipping: Winlogbeat to Elasticsearch

I installed Winlogbeat (matched to the Elastic Stack version in use) on both hosts, shipping these logs:

```yaml
winlogbeat.event_logs:
  - name: Application
  - name: System
  - name: Security
  - name: Microsoft-Windows-Sysmon/Operational
  - name: Microsoft-Windows-PowerShell/Operational
```

<img width="584" height="452" alt="winlogbeat yml" src="https://github.com/user-attachments/assets/2f0c8847-7c30-4689-8943-7da65656c4c1" />

Output straight to Elasticsearch, bypassing Logstash to keep it simple:

```yaml
output.elasticsearch:
  hosts: ["https://<elk-host-ip>:9200"]
  ssl.verification_mode: none
  username: "elastic"
  password: "<redacted>"
```

Elastic Stack 8.x enables TLS on Elasticsearch by default with a self-signed certificate. `ssl.verification_mode: none` is fine for an isolated home lab but I wouldn't use it in production without proper CA-signed certs.

Installed and started as a Windows service:

```powershell
.\install-service-winlogbeat.ps1
Start-Service winlogbeat
```

## 5. Validation

In Kibana I created a `winlogbeat-*` data view and confirmed live Sysmon events (process create/terminate, DNS queries) streaming from both hosts, and that Event ID 4624 (successful logon) was searchable and attributable to a specific user, host and time:

```
event.code:4624
```

![Kibana Discover showing live winlogbeat-* data](https://github.com/user-attachments/assets/bcaa0dd5-2381-40ff-96ec-e60a8c8a93e7)

*Live Sysmon and Security events flowing from both hosts into the `winlogbeat-*` index.*

![Kibana search for event.code:4624 returning a logon event](https://github.com/user-attachments/assets/96c1d42e-d119-4c5c-8435-e89728939b9f)

*A normal user logon, fully searchable. That meets the exit criterion for this phase.*

## What I ran into

- Event Viewer's "Access is denied" errors were almost always a UAC token/elevation issue, not a real permissions gap. Running as Administrator explicitly cleared most of them.
- A SACL on a mapped network drive (`Y:\`) triggers a "remote setting" warning that strips inherited entries. Setting it on the actual local folder path on the file server avoids that.
- YAML is sensitive to whitespace and comment position. A `#` at the end of a line does nothing; it has to be the first character to comment the line out.
- Elastic Stack 8.x defaults to TLS-enabled Elasticsearch, so plan for `https://` and either proper certs or `ssl.verification_mode: none` in a lab.

With visibility established, the next phases move into controlled attack simulation and building detections against the telemetry captured here.

---

*This is a personal home lab for education and skills development. Hostnames, IPs and credentials in the examples are placeholders or redacted.*
