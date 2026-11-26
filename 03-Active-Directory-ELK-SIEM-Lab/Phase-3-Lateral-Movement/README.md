# Phase 3: Lateral Movement and Privilege Escalation

The question for this phase: once an attacker has one low-privilege domain account, how far can they move, and does my SIEM see it?

I took `j.jenkins`, the account I'd compromised with AS-REP Roasting in [Phase 1](../Phase-1-Credential-Access), moved onto the Windows 10 workstation over the network, got `NT AUTHORITY\SYSTEM` there, and then traced every step back to raw events in Elastic.

```
Standard Domain User (j.jenkins)
        │
        ▼  (BloodHound: no existing path found)
Simulated a realistic misconfiguration via GPO
        │
        ▼  (Local Admin on MY-LAB-PC)
Remote Authentication over SMB (NetExec)
        │
        ▼  (4624 Type 3 Network Logon - logged)
Remote Code Execution (WMI failed → fell back to atexec)
        │
        ▼  (Sysmon Event ID 1 - logged, 61ms after logon)
NT AUTHORITY\SYSTEM
```

## What I used

| | |
|---|---|
| Attacker | Kali Linux, NetExec, Impacket |
| Path mapping | BloodHound CE (Docker) |
| Targets | Windows Server 2022 DC, Windows 10 workstation `MY-LAB-PC` |
| Telemetry | Sysmon (SwiftOnSecurity config), Winlogbeat |
| SIEM | Elasticsearch and Kibana 8.12.0 |
| Directory changes | Group Policy (Restricted Groups, Security Filtering) |

## How it went

### No path existed, so I created a realistic one

I re-ran BloodHound first. `j.jenkins` had no local admin or execution rights anywhere; only the built-in `Administrator` was local admin on `MY-LAB-PC`.

Instead of handing myself a shortcut, I recreated a mistake I'd expect to find in a real network: a support account that has picked up local admin rights it no longer needs. I made a narrowly scoped GPO, `Workstation-LocalAdmin-RestrictedGroups`, that gives a few standard users local admin on `MY-LAB-PC` only. I scoped it with Security Filtering on that one computer object, rather than moving it to a new OU, so nothing else in the domain was affected.

### A silent blocker: the firewall

My first lateral movement attempts failed with no useful error. The cause was on the target: the **Domain-profile** firewall rule for inbound SMB was disabled. The Private and Public profile copies were enabled, which hid the problem when I first looked. That's a legitimate control doing its job. I enabled it for the lab:

```powershell
Set-NetFirewallRule -DisplayName "File and Printer Sharing (SMB-In)" -Profile Domain -Enabled True
```

### Moving onto the workstation

```bash
netexec smb <target-ip> -u j.jenkins -p '<redacted>' -d joshua.local
```

NetExec returned `(Pwn3d!)`: admin-level SMB access. On the target this created a **4624 Type 3 (network logon)** event.

### Running code as SYSTEM

```bash
netexec smb <target-ip> -u j.jenkins -p '<redacted>' -d joshua.local -x whoami
```

NetExec's default WMI execution failed with a DCOM error, and it quietly fell back to **atexec**. atexec runs commands through the Task Scheduler service, which lives in a shared `svchost.exe -k netsvcs` process and runs as SYSTEM. So the fallback gave me `NT AUTHORITY\SYSTEM` in one step.

### Finding it in Kibana

```
event.code:4624 and winlog.event_data.LogonType:"3" and winlog.event_data.TargetUserName:"j.jenkins"
```

```
event.code:1 and process.parent.name:"svchost.exe"
```

The Sysmon Event ID 1 for `whoami.exe` landed **61 milliseconds** after the logon. That gave me a clean timeline from network logon to code execution.

## What I learned

- **No path isn't the end.** When BloodHound found nothing, the useful question was what everyday misconfiguration would create one.
- **Silent failures teach the most.** The firewall rule failed with no error from the attack tool. I only found it by checking the target's configuration, not my command.
- **Learn your tools' fallbacks.** The WMI-to-atexec switch looked like a quirk at first. Working out why it happened, and what it leaves behind, taught me more than a clean first-time success would have.
- **A process tree alone isn't proof.** `svchost.exe` spawning `cmd.exe` happens with legitimate scheduled tasks all the time. What makes this one suspicious is the context: 61 ms after an unusual network logon, the account behind it, and output redirected to a random temp file.
- **Trust ground truth over one tool.** BloodHound's graph didn't show the GPO change I'd already confirmed on the machine. `net localgroup administrators` and a live attempt were right; BloodHound was missing it because of a SAMR enumeration restriction on the workstation.

## What I'd do next

- Allow remote SAMR enumeration (`RestrictRemoteSAM`) in the lab, so BloodHound reflects changes like this one.
- Write a detection for atexec specifically. Most public content targets PsExec and WMI. A rule for `svchost.exe -k netsvcs` spawning a shell with output redirected to `%WINDIR%\Temp\<random>` would catch it. I later wrote this as a Sigma rule in [Detection-Engineering](https://github.com/joshuagodwin7929/Detection-Engineering).
- Add network-level monitoring (Zeek or Suricata). All the evidence here came from endpoint logs.
- Automate the BloodHound collection and import. Doing it by hand with `scp` and a web upload cost me a lot of time while troubleshooting.

## Evidence

Internal IPs, sensitive hostnames and credentials are redacted.

**The Restricted Groups GPO, giving local admin on the target workstation only**

<img width="523" height="401" alt="01-gpo-restricted-groups-01" src="https://github.com/user-attachments/assets/3e5323b3-1f68-431d-8003-e181656085e6" />

<img width="502" height="352" alt="01-gpo-restricted-groups-02" src="https://github.com/user-attachments/assets/c55de097-28fa-4cd6-9973-2db39d78cc95" />

**Security Filtering scoped to the target computer object**

<img width="644" height="737" alt="02-security-filtering" src="https://github.com/user-attachments/assets/d4c5e13b-797d-4a61-bdde-318fdaf62504" />

**NetExec showing `(Pwn3d!)` with the low-privilege account**

<img width="539" height="397" alt="04-netexec-pwn3d" src="https://github.com/user-attachments/assets/9016e7fb-434c-4022-8c9c-0c6f1d56c9bb" />

**WMI fails, NetExec falls back to atexec, and `whoami` returns `nt authority\system`**

<img width="539" height="395" alt="05-atexec-fallback" src="https://github.com/user-attachments/assets/243bf310-afbc-41a6-89f0-a486f9dae78e" />

**The 4624 Type 3 logon in Kibana (Elevated Token: Yes)**

<img width="638" height="735" alt="06-kibana-4624-logon" src="https://github.com/user-attachments/assets/c05964fd-d006-4e4b-8a71-15a5fd912d79" />

**Sysmon Event ID 1: `whoami.exe` under `cmd.exe` under `svchost.exe -k netsvcs`, output redirected to a temp file, 61 ms after the logon**

<img width="642" height="689" alt="07-kibana-sysmon-whoami" src="https://github.com/user-attachments/assets/684019d8-ab82-4ddd-bafc-0e560704b4bb" />

---

Previous: [Phase 2](../Phase-2-Attack-Path-Mapping) · Next: [Phase 4: DCSync and Golden Ticket](../Phase-4-DCSync-Golden-Ticket) · Back to the [lab overview](../README.md)

*Everything here ran in an isolated lab I own. No production systems or real user data were involved.*
