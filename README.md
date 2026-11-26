# AD-Attack-Defense-Lab

By OKUNNUWA JOSHUA GODWIN | [LinkedIn](https://www.linkedin.com/in/okunnuwa-joshua-godwin)

Three connected home labs. I built an Active Directory domain, built an Elastic SIEM to watch it, then attacked the domain one technique at a time and checked what the SIEM could and couldn't see.

My rule for all of it: **log first, attack second, hunt third, then formalize.**

## Start here

**[03: Active Directory + ELK SIEM Lab](03-Active-Directory-ELK-SIEM-Lab/)** is the main project. It runs a full attack chain against my domain, from LLMNR poisoning and password spraying through Kerberoasting, BloodHound path mapping and lateral movement to DCSync and a Golden Ticket. For each step I hunted for the attack in Kibana and wrote down where visibility broke. Then I closed the two biggest gaps and wrote the whole thing up as an incident report.

| Phase | What happens |
|---|---|
| [0: Visibility Foundation](03-Active-Directory-ELK-SIEM-Lab/Phase-0-Visibility-Foundation/) | Sysmon, PowerShell logging, Advanced Audit Policy, Winlogbeat into Elastic |
| [1: Credential Access](03-Active-Directory-ELK-SIEM-Lab/Phase-1-Credential-Access/) | LLMNR poisoning, password spraying, Kerberoasting, AS-REP Roasting |
| [2: Attack Path Mapping](03-Active-Directory-ELK-SIEM-Lab/Phase-2-Attack-Path-Mapping/) | SharpHound and BloodHound CE |
| [3: Lateral Movement](03-Active-Directory-ELK-SIEM-Lab/Phase-3-Lateral-Movement/) | A GPO misconfiguration, SMB, atexec as SYSTEM |
| [4: DCSync and Golden Ticket](03-Active-Directory-ELK-SIEM-Lab/Phase-4-DCSync-Golden-Ticket/) | Domain persistence, and the two attacks my SIEM couldn't see |
| [5: Detection Engineering](03-Active-Directory-ELK-SIEM-Lab/Phase-5-Detection-Engineering/) | Hunt queries for every technique, then closing the DCSync and Golden Ticket gaps |
| [6: Incident Report](03-Active-Directory-ELK-SIEM-Lab/Phase-6-Incident-Report/) | The full chain written up as an incident, with recommendations |

## The other two labs

| Lab | What I built |
|---|---|
| [01: Active Directory Homelab](01-Active-Directory-Homelab/) | The domain everything runs on: Windows Server 2022 DC, DNS, DHCP, OUs and groups, Group Policy, AD Certificate Services, file shares, and a domain-joined Windows 10 client |
| [02: SIEM Lab, ELK Stack](02-SIEM-Lab-ELK-Stack/) | The Elastic Stack in Docker Compose with TLS throughout, then (in [Part 4](02-SIEM-Lab-ELK-Stack/Part-4-Continuation/)) least-privilege users, index lifecycle management, dashboards and snapshot backups |

## Where this work continued

The hunt queries from Phase 5 didn't stop here:

- **[Detection-Engineering](https://github.com/joshuagodwin7929/Detection-Engineering):** they became Sigma rules, compiled to Elastic with a CI check on every push.
- **[Purple-Team-Automation](https://github.com/joshuagodwin7929/Purple-Team-Automation):** I ran the attacks again through MITRE Caldera and validated each rule with a live Kibana alert. That re-test also caught a bug in my Phase 5B DCSync rule, which is now corrected [here](03-Active-Directory-ELK-SIEM-Lab/Phase-5-Detection-Engineering/5B-Closing-The-Detection-Gaps/Gap-1-DCSync-No-Audit-Trail/README.md#the-correction-november-2026).

## How each write-up reads

Each phase is written as notes from doing the work: what I did and in what order, what went wrong, what I'd change, and the screenshots that back it up. The facts and evidence come first, not a polished narrative.

## Repo layout

```text
AD-Attack-Defense-Lab/
├── 01-Active-Directory-Homelab/
├── 02-SIEM-Lab-ELK-Stack/
├── 03-Active-Directory-ELK-SIEM-Lab/
├── LICENSE
└── README.md
```

## Disclaimer

Everything here ran in an isolated lab I own. No production systems, third-party networks or real user data were involved. Passwords, hashes and IP addresses shown are lab-only values.
