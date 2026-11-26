# Group Policy Objects (GPOs)

Part of the [Active Directory Homelab](../) series.

I used Group Policy to enforce consistent security, usability and access settings across the domain. Five policies, each with its purpose below.

## Password policy

Set in the Default Domain Policy:

- Minimum length: 12 characters (in line with NIST SP 800-63B and the CIS Benchmark)
- Complexity requirements: enabled
- Maximum password age: 90 days (NIST SP 800-63B leans against mandatory expiration, but I set one here)
- Minimum password age: 1 day
- Password history: 5 remembered

<img width="580" height="399" alt="Password Policy GPO" src="https://github.com/user-attachments/assets/04fd713a-fcca-4915-b717-b485c1aced33" />

## Account lockout policy

To slow brute-force attempts against domain accounts:

- Lockout threshold: 5 invalid attempts
- Lockout duration: 20 minutes
- Reset counter: 15 minutes

<img width="578" height="394" alt="Account Lockout Policy" src="https://github.com/user-attachments/assets/bd822bf7-bc22-471d-88c5-003f0a1f56ad" />

## Desktop wallpaper

A standard wallpaper pushed to all domain-joined machines through User Configuration → Policies → Administrative Templates → Desktop, for visual consistency and fewer cosmetic helpdesk tickets.

<img width="586" height="494" alt="Desktop Wallpaper GPO" src="https://github.com/user-attachments/assets/96062ba1-8de0-414e-84cf-f750a8537f04" />
<img width="1175" height="678" alt="GPO Wallpaper" src="https://github.com/user-attachments/assets/e32f752f-64df-417c-ae43-561c8eb9f683" />

## Disable USB storage

Blocked removable storage through Computer Configuration → Policies → Administrative Templates → System → Removable Storage Access, to cut the risk of data exfiltration and unauthorized software coming in on removable media.

<img width="682" height="451" alt="Disable USB storage GPO" src="https://github.com/user-attachments/assets/5f26df50-fbb9-435b-a218-0c1afa398596" />

## Map network drives

Group Policy Preferences to map the 5 department drives at login, scoped by OU and security group so each department only sees its own share.

<img width="584" height="406" alt="Map network drive GPO" src="https://github.com/user-attachments/assets/f734cdbe-e3f9-4ecb-b2d8-86d23e57165c" />
<img width="538" height="323" alt="Mapped drives result" src="https://github.com/user-attachments/assets/f20b8eaa-d46f-43a2-adc4-3c1ebbb304a4" />

## What went wrong

**Two GPOs fought over the same setting.** My mapped-drive policy was being overridden by another GPO linked higher in the OU hierarchy that assigned a different drive letter. GPOs apply in order (Local, Site, Domain, OU, with later policies winning by default), so the higher-level one was taking precedence. I sorted it by reviewing GPO precedence and adjusting the link order so the intended settings actually applied to the target OU.

**A new policy didn't apply right away.** After linking a GPO, the client didn't reflect the change immediately, because Group Policy only refreshes periodically or at logon/reboot. Waiting wasn't practical for testing, so I ran `gpupdate /force` on the client and used the Group Policy Results report (`gpresult /h report.html`, or through the GPMC) to see exactly which GPOs were applying, in what order, and where a setting wasn't taking effect because of a conflict or scope.

The main thing I took away is that GPO troubleshooting is less about the individual setting and more about precedence and scope. `gpresult` became my go-to for working out why an expected policy wasn't applying, which is the same skill I'd use reviewing GPO-based controls during a security assessment.
