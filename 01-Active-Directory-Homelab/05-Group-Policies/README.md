# Group Policy Objects (GPOs)

Part of the [Active Directory Homelab](../) series.

## Objective
Enforce consistent security, usability, and access standards across all 
users and devices in the domain using Group Policy.

## Password Policy
- Configured via the Default Domain Policy GPO
- Set minimum password length: **12 Characters** (According to NIST SP 800-63B, this is the value
  most current security Baselines, and CIS Benchmark)
- Complexity requirements: **Enabled**
- Maximum password age: **90 days** (According to NIST SP 800-63B, No Mandatory Expiration)
- Minimum Password age: **1 day**
- Enforced Password History: **5 Passwords Remembered**
- Screenshot: ![Password policy GPO](../images/password-policy-gpo.png)
- <img width="580" height="399" alt="SPassword Policy GPO" src="https://github.com/user-attachments/assets/04fd713a-fcca-4915-b717-b485c1aced33" />



## Account Lockout Policy
- What I Configured:
- Account Lockout threshold: **5 invalid login attempts**
- Account Lockout Duration: **20 minutes**
- Account reset counter: **15 minutes**
- **Purpose:** mitigate brute-force login attempts against domain accounts
- Screenshot: ![Account lockout GPO](../images/lockout-policy-gpo.png)
- <img width="578" height="394" alt="Account Lockout Policy" src="https://github.com/user-attachments/assets/bd822bf7-bc22-471d-88c5-003f0a1f56ad" />


## Desktop Wallpaper GPO
- Deployed a standardized desktop wallpaper across all domain-joined 
  machines via **Group Policy Management > User Configuration > Policies > Administrative 
  Templates > Desktop**
- **Purpose:** enforce visual branding/consistency and reduce helpdesk 
  "cosmetic" support tickets
- Screenshot: ![Wallpaper GPO](../images/wallpaper-gpo.png)
- <img width="586" height="494" alt="Desktop Wallpaper GPO" src="https://github.com/user-attachments/assets/96062ba1-8de0-414e-84cf-f750a8537f04" />
- <img width="1175" height="678" alt="GPO Wallpaper" src="https://github.com/user-attachments/assets/e32f752f-64df-417c-ae43-561c8eb9f683" />


## Disable USB Storage GPO
- Blocked removable storage devices via **Computer Configuration > 
  Policies > Administrative Templates > System > Removable Storage Access**
- **Purpose:** reduce data exfiltration risk and unauthorized software 
  introduction via removable media — a common vector reviewed in 
  security hardening
- Screenshot: ![USB block GPO](../images/usb-block-gpo.png)
- <img width="682" height="451" alt="Screenshot 2026-07-24 045457" src="https://github.com/user-attachments/assets/5f26df50-fbb9-435b-a218-0c1afa398596" />


## Map Network Drive GPO
- Configured Group Policy Preferences to automatically map 5 department 
  drives on user login, scoped by OU/security group so each department 
  only sees its own share
- Screenshot: ![Mapped drives GPO](../images/mapped-drives-gpo.png)
- <img width="584" height="406" alt="image" src="https://github.com/user-attachments/assets/f734cdbe-e3f9-4ecb-b2d8-86d23e57165c" />
- <img width="538" height="323" alt="Screenshot 2026-06-17 150300" src="https://github.com/user-attachments/assets/f20b8eaa-d46f-43a2-adc4-3c1ebbb304a4" />




## What This Demonstrates
Hands-on application of the principle of least privilege and endpoint 
hardening through policy enforcement — skills directly relevant to 
reviewing GPO-based controls during a security assessment or incident 
investigation.

## Notes / Lessons Learned

**GPO conflict (competing settings):** Two GPOs ended up applying 
conflicting settings to the same OU — the mapped network drive policy 
was being overridden by another GPO linked higher in the OU hierarchy 
with a different drive letter assignment. Since GPOs apply in a defined 
order (Local > Site > Domain > OU, with later-applied policies winning 
by default), the higher-level GPO was taking precedence. Resolved by 
reviewing GPO precedence and either adjusting the link order or 
enforcing the correct GPO so the intended settings actually took effect 
for the target OU.

**Policy not applying immediately:** After creating and linking a new 
GPO, the client machine wasn't reflecting the change right away — 
Group Policy only refreshes on its own periodically (or at logon/reboot 
by default), so waiting for a natural refresh wasn't practical for 
testing. So, ran `gpupdate /force` on the client to trigger an immediate 
policy refresh, and used the Group Policy Results report (`gpresult /h 
report.html` or via the GPMC) to confirm exactly which GPOs were 
applying, in what order, and to catch cases where a setting wasn't 
being applied due to conflict or scope.

This reinforced that Group Policy troubleshooting is less about the 
individual setting and more about understanding precedence and scope — 
`gpresult` became the go-to tool for diagnosing why an expected policy 
wasn't taking effect.
