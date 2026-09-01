# File Server & Department Shares

Part of the [Active Directory Homelab](../) series.

## Objective
Stand up a file server with department-based shares, secured with 
appropriate NTFS and share permissions, so each department can only 
access its own data.

## What I Configured
- Installed the File and Storage Services role on [Joshua-Server2022]
- Created 5 department shares:
- **Sales**
- **HR**,
- **IT**
- **Management**
- **Accounting**
- Configured NTFS permissions scoped to each department's security group 
  (created from the OU structure in [02-users-and-ous](../02-users-and-ous))
- Configured share-level permissions to complement NTFS permissions 
  (principle of least privilege — only the relevant department group 
  gets Modify/Read access)
- Tested access as different department users to confirm isolation 
  (e.g. HR user cannot browse the Finance share)

## Screenshots
![Share setup](../images/file-shares.png)
![NTFS permissions](../images/ntfs-permissions.png)
![Access test](../images/access-test.png)
- <img width="584" height="406" alt="Share file department" src="https://github.com/user-attachments/assets/7781028d-3195-47f0-bf4c-ac06fa2f758b" />
- <img width="572" height="395" alt="File Share Permission" src="https://github.com/user-attachments/assets/e37fa425-f153-4c6b-a090-374ae222a630" />
- <img width="508" height="356" alt="Access Test" src="https://github.com/user-attachments/assets/1159cbe0-1ac9-4556-8d76-20521ec31098" />



## What This Demonstrates
Practical application of access control principles — ensuring data is 
only accessible to authorized groups, which is a core control reviewed 
during access audits and a key concept in preventing lateral movement 
during a security incident.

## Notes / Lessons Learned

No major permission conflicts here — applying the principle of least 
privilege from the start (scoping NTFS permissions to each department's 
security group, then matching share permissions rather than leaving 
them at "Everyone: Full Control") avoided the most common cause of 
access issues on file servers. Testing access as different department 
users early on confirmed isolation was working correctly before moving 
on, rather than discovering a misconfiguration later.
