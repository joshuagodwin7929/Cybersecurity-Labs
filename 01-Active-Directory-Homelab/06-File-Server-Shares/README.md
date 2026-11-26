# File Server and Department Shares

Part of the [Active Directory Homelab](../) series.

I set up a file server with one share per department, locked down so each department can only reach its own data.

I installed the File and Storage Services role on `Joshua-Server2022` and created five department shares: Sales, HR, IT, Management and Accounting. For each one I scoped the NTFS permissions to that department's security group (the groups come from the OU structure in [02-Users-And-OUs](../02-Users-And-OUs)), then set share-level permissions to match, so only the relevant group gets Modify/Read rather than leaving anything at "Everyone: Full Control."

Then I logged in as users from different departments to confirm the isolation held, for example that an HR user can't browse the Finance share.

## Screenshots

<img width="584" height="406" alt="Share file department" src="https://github.com/user-attachments/assets/7781028d-3195-47f0-bf4c-ac06fa2f758b" />
<img width="572" height="395" alt="File Share Permission" src="https://github.com/user-attachments/assets/e37fa425-f153-4c6b-a090-374ae222a630" />
<img width="508" height="356" alt="Access Test" src="https://github.com/user-attachments/assets/1159cbe0-1ac9-4556-8d76-20521ec31098" />

## Notes

There were no permission conflicts to untangle here, and I think that's because I scoped least privilege from the start: NTFS permissions tied to each department's group, share permissions matched to them, nothing left wide open. Testing access as different users early confirmed the isolation was working before I moved on, instead of finding a misconfiguration later. Access control like this is a core control during access audits, and keeping departments separated is one of the things that limits how far an attacker can move sideways during an incident.
