# Windows 10 Domain Join

Part of the [Active Directory Homelab](../) series.

## Objective
Join a Windows 10 client to the domain and verify it correctly receives 
policy, network configuration, and authentication from the domain 
controller.

## What I Configured
- Set the client's DNS server to point to the domain controller 
  ([192.168.18.50])
- Joined the machine to **Joshua.local** via System Properties > 
  Change > Domain
- Logged in with a domain user account to confirm authentication
- Verified the machine appears under Computers in Active Directory 
  Users and Computers
- Ran `gpupdate /force` and `gpresult /r` to confirm GPOs were applying 
  correctly (password policy, wallpaper, USB block, mapped drives)

## Screenshots
<img width="507" height="361" alt="Ethernet" src="https://github.com/user-attachments/assets/8cdddc66-1fea-42ab-8da1-17a5143dd343" />

<img width="233" height="264" alt="24 DNS" src="https://github.com/user-attachments/assets/10e74695-bf4f-46b8-953c-921e3041b55a" />

<img width="393" height="270" alt="Ethernet Join the Domain" src="https://github.com/user-attachments/assets/fb094153-a6b5-470e-bdf8-05707a58dbb5" />

<img width="508" height="380" alt="Ethernet Login page" src="https://github.com/user-attachments/assets/132d172f-7031-4b35-bd8b-e3dc7ec98342" />

<img width="509" height="379" alt="Ethernet Successful login" src="https://github.com/user-attachments/assets/7db4ca01-427a-4b15-93fe-4e6b7d301e65" />

<img width="478" height="253" alt="24 cmd 00" src="https://github.com/user-attachments/assets/68818e89-cc01-4d99-a086-adbfa79bfe04" />


## What This Demonstrates
Understanding of the client-side of domain membership — how a device 
authenticates against AD, inherits Group Policy, and becomes a managed 
endpoint. This is the perspective needed when investigating a 
compromised or misconfigured endpoint in a SOC context.

## Notes / Lessons Learned

**DNS misconfiguration during domain join:** The Windows 10 client 
initially failed to join the domain, with an error indicating the 
domain could not be found. The root cause was the client's network 
adapter still pointing to a public/default DNS server instead of the 
domain controller — since domain join relies on DNS to locate the 
domain controller via SRV records, not just plain hostname resolution, 
an incorrect DNS setting causes the join to fail even if the network 
itself is reachable.

Fixed by manually setting the client's preferred DNS server to the 
domain controller's IP address ([192.168.18.50]) in the network adapter 
settings, then retrying the domain join — which succeeded immediately 
afterward. This reinforced that DNS is a prerequisite for domain join, 
not just a nice-to-have — the client needs to resolve the domain's SRV 
records to even locate a domain controller to authenticate against.
