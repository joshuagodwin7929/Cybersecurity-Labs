# Windows 10 Domain Join

Part of the [Active Directory Homelab](../) series.

I joined a Windows 10 client to the domain and checked that it actually received policy, network config and authentication from the domain controller.

I pointed the client's DNS at the domain controller (`192.168.18.50`), joined it to `Joshua.local` through System Properties → Change → Domain, and logged in with a domain account to confirm authentication worked. I verified the machine showed up under Computers in ADUC, then ran `gpupdate /force` and `gpresult /r` to confirm the GPOs were applying (password policy, wallpaper, USB block, mapped drives).

## Screenshots

<img width="507" height="361" alt="Ethernet" src="https://github.com/user-attachments/assets/8cdddc66-1fea-42ab-8da1-17a5143dd343" />

<img width="233" height="264" alt="24 DNS" src="https://github.com/user-attachments/assets/10e74695-bf4f-46b8-953c-921e3041b55a" />

<img width="393" height="270" alt="Ethernet Join the Domain" src="https://github.com/user-attachments/assets/fb094153-a6b5-470e-bdf8-05707a58dbb5" />

<img width="508" height="380" alt="Ethernet Login page" src="https://github.com/user-attachments/assets/132d172f-7031-4b35-bd8b-e3dc7ec98342" />

<img width="509" height="379" alt="Ethernet Successful login" src="https://github.com/user-attachments/assets/7db4ca01-427a-4b15-93fe-4e6b7d301e65" />

<img width="478" height="253" alt="24 cmd 00" src="https://github.com/user-attachments/assets/68818e89-cc01-4d99-a086-adbfa79bfe04" />

## What went wrong

The client failed to join at first, with an error saying the domain couldn't be found. The cause was that its network adapter was still pointing at a public DNS server instead of the domain controller. Domain join relies on DNS to locate the DC through SRV records, not just plain hostname resolution, so the join fails even when the network itself is reachable.

I fixed it by setting the client's preferred DNS to the domain controller's IP (`192.168.18.50`) and retrying, which joined immediately. The lesson stuck: DNS is a prerequisite for domain join, not a nice-to-have. The client has to resolve the domain's SRV records before it can even find a DC to authenticate against. This is also the client-side view I'd need when investigating a compromised or misconfigured endpoint: how a device authenticates against AD, inherits Group Policy and becomes a managed endpoint.
