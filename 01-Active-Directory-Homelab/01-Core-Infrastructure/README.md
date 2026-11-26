# Core Infrastructure: AD DS, DNS and DHCP

Part of the [Active Directory Homelab](../) series.

This is the foundation the rest of the homelab sits on: Active Directory Domain Services, DNS and DHCP on a single Windows Server 2022 box (`Joshua-Server2022`, domain `joshua.local`, running on VMware). The goal was to stand up identity, internal name resolution and automated client networking, then actually validate each one rather than assume it worked.

## Active Directory Domain Services

I installed the AD DS role, promoted `Joshua-Server2022` to a Domain Controller, created the forest, and created the `joshua.local` domain. That made the server the identity backbone for everything that follows.

I checked DC health and replication with:

```powershell
dcdiag
```

```powershell
repadmin /replsummary
```

## DNS

AD depends heavily on DNS to locate domain services, so this had to be solid. I installed the DNS Server role on the DC, created the forward lookup zone for `joshua.local`, and made it Active Directory-integrated so it replicates with AD.

I tested resolution with:

```powershell
nslookup joshua.local
```

```powershell
Resolve-DnsName joshua.local
```

## DHCP

I installed the DHCP Server role, authorized it in Active Directory, created a scope for the lab network, and set the lease duration, default gateway and DNS server options. Then I confirmed a client could pull its config:

```powershell
ipconfig /all
```

I checked the client got an IP, subnet, default gateway, DNS server, DHCP server and a valid lease.

## What went wrong

**DNS didn't resolve right away.** After I created the AD-integrated zone, a test client couldn't resolve the domain. The zone config looked correct, so I suspected replication rather than DNS itself, and forced it:

```powershell
repadmin /syncall
```

Once replication finished, resolution worked. The DNS records simply hadn't reached the client yet. The lesson: AD-integrated DNS changes depend on AD replication and won't appear everywhere instantly, so check replication status before changing DNS config you've already got right.

**A DHCP/static IP conflict.** A statically configured device clashed with an address DHCP had handed to another client. The static IP sat inside the DHCP allocation range, so the server was free to lease it out. I added an exclusion range to keep infrastructure addresses out of the dynamic pool. The takeaway is to plan static addresses before building the scope: reserve part of the subnet for infrastructure, and keep those addresses either outside the scope or explicitly excluded.

## Validation

| Check | Method | Result |
|---|---|---|
| Domain Controller health | `dcdiag` | Passed |
| AD replication | `repadmin` | Passed |
| DNS resolution | `nslookup`, `Resolve-DnsName` | Passed |
| DHCP authorization | AD / DHCP console | Passed |
| DHCP assignment, gateway, DNS on client | `ipconfig /all` | Passed |

The big lessons from this module carried through the rest of the lab: AD leans on DNS, AD-integrated DNS leans on replication, DHCP scope design has to account for static infrastructure, and troubleshooting should start from evidence rather than assumptions.

## Related modules

| Module | Description |
|---|---|
| [02: Users & OUs](../02-Users-And-OUs/) | OUs, users, groups, department structure |
| [03: Certificate Services](../03-Certificate-Services/) | AD Certificate Services and PKI |
| [04: Client Domain Join](../04-Client-Domain-Join/) | Joining Windows clients to the domain |
| [05: Group Policies](../05-Group-Policies/) | Security policies and centralized configuration |
| [06: File Server & Shares](../06-File-Server-Shares/) | Department shares and NTFS permissions |

---

[← Back to Active Directory Homelab](../)
