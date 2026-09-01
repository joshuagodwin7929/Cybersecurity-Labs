# Users & Organizational Units

Part of the [Active Directory Homelab](../) series.

## Objective
Design an OU structure that reflects a real multi-region organization, 
then provision users into it in a way that supports targeted Group 
Policy application and department-based access control.

## OU Design
Organized by region, then by department within each region, so GPOs 
and permissions can be scoped precisely instead of applied domain-wide:

```
Joshua.local

├── REGION (ASIA)
│   ├── Sales
│   ├── HR
│   ├── IT
│   ├── Management
│   └── Accounting
├── REGION (Europe)
│   ├── Sales
│   ├── HR
│   ├── IT
│   ├── Management
│   └── Accounting
└── REGION (USA)
    ├── Sales
    ├── HR
    ├── IT
    ├── Management
    └── Accounting
```

## User Provisioning
- Created 60 user accounts distributed across the 3 regional OUs and 
  5 department OUs
- Created accounts manually through Active Directory Users 
  and Computers (ADUC), assigning each to the correct regional/department OU
- Set initial passwords, home folder paths, and group memberships per department

## Screenshots
<img width="453" height="394" alt="Creating Organizational units" src="https://github.com/user-attachments/assets/aa51ffbf-970f-49e3-9a70-97921ee67fc0" />
<img width="462" height="545" alt="Organizational Units ASIA USERS" src="https://github.com/user-attachments/assets/e9a3caa6-a4ca-4c9e-8642-972359c9edaa" />
<img width="463" height="558" alt="Organizational Units EUROPE USERS" src="https://github.com/user-attachments/assets/03cfdda7-a836-42b4-b5e0-7bd59a336d78" />
<img width="461" height="597" alt="Organizational Units USA USERS" src="https://github.com/user-attachments/assets/522395b9-9140-4c00-8657-0998f3ed8f49" />


## What I Demonstrated
Understanding of how enterprise identity is structured for scale — OU 
design directly determines how Group Policy, permissions, and 
administrative delegation are scoped, which is core to both IT admin 
and SOC investigative work (e.g. tracing which policies apply to a 
compromised account).

## Notes / Lessons Learned
This part of the build went smoothly, since the OU structure was 
planned out before creating any accounts by deciding the region-then-department 
hierarchy up front meant user provisioning was mostly a matter of placing 
each account in the right OU rather than troubleshooting afterward. The 
main takeaway was how much a bit of planning before provisioning reduces 
rework later, especially once Group Policy and permissions get layered 
on top of the OU structure and how you solved them.
