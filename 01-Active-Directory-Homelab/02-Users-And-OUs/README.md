# Users and Organizational Units

Part of the [Active Directory Homelab](../) series.

I wanted an OU structure that looks like a real multi-region company, so that Group Policy and permissions could be scoped precisely instead of applied across the whole domain. I organized it by region first, then by department within each region:

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

Then I created 60 user accounts spread across the 3 regional OUs and 5 department OUs. I made them by hand in Active Directory Users and Computers (ADUC), placing each in the right region and department OU and setting initial passwords, home folder paths and group memberships per department.

## Screenshots

<img width="453" height="394" alt="Creating Organizational units" src="https://github.com/user-attachments/assets/aa51ffbf-970f-49e3-9a70-97921ee67fc0" />
<img width="462" height="545" alt="Organizational Units ASIA USERS" src="https://github.com/user-attachments/assets/e9a3caa6-a4ca-4c9e-8642-972359c9edaa" />
<img width="463" height="558" alt="Organizational Units EUROPE USERS" src="https://github.com/user-attachments/assets/03cfdda7-a836-42b4-b5e0-7bd59a336d78" />
<img width="461" height="597" alt="Organizational Units USA USERS" src="https://github.com/user-attachments/assets/522395b9-9140-4c00-8657-0998f3ed8f49" />

## Notes

This part went smoothly, and the reason was planning the region-then-department hierarchy before creating any accounts. With the structure decided up front, provisioning was mostly placing each account in the right OU rather than fixing things afterward. The takeaway for me was how much a little planning before provisioning saves once Group Policy and permissions get layered on top. OU design decides how policy, permissions and delegation are scoped, which also matters in SOC work when you're tracing which policies applied to a compromised account.
