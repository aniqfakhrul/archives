---
title: Utilizing Trust Accounts for Benefits
tags:
- active directory
- posts
---

## Introduction
Before we begin with the blogpost, this whole idea is inspired by the original [article](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted) by Improsec which explained the concept really well. Lets beging with a simple definition of a Forest trust, it is a trust connection between two or multiple forests to communicate between each other. Communicate means trusting domain object could access or read the trusted domain resources for example forest A can access SMB shares across to forest B for whatever reason. This blog post will cover on the default configuration of forest trust type `WINCOWS_ACTIVE_DIRECTORY` which will be explained later. There are multiple trust types which is well documented by Microsoft [here](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/e9a2d23c-c31e-4a6f-88a0-6646fdb51a3c).  Also note that there is also a `trustDirection` attribute which is really important here.

## Lab Setup
I have setup two domain controllers which assigned to their respective forest. The first forest will 

## From Trust Account to DA
```
mimikatz# lsadump::trust /patch
```
![](Pasted%20image%2020220718095631.png)
![](Pasted%20image%2020220718095835.png)
![](Pasted%20image%2020220718101634.png)
## Conclusion

## Credits