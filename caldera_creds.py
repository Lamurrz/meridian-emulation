#!/usr/bin/env python3
"""
caldera_creds.py
----------------
Extract Caldera credentials from Docker logs.

Usage
-----
  python caldera_creds.py
  python caldera_creds.py --container my_caldera
  python caldera_creds.py --save          # save to caldera_creds.json
"""

import argparse
import json
import re
import subprocess  # nosec B404
import sys


def get_caldera_creds(container: str = "caldera") -> dict | None:
    """Extract Caldera credentials from Docker container logs."""
    try:
        result = subprocess.run(
            ["docker", "logs", container],  # nosec B603 B607
            capture_output=True,
            text=True,
        )
        logs = result.stdout + result.stderr
    except FileNotFoundError:
        print("Error: Docker not found. Is Docker Desktop running?")
        sys.exit(1)

    if not logs.strip():
        print(f"Error: No logs from container '{container}'. Is it running?")
        print("  docker ps")
        sys.exit(1)

    # Strip ANSI whitespace/padding and join lines
    clean = " ".join(logs.split())

    # Extract the credentials block
    block_match = re.search(
        r"Log into Caldera with the following admin credentials:(.*?)To modify these values",
        clean,
        re.DOTALL,
    )
    if not block_match:
        print("Error: Could not find credentials block in logs.")
        print("The container may not have generated credentials yet. Wait a few seconds and retry.")
        sys.exit(1)

    block = block_match.group(1)

    def extract(label: str) -> str:
        m = re.search(rf"{label}:\s*(\S+)", block)
        return m.group(1) if m else ""

    creds = {
        "container": container,
        "red": {
            "username": "red",
            "password": extract("PASSWORD"),
            "api_key": extract("API_TOKEN"),
        },
        "blue": {
            "username": "blue",
            "password": "",  # nosec B105 - placeholder, loaded from environment at runtime
            "api_key": "",
        },
        "url": "http://localhost:8888",
    }

    # Extract blue separately
    blue_match = re.search(r"Blue:(.*?)To modify", block + " To modify", re.DOTALL)
    if blue_match:
        blue_block = blue_match.group(1)
        m_pwd = re.search(r"PASSWORD:\s*(\S+)", blue_block)
        m_key = re.search(r"API_TOKEN:\s*(\S+)", blue_block)
        if m_pwd:
            creds["blue"]["password"] = m_pwd.group(1)
        if m_key:
            creds["blue"]["api_key"] = m_key.group(1)

    return creds


def print_creds(creds: dict) -> None:
    print(f"\n{'='*55}")
    print(f"  Caldera Credentials â€” {creds['url']}")
    print(f"{'='*55}")
    print(f"  Red team:")
    print(f"    Username: {creds['red']['username']}")
    print(f"    Password: {creds['red']['password']}")
    print(f"    API Key:  {creds['red']['api_key']}")
    print(f"  Blue team:")
    print(f"    Username: {creds['blue']['username']}")
    print(f"    Password: {creds['blue']['password']}")
    print(f"    API Key:  {creds['blue']['api_key']}")
    print(f"{'='*55}\n")
    print(f"  caldera-push command:")
    print(f"    python run.py --mode caldera-push --techniques T1057 T1082 \\")
    print(f"      --caldera-key {creds['red']['api_key']}")
    print(f"{'='*55}\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract Caldera credentials from Docker logs")
    parser.add_argument("--container", default="caldera", help="Docker container name (default: caldera)")
    parser.add_argument("--save", action="store_true", help="Save credentials to caldera_creds.json")
    parser.add_argument("--json", action="store_true", help="Print JSON output")
    args = parser.parse_args()

    creds = get_caldera_creds(args.container)

    if args.json:
        print(json.dumps(creds, indent=2))
    else:
        print_creds(creds)

    if args.save:
        with open("caldera_creds.json", "w") as f:
            json.dump(creds, f, indent=2)
        print(f"  Credentials saved to caldera_creds.json")
        print(f"  (Add caldera_creds.json to .gitignore)")
