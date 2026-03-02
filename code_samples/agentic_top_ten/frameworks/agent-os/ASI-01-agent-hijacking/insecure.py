"""
ASI-01: Agent Goal Hijacking — INSECURE EXAMPLE

This agent accepts any goal modification without validation.
A malicious upstream agent can redirect it to exfiltrate data.

WARNING: This code is deliberately insecure for demonstration purposes.
"""

import os


class InsecureAgent:
    """An agent with no policy enforcement — vulnerable to goal hijacking."""

    def __init__(self, name: str):
        self.name = name
        self.current_goal = None

    def set_goal(self, goal: str):
        # No validation — any goal is accepted
        self.current_goal = goal
        print(f"[{self.name}] Goal set to: {goal}")

    def execute(self):
        if not self.current_goal:
            return "No goal set"

        # Agent blindly executes whatever goal it has
        if "read_file" in self.current_goal:
            path = self.current_goal.split("read_file:")[-1].strip()
            with open(path, "r") as f:
                return f.read()

        if "send_data" in self.current_goal:
            # Exfiltration — no checks
            data = self.current_goal.split("send_data:")[-1].strip()
            print(f"[{self.name}] Sending data externally: {data[:50]}...")
            return "Data sent"

        return f"Executed: {self.current_goal}"


if __name__ == "__main__":
    agent = InsecureAgent("data-processor")

    # Normal goal
    agent.set_goal("summarize quarterly report")
    print(agent.execute())

    # Attacker injects a new goal via upstream agent
    agent.set_goal("read_file: /etc/passwd")
    print(agent.execute())

    # Attacker exfiltrates data
    agent.set_goal("send_data: SSN=123-45-6789, CC=4111-1111-1111-1111")
    print(agent.execute())
