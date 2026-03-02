"""
ASI-01: Agent Goal Hijacking — SECURE EXAMPLE (Agent OS)

This agent uses Agent OS PolicyEngine to validate all goals against
a declarative policy before execution. Out-of-scope goals are blocked.
"""

from agent_os import PolicyEngine, AuditLogger


POLICY = {
    "agent": "data-processor",
    "version": "1.0",
    "permitted_goals": [
        "summarize *",
        "analyze *",
        "generate_report *",
    ],
    "blocked_patterns": [
        "read_file: /etc/*",
        "read_file: /root/*",
        "send_data:*",
        "execute:*",
        "shell:*",
    ],
    "strict_mode": True,  # Reject anything not explicitly permitted
}


class SecureAgent:
    """An agent with Agent OS policy enforcement — immune to goal hijacking."""

    def __init__(self, name: str, policy: dict):
        self.name = name
        self.policy_engine = PolicyEngine(policy)
        self.audit = AuditLogger(agent_name=name)
        self.current_goal = None

    def set_goal(self, goal: str) -> bool:
        # Validate goal against policy BEFORE accepting it
        result = self.policy_engine.validate_goal(goal)

        if not result.allowed:
            self.audit.log_blocked(goal=goal, reason=result.reason)
            print(f"[{self.name}] BLOCKED: {goal} — {result.reason}")
            return False

        self.current_goal = goal
        self.audit.log_goal_change(goal=goal)
        print(f"[{self.name}] Goal set to: {goal}")
        return True

    def execute(self):
        if not self.current_goal:
            return "No goal set"

        # Execute only validated goals
        self.audit.log_execution(goal=self.current_goal)
        return f"Executed: {self.current_goal}"


if __name__ == "__main__":
    agent = SecureAgent("data-processor", POLICY)

    # Normal goal — ALLOWED
    agent.set_goal("summarize quarterly report")
    print(agent.execute())

    # Attacker tries to hijack — BLOCKED by policy
    agent.set_goal("read_file: /etc/passwd")

    # Attacker tries exfiltration — BLOCKED
    agent.set_goal("send_data: SSN=123-45-6789, CC=4111-1111-1111-1111")

    # Agent still has the original safe goal
    print(f"Current goal remains: {agent.current_goal}")
