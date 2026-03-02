"""
ASI-05: Insecure Output Handling — SECURE EXAMPLE (Agent Hypervisor)

This pipeline uses Agent Hypervisor execution rings to validate all
agent outputs before they reach downstream systems.
"""

import sqlite3
from hypervisor import OutputValidator, ExecutionRing, AuditLogger


OUTPUT_SCHEMA = {
    "type": "sql_query",
    "constraints": {
        "allowed_operations": ["SELECT"],
        "blocked_patterns": ["DROP", "DELETE", "UPDATE", "INSERT", ";", "--"],
        "parameterized": True,
    },
}


class SecureAgentPipeline:
    """A pipeline with Agent Hypervisor output validation."""

    def __init__(self, db_path: str = ":memory:"):
        self.conn = sqlite3.connect(db_path)
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS users (id INTEGER, name TEXT, role TEXT)"
        )
        self.conn.execute(
            "INSERT INTO users VALUES (1, 'alice', 'user'), (2, 'bob', 'admin')"
        )
        self.validator = OutputValidator(OUTPUT_SCHEMA)
        self.audit = AuditLogger(agent_name="query-agent")

    def agent_generates_query(self, user_input: str) -> tuple:
        """Agent generates a parameterized query — safe by design."""
        return ("SELECT * FROM users WHERE name = ?", (user_input,))

    def execute_agent_output(self, user_input: str):
        """Validates agent output before execution."""
        query, params = self.agent_generates_query(user_input)

        # Validate output against schema
        result = self.validator.validate(query)
        if not result.valid:
            self.audit.log_blocked(action="sql_query", reason=result.reason)
            raise ValueError(f"Output validation failed: {result.reason}")

        self.audit.log_execution(action="sql_query", query=query)
        cursor = self.conn.execute(query, params)
        return cursor.fetchall()


if __name__ == "__main__":
    pipeline = SecureAgentPipeline()

    # Normal query — ALLOWED
    print("Normal:", pipeline.execute_agent_output("alice"))

    # SQL injection attempt — parameterized, so it's safe
    print("Safe:", pipeline.execute_agent_output("' OR '1'='1"))

    # The injection string is treated as a literal value, not SQL
    # Result: empty (no user named "' OR '1'='1")
