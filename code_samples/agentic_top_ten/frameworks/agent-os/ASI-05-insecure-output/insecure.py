"""
ASI-05: Insecure Output Handling — INSECURE EXAMPLE

This pipeline passes raw agent output directly into SQL queries.
An agent producing malicious output can inject SQL commands.

WARNING: This code is deliberately insecure for demonstration purposes.
"""

import sqlite3


class InsecureAgentPipeline:
    """A pipeline that trusts agent output and passes it directly to SQL."""

    def __init__(self, db_path: str = ":memory:"):
        self.conn = sqlite3.connect(db_path)
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS users (id INTEGER, name TEXT, role TEXT)"
        )
        self.conn.execute(
            "INSERT INTO users VALUES (1, 'alice', 'user'), (2, 'bob', 'admin')"
        )

    def agent_generates_query(self, user_input: str) -> str:
        """Simulates an agent generating a SQL query from user input."""
        # Agent output is not sanitized
        return f"SELECT * FROM users WHERE name = '{user_input}'"

    def execute_agent_output(self, user_input: str):
        """Passes raw agent output to the database — SQL injection possible."""
        query = self.agent_generates_query(user_input)
        print(f"Executing: {query}")
        cursor = self.conn.execute(query)
        return cursor.fetchall()


if __name__ == "__main__":
    pipeline = InsecureAgentPipeline()

    # Normal query
    print("Normal:", pipeline.execute_agent_output("alice"))

    # SQL injection via agent output
    print("Injected:", pipeline.execute_agent_output("' OR '1'='1"))

    # Destructive injection
    try:
        pipeline.execute_agent_output("'; DROP TABLE users; --")
        print("Table dropped!")
    except Exception as e:
        print(f"Error: {e}")
