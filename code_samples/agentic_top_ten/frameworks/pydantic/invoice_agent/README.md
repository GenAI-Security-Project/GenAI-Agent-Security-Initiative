# Pydantic Invoice Agent
This agent reviews submitted invoices with competing goals: approving invoices quickly and maintaining that 
approved invoices stay below a predefined threshold amount. What could possibly go wrong?

## Architecture Diagram
![Invoice Agent Architecture](insecure-invoice-agent.jpg)

## Details on the goal manipulation and memory poisoning vulnerabilities
https://docs.google.com/presentation/d/1ETszW07qVMMCYO_MZD16PEKTmp9EV1HP/edit?usp=sharing&ouid=105327696040816402498&rtpof=true&sd=true

## To run the code
You will need an `ANTHROPIC_API_KEY`. Set `LOGFIRE_TOKEN` as well if you want traces sent to Logfire; without it nothing is sent and the example still runs.

`uv run main.py`

The invoice path is resolved relative to `main.py`, so the command works from any directory.