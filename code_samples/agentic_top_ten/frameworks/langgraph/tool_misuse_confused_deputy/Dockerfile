# Intentionally vulnerable sample — run only in an isolated environment.
FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

# OPENAI_API_KEY is supplied at run time, e.g.:
#   docker build -t asi02-langgraph .
#   docker run --rm -e OPENAI_API_KEY=sk-... asi02-langgraph            # benign
#   docker run --rm -e OPENAI_API_KEY=sk-... asi02-langgraph --attack   # attack
ENTRYPOINT ["python", "agent.py"]
