FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir agent-os agentmesh agent-hypervisor
COPY . .
CMD ["python", "-m", "pytest", "-v", "--tb=short"]
