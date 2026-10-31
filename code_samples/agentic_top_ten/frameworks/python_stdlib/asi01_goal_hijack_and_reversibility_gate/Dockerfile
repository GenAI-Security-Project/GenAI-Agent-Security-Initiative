FROM python:3.11-slim
WORKDIR /app
COPY main.py test_goal_hijack_gate.py README.md ./
RUN python -B -m unittest discover -v
CMD ["python", "-B", "main.py"]
