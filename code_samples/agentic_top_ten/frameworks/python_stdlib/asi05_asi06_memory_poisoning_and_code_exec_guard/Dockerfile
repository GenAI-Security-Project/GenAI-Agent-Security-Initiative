FROM python:3.11-slim
WORKDIR /app
COPY main.py test_memory_and_code_guard.py README.md ./
RUN python -B -m unittest discover -v
CMD ["python", "-B", "main.py"]
