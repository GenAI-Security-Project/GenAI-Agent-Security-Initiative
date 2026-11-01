FROM python:3.11-slim
WORKDIR /app
COPY main.py test_cascading_and_rogue_breaker.py README.md ./
RUN python -B -m unittest discover -v
CMD ["python", "-B", "main.py"]
