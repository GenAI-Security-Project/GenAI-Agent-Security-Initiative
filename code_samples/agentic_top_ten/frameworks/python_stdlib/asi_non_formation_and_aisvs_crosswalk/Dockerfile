FROM python:3.11-slim
WORKDIR /app
COPY main.py test_aisvs_crosswalk_and_fixtures.py crosswalk.json fixtures.json README.md ./
RUN python -B -m unittest discover -v
CMD ["python", "-B", "main.py"]
