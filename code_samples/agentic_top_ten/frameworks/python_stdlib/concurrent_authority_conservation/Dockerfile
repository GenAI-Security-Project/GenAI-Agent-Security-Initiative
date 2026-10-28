FROM python:3.12-slim
WORKDIR /app
COPY main.py test_conservation.py README.md ./
RUN python -m unittest discover -v
CMD ["python", "main.py"]
