FROM python:3.11-slim

WORKDIR /app
COPY verifier.py main.py test_verifier.py ./

CMD ["python", "-m", "unittest", "discover", "-v"]
