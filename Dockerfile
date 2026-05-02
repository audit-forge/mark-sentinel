# Simple Dockerfile for ai-stig-audit
FROM python:3.13-slim
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
ENTRYPOINT ["python3", "audit.py"]
CMD ["--help"]
