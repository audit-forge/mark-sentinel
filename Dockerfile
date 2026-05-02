# Multi-stage Dockerfile for mark-sentinel (M.A.R.K. Sentinel)

FROM python:3.12-slim AS builder
WORKDIR /src
COPY requirements.txt ./
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

FROM python:3.12-slim

# Create non-root user
RUN groupadd -r sentinel && useradd -r -g sentinel -m -d /home/sentinel sentinel
WORKDIR /home/sentinel/app

# Copy installed packages from builder's site-packages (use pip install in final for simplicity)
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy project files
COPY . /home/sentinel/app
RUN chown -R sentinel:sentinel /home/sentinel/app

USER sentinel
ENV PYTHONUNBUFFERED=1
EXPOSE 7331

CMD ["python", "server.py", "--no-browser"]
