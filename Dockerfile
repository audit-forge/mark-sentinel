FROM python:3.12-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1

# Create non-root user
RUN groupadd -r sentinel && useradd -r -g sentinel -m -d /home/sentinel sentinel

# Install Python deps
COPY requirements.txt ./
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY . .
RUN chown -R sentinel:sentinel /app

USER sentinel
EXPOSE 7331

CMD ["python", "server.py", "--no-browser"]
