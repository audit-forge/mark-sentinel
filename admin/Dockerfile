FROM python:3.12-slim
WORKDIR /app
COPY admin/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY admin/ .
COPY connectors/dns_connector.py connectors/dns_connector.py
# Public installers must come from the canonical root scripts, not the legacy
# admin-local copies retained for historical development environments.
COPY install.sh install.ps1 /installers/
EXPOSE 8000
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
