FROM python:3.12-slim
WORKDIR /app

# nsis (makensis) compiles per-customer Windows .exe installers on the server;
# zip packages the macOS .app bundle. Both are used by installer_gen.py.
RUN apt-get update && apt-get install -y --no-install-recommends nsis zip && rm -rf /var/lib/apt/lists/*

COPY admin/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY admin/ .
COPY arckon_version.py .
COPY connectors/dns_connector.py connectors/dns_connector.py
# Public installers must come from the canonical root scripts, not the legacy
# admin-local copies retained for historical development environments.
COPY install.sh install.ps1 uninstall.ps1 /installers/
COPY deploy/intune/install-intune.ps1 deploy/intune/detect-intune.ps1 deploy/intune/uninstall-intune.ps1 /installers/
COPY deploy/intune/install-intune.sh deploy/intune/detect-intune.sh deploy/intune/uninstall-intune.sh /installers/

RUN groupadd -r arckon && useradd -r -g arckon -m -d /home/arckon arckon \
    && chown -R arckon:arckon /app /installers

USER arckon
EXPOSE 8000
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
