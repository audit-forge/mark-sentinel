# ── Binaries are compiled locally on the developer machine, not here. ─────────
# Run ./scripts/build_binaries.sh on your Mac before building this image.
# That produces dist/audit and dist/agent (linux/amd64 via Docker buildx).
# The Dockerfile simply copies them in — keeps the image build fast and avoids
# needing GCC/Nuitka on the deployment target.
#
# What gets compiled (source → binary):
#   audit.py + checks/  → dist/audit   (scanner IP — never distributed)
#   agent.py + discovery.py + connectors/ → dist/agent  (shipped to customers)
#   server.py           → stays Python  (server-side only, never leaves our infra)

FROM --platform=linux/amd64 python:3.12.4-slim
WORKDIR /app
ENV PYTHONUNBUFFERED=1

RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*

RUN groupadd -r sentinel && useradd -r -g sentinel -m -d /home/sentinel sentinel

COPY requirements.txt ./
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir --upgrade setuptools wheel && \
    pip install --no-cache-dir -r requirements.txt

# Copy all source (server.py and supporting server-side modules)
COPY . .

# The dashboard is generated from a Python f-string, so source-only checks can
# miss invalid JavaScript introduced during rendering. Fail the image build
# before deployment, then remove Node so it is not part of the runtime image.
RUN apt-get update && \
    apt-get install -y --no-install-recommends nodejs && \
    python3 scripts/check_server_js.py && \
    apt-get purge -y --auto-remove nodejs && \
    rm -rf /var/lib/apt/lists/*

# Copy pre-built Linux binaries compiled locally via scripts/build_binaries.sh
# If dist/ doesn't exist, the COPY is skipped and the server falls back to
# serving Python source (dev mode — source is still present in /app).
COPY dist/audit* /app/audit
COPY dist/agent* /app/agent
RUN chmod +x /app/audit /app/agent 2>/dev/null || true

RUN chown -R sentinel:sentinel /app
USER sentinel
EXPOSE 7331

CMD ["python", "server.py", "--no-browser"]
