# ── Stage 1: Compile Python source to native binaries ─────────────────────────
FROM python:3.12-slim AS builder
WORKDIR /src

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc g++ patchelf ccache make libffi-dev && \
    rm -rf /var/lib/apt/lists/*

# Install deps first so Nuitka can follow all imports
COPY requirements.txt ./
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir nuitka ordered-set

COPY . .

# Compile the three entry points as standalone executables.
# --assume-yes-for-downloads fetches any missing Nuitka C runtime automatically.
# --output-dir keeps each build isolated.
RUN python -m nuitka --standalone --assume-yes-for-downloads \
    --output-dir=/build/server --output-filename=server \
    --include-data-dir=./profiles=profiles \
    server.py

RUN python -m nuitka --standalone --assume-yes-for-downloads \
    --output-dir=/build/audit --output-filename=audit \
    audit.py

RUN python -m nuitka --standalone --assume-yes-for-downloads \
    --output-dir=/build/demo --output-filename=demo \
    scripts/demo.py

# ── Stage 2: Lean runtime image — no Python, no source ───────────────────────
FROM debian:bookworm-slim
WORKDIR /app
ENV PYTHONUNBUFFERED=1

RUN groupadd -r sentinel && useradd -r -g sentinel -m -d /home/sentinel sentinel

# Copy compiled server (includes bundled Python runtime + all dependencies)
COPY --from=builder /build/server/server.dist /app

# Drop compiled audit and demo binaries next to server (server.py uses _compiled_cmd to find them)
COPY --from=builder /build/audit/audit.dist/audit /app/audit
COPY --from=builder /build/demo/demo.dist/demo /app/scripts/demo

# Copy non-Python assets that the server reads at runtime
COPY --from=builder /src/agent_config.json /app/
COPY --from=builder /src/tools.json /app/
COPY --from=builder /src/alerts_config.json.example /app/
COPY --from=builder /src/license.json* /app/ 2>/dev/null || true

RUN chmod +x /app/server /app/audit /app/scripts/demo && \
    chown -R sentinel:sentinel /app

USER sentinel
EXPOSE 7331

CMD ["/app/server", "--no-browser"]
