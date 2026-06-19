# ── Stage 1: Compile scanner binaries only (audit + demo) ────────────────────
# server.py runs as Python — it's behind auth and changes frequently.
# audit.py and demo.py are the actual IP — compiled to native binaries.
FROM --platform=linux/amd64 python:3.12.4-slim AS builder
WORKDIR /src

RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends \
    gcc g++ patchelf ccache make libffi-dev && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir --upgrade setuptools wheel && \
    pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir nuitka ordered-set

# Copy only the files needed for compilation so layer cache survives server.py changes
COPY audit.py checks/ profiles/ connectors/ ./
COPY output/ ./output/

RUN python -m nuitka --onefile --assume-yes-for-downloads \
    --include-package=checks \
    --include-package=connectors \
    --include-package=output \
    --output-dir=/build --output-filename=audit \
    audit.py

# ── Stage 2: Python runtime with compiled scanners ───────────────────────────
FROM --platform=linux/amd64 python:3.12.4-slim
WORKDIR /app
ENV PYTHONUNBUFFERED=1

RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*

RUN groupadd -r sentinel && useradd -r -g sentinel -m -d /home/sentinel sentinel

COPY requirements.txt ./
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir --upgrade setuptools wheel && \
    pip install --no-cache-dir -r requirements.txt

# Copy all Python source for the server
COPY . .

# Overwrite audit with compiled binary from builder
COPY --from=builder /build/audit /app/audit
RUN chmod +x /app/audit

RUN --mount=type=bind,from=builder,source=/src,target=/build-src \
    cp /build-src/license.json /app/ 2>/dev/null || true

RUN chown -R sentinel:sentinel /app
USER sentinel
EXPOSE 7331

CMD ["python", "server.py", "--no-browser"]
