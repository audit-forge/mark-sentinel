# Regulated AI Integration Setup Guide

This guide explains how to connect your eTMF, model registry, and data
pipeline systems to Arckon so the Regulated AI dashboards populate
with real data.

## How It Works

```
Your System (Veeva/MLflow/DVC)
        ↓ (forwarder script polls for new data)
Arckon Forwarder (runs on your server or Arckon host)
        ↓ (sends metadata via HTTPS to ingest API)
Arckon Server (stores, assesses, displays on dashboard)
```

Arckon never accesses your systems directly or receives document/model
contents — only metadata.

## Prerequisites

1. Arckon deployed and accessible via HTTPS
2. Cloud ingest token (from Protected Cloud Assets → Show Cloud Ingest Token)
3. Python 3.11+ with `requests` package (`pip install requests`)
4. Network access from the forwarder host to both your system and Arckon

---

## 1. eTMF Completeness

### What it monitors
Checks your eTMF document metadata against the DIA TMF Reference Model
to identify missing documents, unsigned approvals, version control gaps,
and AI-generated content without human review.

### Supported Systems
- **Veeva Vault** (REST API v20.3+)
- **PhlexElection** (via generic REST adapter)
- **Any system with a REST API** (via generic adapter)

### Setup: Veeva Vault

1. **Get your Arckon ingest token:**
   - Open Arckon dashboard → Protected Cloud Assets → Show Cloud Ingest Token
   - Save the token to a secure file: `install -m 600 <token> /etc/arckon/ingest-token`

2. **Install the forwarder:**
   ```sh
   curl -o etmf_forwarder.py https://raw.githubusercontent.com/audit-forge/mark-sentinel/main/scripts/etmf_forwarder.py
   pip install requests
   ```

3. **Test manually:**
   ```sh
   python3 etmf_forwarder.py \
     --etmf-system veeva \
     --vault-url https://myvault.veevavault.com \
     --vault-username admin@company.com \
     --vault-password "$VAULT_PASSWORD" \
     --arckon-url https://arckon.riskraven.ai \
     --arckon-token-file /etc/arckon/ingest-token \
     --study-id NCT05567890 \
     --state-file /var/lib/arckon-etmf/state
   ```

4. **Schedule (every 5 minutes):**
   ```sh
   # Create env file
   cat > /etc/arckon-regulated-ai/mfdynamicsllc.env << EOF
   ETMF_SYSTEM=veeva
   VAULT_ARGS=--vault-url https://myvault.veevavault.com --vault-username admin@company.com --vault-password \$VAULT_PASSWORD
   STUDY_ID=NCT05567890
   EOF

   # Enable timer
   systemctl enable arckon-etmf-forwarder@mfdynamicsllc.timer
   systemctl start arckon-etmf-forwarder@mfdynamicsllc.timer
   ```

5. **Verify:** Open Arckon → eTMF Completeness → select your study ID

### Setup: Generic REST API

If your eTMF system has a REST API that returns JSON document metadata:

```sh
python3 etmf_forwarder.py \
  --etmf-system generic \
  --api-url https://my-etmf.example.com/api/documents \
  --api-key "$ETMF_API_KEY" \
  --arckon-url https://arckon.riskraven.ai \
  --arckon-token-file /etc/arckon/ingest-token \
  --study-id NCT05567890 \
  --state-file /var/lib/arckon-etmf/state
```

---

## 2. Model Monitoring

### What it monitors
Tracks your model registry for version drift (running different version
than approved), threshold breaches (performance or error rate exceeding
limits), monitoring gaps (approved models with no recent metrics),
and approval gaps (models in use without recorded approval).

### Supported Systems
- **MLflow** (open source model registry)
- **Weights & Biases** (via generic adapter)
- **Any system with a REST API** (via generic adapter)

### Setup: MLflow

1. **Install and test:**
   ```sh
   curl -o model_registry_forwarder.py https://raw.githubusercontent.com/audit-forge/mark-sentinel/main/scripts/model_registry_forwarder.py
   pip install requests

   python3 model_registry_forwarder.py \
     --registry mlflow \
     --mlflow-url http://localhost:5000 \
     --arckon-url https://arckon.riskraven.ai \
     --arckon-token-file /etc/arckon/ingest-token \
     --state-file /var/lib/arckon-model-monitor/state
   ```

2. **Schedule:**
   ```sh
   cat > /etc/arckon-regulated-ai/mfdynamicsllc.env << EOF
   REGISTRY_TYPE=mlflow
   REGISTRY_ARGS=--mlflow-url http://localhost:5000
   EOF

   systemctl enable arckon-model-forwarder@mfdynamicsllc.timer
   systemctl start arckon-model-forwarder@mfdynamicsllc.timer
   ```

3. **Verify:** Open Arckon → Model Monitoring (under Regulated AI section)

---

## 3. Data Provenance

### What it monitors
Tracks your training datasets for integrity violations (checksum
mismatches, unapproved modifications), unapproved training (models
trained on non-approved datasets), lineage breaks (training runs
referencing unregistered datasets), and data anomalies (schema changes,
distribution shifts).

### Supported Systems
- **DVC** (Data Version Control)
- **Apache Airflow** (via REST API)
- **Any system with a REST API** (via generic adapter)

### Setup: DVC

1. **Install and test:**
   ```sh
   curl -o data_pipeline_forwarder.py https://raw.githubusercontent.com/audit-forge/mark-sentinel/main/scripts/data_pipeline_forwarder.py
   pip install requests dvc

   python3 data_pipeline_forwarder.py \
     --pipeline dvc \
     --dvc-repo /path/to/your/dvc/repo \
     --arckon-url https://arckon.riskraven.ai \
     --arckon-token-file /etc/arckon/ingest-token \
     --state-file /var/lib/arckon-data-provenance/state
   ```

2. **Schedule:**
   ```sh
   cat > /etc/arckon-regulated-ai/mfdynamicsllc.env << EOF
   PIPELINE_TYPE=dvc
   PIPELINE_ARGS=--dvc-repo /path/to/your/dvc/repo
   EOF

   systemctl enable arckon-data-forwarder@mfdynamicsllc.timer
   systemctl start arckon-data-forwarder@mfdynamicsllc.timer
   ```

3. **Verify:** Open Arckon → Data Provenance (under Regulated AI section)

### Setup: Apache Airflow

```sh
python3 data_pipeline_forwarder.py \
  --pipeline airflow \
  --airflow-url http://airflow.example.com/api/v1 \
  --api-key "$AIRFLOW_API_KEY" \
  --arckon-url https://arckon.riskraven.ai \
  --arckon-token-file /etc/arckon/ingest-token \
  --state-file /var/lib/arckon-data-provenance/state
```

---

## Troubleshooting

| Symptom | Check |
| --- | --- |
| No data on dashboard | Verify forwarder ran: check state file and logs |
| 401 Unauthorized | Cloud ingest token is wrong or expired — get new one from dashboard |
| No new documents | State file may be ahead — delete it to re-sync all documents |
| Connection refused | Forwarder host can't reach Arckon URL — check network/firewall |
| Veeva auth failed | Verify Vault URL, username, and password |
| MLflow connection failed | Verify MLflow server is running and accessible |

## Security Notes

- Forwarder scripts are credential-free — they receive credentials via
  command-line arguments or environment variables, never hardcoded
- Arckon never accesses your eTMF/registry/pipeline directly
- All communication is over HTTPS
- Ingest tokens should be stored in root-owned files with mode 0600
- Forwarder containers run with --read-only, --cap-drop ALL, and
  no-new-privileges
