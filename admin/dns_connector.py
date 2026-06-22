"""
Arckon by RiskRaven — DNS Log Connector
Agentless AI inventory from DNS query logs. No agent, no credentials required —
the customer uploads or pastes a DNS log and Arckon maps it to their AI footprint.

Supported log formats (auto-detected):
  - Pi-hole / dnsmasq query log
  - BIND / named query log
  - Unbound
  - Cisco Umbrella CSV export
  - Windows DNS Server debug log
  - Plain domain list (one per line)
  - Generic fallback (domain extraction via regex)

No external dependencies — pure stdlib.
"""
from __future__ import annotations

import csv
import io
import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Iterator


# ---------------------------------------------------------------------------
# AI Service Catalog
# Each entry: base_domain -> {vendor, product, category, risk}
#   risk: "low"    = commonly enterprise-sanctioned (O365 AI, Google Workspace AI)
#         "medium" = popular, often ungoverned (ChatGPT, Copilot consumer)
#         "high"   = shadow AI / data-exfiltration risk (unknown vendors, jailbreak sites)
# ---------------------------------------------------------------------------
_CATALOG: dict[str, dict] = {
    # ── OpenAI ──────────────────────────────────────────────────────────────
    "api.openai.com":          {"vendor": "OpenAI", "product": "OpenAI API",          "category": "api",    "risk": "medium"},
    "openai.com":              {"vendor": "OpenAI", "product": "OpenAI Platform",      "category": "api",    "risk": "medium"},
    "chat.openai.com":         {"vendor": "OpenAI", "product": "ChatGPT",              "category": "chat",   "risk": "medium"},
    "chatgpt.com":             {"vendor": "OpenAI", "product": "ChatGPT",              "category": "chat",   "risk": "medium"},
    "auth.openai.com":         {"vendor": "OpenAI", "product": "ChatGPT (auth)",       "category": "chat",   "risk": "medium"},
    "cdn.oaistatic.com":       {"vendor": "OpenAI", "product": "ChatGPT (CDN)",        "category": "chat",   "risk": "medium"},
    "oaiusercontent.com":      {"vendor": "OpenAI", "product": "ChatGPT (uploads)",    "category": "chat",   "risk": "medium"},
    "sora.com":                {"vendor": "OpenAI", "product": "Sora (video AI)",      "category": "image",  "risk": "medium"},

    # ── Anthropic ───────────────────────────────────────────────────────────
    "api.anthropic.com":       {"vendor": "Anthropic", "product": "Claude API",        "category": "api",    "risk": "medium"},
    "claude.ai":               {"vendor": "Anthropic", "product": "Claude",            "category": "chat",   "risk": "medium"},
    "anthropic.com":           {"vendor": "Anthropic", "product": "Anthropic Platform","category": "api",    "risk": "medium"},

    # ── Google AI ───────────────────────────────────────────────────────────
    "generativelanguage.googleapis.com": {"vendor": "Google", "product": "Gemini API",         "category": "api",    "risk": "low"},
    "aiplatform.googleapis.com":         {"vendor": "Google", "product": "Vertex AI",           "category": "api",    "risk": "low"},
    "ml.googleapis.com":                 {"vendor": "Google", "product": "Google Cloud ML",     "category": "api",    "risk": "low"},
    "dialogflow.googleapis.com":         {"vendor": "Google", "product": "Dialogflow",          "category": "api",    "risk": "low"},
    "speech.googleapis.com":            {"vendor": "Google", "product": "Cloud Speech-to-Text", "category": "voice",  "risk": "low"},
    "texttospeech.googleapis.com":      {"vendor": "Google", "product": "Cloud Text-to-Speech", "category": "voice",  "risk": "low"},
    "vision.googleapis.com":            {"vendor": "Google", "product": "Cloud Vision API",     "category": "api",    "risk": "low"},
    "language.googleapis.com":          {"vendor": "Google", "product": "Natural Language API", "category": "api",    "risk": "low"},
    "translate.googleapis.com":         {"vendor": "Google", "product": "Cloud Translate",      "category": "api",    "risk": "low"},
    "gemini.google.com":                {"vendor": "Google", "product": "Gemini",               "category": "chat",   "risk": "low"},
    "bard.google.com":                  {"vendor": "Google", "product": "Gemini (legacy Bard)", "category": "chat",   "risk": "low"},
    "notebooklm.google.com":            {"vendor": "Google", "product": "NotebookLM",           "category": "chat",   "risk": "low"},

    # ── Microsoft / Azure AI ────────────────────────────────────────────────
    "openai.azure.com":                 {"vendor": "Microsoft", "product": "Azure OpenAI",       "category": "api",   "risk": "low"},
    "cognitiveservices.azure.com":      {"vendor": "Microsoft", "product": "Azure Cognitive Svcs","category": "api",  "risk": "low"},
    "api.cognitive.microsoft.com":      {"vendor": "Microsoft", "product": "Azure Cognitive API", "category": "api",  "risk": "low"},
    "copilot.microsoft.com":            {"vendor": "Microsoft", "product": "Copilot",             "category": "chat", "risk": "low"},
    "sydney.bing.com":                  {"vendor": "Microsoft", "product": "Copilot (Bing)",      "category": "chat", "risk": "low"},
    "edgeservices.bing.com":            {"vendor": "Microsoft", "product": "Copilot (Edge)",      "category": "chat", "risk": "low"},
    "copilot.github.com":               {"vendor": "Microsoft", "product": "GitHub Copilot",      "category": "coding","risk": "low"},
    "githubcopilot.com":                {"vendor": "Microsoft", "product": "GitHub Copilot",      "category": "coding","risk": "low"},
    "api.githubcopilot.com":            {"vendor": "Microsoft", "product": "GitHub Copilot API",  "category": "coding","risk": "low"},
    "telemetry.githubcopilot.com":      {"vendor": "Microsoft", "product": "GitHub Copilot",      "category": "coding","risk": "low"},

    # ── AWS AI ──────────────────────────────────────────────────────────────
    "bedrock.us-east-1.amazonaws.com":  {"vendor": "AWS", "product": "Amazon Bedrock",    "category": "api",  "risk": "low"},
    "bedrock-runtime.us-east-1.amazonaws.com": {"vendor": "AWS", "product": "Amazon Bedrock Runtime", "category": "api", "risk": "low"},
    "sagemaker.amazonaws.com":          {"vendor": "AWS", "product": "SageMaker",         "category": "api",  "risk": "low"},
    "rekognition.amazonaws.com":        {"vendor": "AWS", "product": "AWS Rekognition",   "category": "api",  "risk": "low"},
    "comprehend.amazonaws.com":         {"vendor": "AWS", "product": "AWS Comprehend",    "category": "api",  "risk": "low"},
    "textract.amazonaws.com":           {"vendor": "AWS", "product": "AWS Textract",      "category": "api",  "risk": "low"},
    "polly.amazonaws.com":              {"vendor": "AWS", "product": "AWS Polly",         "category": "voice","risk": "low"},
    "transcribe.amazonaws.com":         {"vendor": "AWS", "product": "AWS Transcribe",    "category": "voice","risk": "low"},
    "lex.amazonaws.com":                {"vendor": "AWS", "product": "Amazon Lex",        "category": "api",  "risk": "low"},
    "kendra.amazonaws.com":             {"vendor": "AWS", "product": "Amazon Kendra",     "category": "api",  "risk": "low"},

    # ── Mistral ─────────────────────────────────────────────────────────────
    "api.mistral.ai":          {"vendor": "Mistral AI", "product": "Mistral API",         "category": "api",   "risk": "medium"},
    "mistral.ai":              {"vendor": "Mistral AI", "product": "Mistral Platform",    "category": "api",   "risk": "medium"},
    "chat.mistral.ai":         {"vendor": "Mistral AI", "product": "Le Chat",             "category": "chat",  "risk": "medium"},

    # ── Cohere ──────────────────────────────────────────────────────────────
    "api.cohere.com":          {"vendor": "Cohere", "product": "Cohere API",              "category": "api",   "risk": "medium"},
    "cohere.com":              {"vendor": "Cohere", "product": "Cohere Platform",         "category": "api",   "risk": "medium"},
    "dashboard.cohere.com":    {"vendor": "Cohere", "product": "Cohere Dashboard",        "category": "api",   "risk": "medium"},

    # ── Meta / Llama ────────────────────────────────────────────────────────
    "llama.meta.com":          {"vendor": "Meta", "product": "Llama API",                 "category": "api",   "risk": "medium"},
    "api.llama.com":           {"vendor": "Meta", "product": "Llama API",                 "category": "api",   "risk": "medium"},

    # ── xAI / Grok ──────────────────────────────────────────────────────────
    "api.x.ai":                {"vendor": "xAI", "product": "Grok API",                  "category": "api",   "risk": "medium"},
    "x.ai":                    {"vendor": "xAI", "product": "Grok",                      "category": "chat",  "risk": "medium"},
    "grok.com":                {"vendor": "xAI", "product": "Grok",                      "category": "chat",  "risk": "medium"},

    # ── Perplexity ──────────────────────────────────────────────────────────
    "perplexity.ai":           {"vendor": "Perplexity", "product": "Perplexity AI",      "category": "search","risk": "medium"},
    "api.perplexity.ai":       {"vendor": "Perplexity", "product": "Perplexity API",     "category": "api",   "risk": "medium"},

    # ── DeepSeek ────────────────────────────────────────────────────────────
    "api.deepseek.com":        {"vendor": "DeepSeek", "product": "DeepSeek API",         "category": "api",   "risk": "high"},
    "chat.deepseek.com":       {"vendor": "DeepSeek", "product": "DeepSeek Chat",        "category": "chat",  "risk": "high"},
    "deepseek.com":            {"vendor": "DeepSeek", "product": "DeepSeek Platform",    "category": "api",   "risk": "high"},

    # ── Moonshot / Kimi ─────────────────────────────────────────────────────
    "api.moonshot.cn":         {"vendor": "Moonshot AI", "product": "Kimi API",          "category": "api",   "risk": "high"},
    "kimi.ai":                 {"vendor": "Moonshot AI", "product": "Kimi",              "category": "chat",  "risk": "high"},
    "kimi.moonshot.cn":        {"vendor": "Moonshot AI", "product": "Kimi",              "category": "chat",  "risk": "high"},

    # ── Alibaba / Qwen ──────────────────────────────────────────────────────
    "dashscope.aliyuncs.com":  {"vendor": "Alibaba", "product": "Qwen / DashScope API",  "category": "api",   "risk": "high"},

    # ── Together / Groq / Replicate ─────────────────────────────────────────
    "api.together.xyz":        {"vendor": "Together AI", "product": "Together AI API",   "category": "api",   "risk": "medium"},
    "api.groq.com":            {"vendor": "Groq", "product": "Groq API",                 "category": "api",   "risk": "medium"},
    "api.replicate.com":       {"vendor": "Replicate", "product": "Replicate API",       "category": "api",   "risk": "medium"},
    "replicate.com":           {"vendor": "Replicate", "product": "Replicate Platform",  "category": "api",   "risk": "medium"},

    # ── Hugging Face ────────────────────────────────────────────────────────
    "api-inference.huggingface.co": {"vendor": "Hugging Face", "product": "HF Inference API", "category": "api", "risk": "medium"},
    "huggingface.co":          {"vendor": "Hugging Face", "product": "Hugging Face Hub", "category": "api",   "risk": "medium"},
    "router.huggingface.co":   {"vendor": "Hugging Face", "product": "HF Inference Providers", "category": "api", "risk": "medium"},

    # ── AI21 / Jurassic ─────────────────────────────────────────────────────
    "api.ai21.com":            {"vendor": "AI21 Labs", "product": "Jurassic API",        "category": "api",   "risk": "medium"},
    "studio.ai21.com":         {"vendor": "AI21 Labs", "product": "AI21 Studio",         "category": "api",   "risk": "medium"},

    # ── NVIDIA ──────────────────────────────────────────────────────────────
    "integrate.api.nvidia.com": {"vendor": "NVIDIA", "product": "NVIDIA NIM API",        "category": "api",   "risk": "medium"},
    "build.nvidia.com":         {"vendor": "NVIDIA", "product": "NVIDIA NIM",            "category": "api",   "risk": "medium"},

    # ── Image generation ────────────────────────────────────────────────────
    "midjourney.com":          {"vendor": "Midjourney", "product": "Midjourney",         "category": "image", "risk": "medium"},
    "cdn.midjourney.com":      {"vendor": "Midjourney", "product": "Midjourney CDN",     "category": "image", "risk": "medium"},
    "stability.ai":            {"vendor": "Stability AI", "product": "Stable Diffusion", "category": "image", "risk": "medium"},
    "api.stability.ai":        {"vendor": "Stability AI", "product": "Stability API",    "category": "api",   "risk": "medium"},
    "runwayml.com":            {"vendor": "Runway", "product": "Runway ML",              "category": "image", "risk": "medium"},
    "runway.com":              {"vendor": "Runway", "product": "Runway",                 "category": "image", "risk": "medium"},
    "pika.art":                {"vendor": "Pika Labs", "product": "Pika",               "category": "image", "risk": "medium"},
    "leonardo.ai":             {"vendor": "Leonardo AI", "product": "Leonardo",          "category": "image", "risk": "medium"},
    "ideogram.ai":             {"vendor": "Ideogram", "product": "Ideogram",             "category": "image", "risk": "medium"},
    "flux.ai":                 {"vendor": "Black Forest Labs", "product": "FLUX",        "category": "image", "risk": "medium"},

    # ── Audio / Voice ───────────────────────────────────────────────────────
    "api.elevenlabs.io":       {"vendor": "ElevenLabs", "product": "ElevenLabs API",    "category": "voice", "risk": "medium"},
    "elevenlabs.io":           {"vendor": "ElevenLabs", "product": "ElevenLabs",        "category": "voice", "risk": "medium"},
    "suno.ai":                 {"vendor": "Suno", "product": "Suno AI Music",           "category": "audio", "risk": "medium"},
    "udio.com":                {"vendor": "Udio", "product": "Udio AI Music",           "category": "audio", "risk": "medium"},

    # ── Coding assistants ───────────────────────────────────────────────────
    "codeium.com":             {"vendor": "Codeium", "product": "Codeium",              "category": "coding","risk": "medium"},
    "api.codeium.com":         {"vendor": "Codeium", "product": "Codeium API",          "category": "coding","risk": "medium"},
    "tabnine.com":             {"vendor": "Tabnine", "product": "Tabnine",              "category": "coding","risk": "medium"},
    "cursor.sh":               {"vendor": "Cursor", "product": "Cursor IDE",            "category": "coding","risk": "medium"},
    "api2.cursor.sh":          {"vendor": "Cursor", "product": "Cursor API",            "category": "coding","risk": "medium"},
    "marketplace.cursorapi.com": {"vendor": "Cursor", "product": "Cursor Marketplace", "category": "coding","risk": "medium"},
    "replit.com":              {"vendor": "Replit", "product": "Replit AI",             "category": "coding","risk": "medium"},
    "v0.dev":                  {"vendor": "Vercel", "product": "v0",                    "category": "coding","risk": "medium"},
    "bolt.new":                {"vendor": "StackBlitz", "product": "Bolt",             "category": "coding","risk": "medium"},
    "lovable.dev":             {"vendor": "Lovable", "product": "Lovable",             "category": "coding","risk": "medium"},

    # ── Writing / Productivity AI ────────────────────────────────────────────
    "jasper.ai":               {"vendor": "Jasper", "product": "Jasper AI",             "category": "writing","risk": "medium"},
    "api.jasper.ai":           {"vendor": "Jasper", "product": "Jasper API",            "category": "writing","risk": "medium"},
    "copy.ai":                 {"vendor": "Copy.ai", "product": "Copy.ai",              "category": "writing","risk": "medium"},
    "writesonic.com":          {"vendor": "Writesonic", "product": "Writesonic",        "category": "writing","risk": "medium"},
    "notion.so":               {"vendor": "Notion", "product": "Notion AI",             "category": "writing","risk": "low"},
    "api.notion.com":          {"vendor": "Notion", "product": "Notion API",            "category": "writing","risk": "low"},
    "grammarly.com":           {"vendor": "Grammarly", "product": "Grammarly AI",       "category": "writing","risk": "low"},
    "writer.com":              {"vendor": "Writer", "product": "Writer",                "category": "writing","risk": "medium"},

    # ── Search / Research AI ─────────────────────────────────────────────────
    "you.com":                 {"vendor": "You.com", "product": "You.com AI Search",    "category": "search","risk": "medium"},
    "phind.com":               {"vendor": "Phind", "product": "Phind",                  "category": "search","risk": "medium"},

    # ── Character / Companion AI ─────────────────────────────────────────────
    "character.ai":            {"vendor": "Character.AI", "product": "Character.AI",    "category": "chat",  "risk": "high"},
    "neo.character.ai":        {"vendor": "Character.AI", "product": "Character.AI",    "category": "chat",  "risk": "high"},
    "pi.ai":                   {"vendor": "Inflection AI", "product": "Pi",             "category": "chat",  "risk": "medium"},
    "inflection.ai":           {"vendor": "Inflection AI", "product": "Inflection",     "category": "chat",  "risk": "medium"},

    # ── Enterprise AI platforms ──────────────────────────────────────────────
    "api.scale.com":           {"vendor": "Scale AI", "product": "Scale API",           "category": "api",   "risk": "medium"},
    "scale.com":               {"vendor": "Scale AI", "product": "Scale AI",            "category": "api",   "risk": "medium"},
    "app.glean.com":           {"vendor": "Glean", "product": "Glean AI Search",        "category": "search","risk": "low"},
    "api.glean.com":           {"vendor": "Glean", "product": "Glean API",              "category": "api",   "risk": "low"},
    "asapp.com":               {"vendor": "ASAPP", "product": "ASAPP AI",               "category": "api",   "risk": "medium"},

    # ── LiteLLM / proxy layers ───────────────────────────────────────────────
    "litellm.ai":              {"vendor": "LiteLLM", "product": "LiteLLM Proxy",        "category": "api",   "risk": "medium"},
    "api.openrouter.ai":       {"vendor": "OpenRouter", "product": "OpenRouter API",    "category": "api",   "risk": "medium"},
    "openrouter.ai":           {"vendor": "OpenRouter", "product": "OpenRouter",        "category": "api",   "risk": "medium"},
}

# Wildcard suffix patterns for cloud providers with regional subdomains.
# Matched with endswith() against the full queried domain.
_WILDCARD_PATTERNS: list[tuple[str, dict]] = [
    (".bedrock.us-east-1.amazonaws.com",      {"vendor": "AWS", "product": "Amazon Bedrock",        "category": "api",   "risk": "low"}),
    (".bedrock-runtime.amazonaws.com",         {"vendor": "AWS", "product": "Amazon Bedrock Runtime","category": "api",   "risk": "low"}),
    (".sagemaker.amazonaws.com",               {"vendor": "AWS", "product": "AWS SageMaker",         "category": "api",   "risk": "low"}),
    (".execute-api.amazonaws.com",             {"vendor": "AWS", "product": "AWS API Gateway (AI?)", "category": "api",   "risk": "low"}),
    (".cognitiveservices.azure.com",           {"vendor": "Microsoft", "product": "Azure Cognitive Services", "category": "api", "risk": "low"}),
    (".openai.azure.com",                      {"vendor": "Microsoft", "product": "Azure OpenAI",    "category": "api",   "risk": "low"}),
    (".inference.ml.azure.com",                {"vendor": "Microsoft", "product": "Azure ML Inference","category": "api",  "risk": "low"}),
    (".aiplatform.googleapis.com",             {"vendor": "Google", "product": "Vertex AI",          "category": "api",   "risk": "low"}),
]

# ---------------------------------------------------------------------------
# Log format detection
# ---------------------------------------------------------------------------
_FMT_PIHOLE   = "pihole"
_FMT_BIND     = "bind"
_FMT_UNBOUND  = "unbound"
_FMT_UMBRELLA = "umbrella_csv"
_FMT_NEXTDNS  = "nextdns_csv"
_FMT_WINDDNS  = "windows_dns"
_FMT_PLAIN    = "plain_domains"
_FMT_GENERIC  = "generic"

_RE_PIHOLE   = re.compile(r'dnsmasq\[\d+\].*query\[')
_RE_BIND     = re.compile(r'client\s+(?:@\S+\s+)?\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}#\d+.*query:')
_RE_UNBOUND  = re.compile(r'unbound\[\d+')
_RE_NEXTDNS  = re.compile(r'^timestamp[,\t]domain', re.IGNORECASE)
_RE_UMBRELLA = re.compile(r'^\s*"?\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}"?,')
_RE_WINDNS   = re.compile(r'\d+/\d+/\d{4}\s+\d+:\d+:\d+\s+[AP]M')
_RE_DOMAIN   = re.compile(r'\b((?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,})\b')


def _detect_format(lines: list[str]) -> str:
    sample = "\n".join(lines[:20])
    if _RE_PIHOLE.search(sample):
        return _FMT_PIHOLE
    if _RE_BIND.search(sample):
        return _FMT_BIND
    if _RE_UNBOUND.search(sample):
        return _FMT_UNBOUND
    if _RE_NEXTDNS.search(sample):
        return _FMT_NEXTDNS
    if _RE_UMBRELLA.search(sample):
        return _FMT_UMBRELLA
    if _RE_WINDNS.search(sample):
        return _FMT_WINDDNS
    # Plain domain list: most lines look like bare domains
    domain_lines = sum(1 for l in lines[:20] if _RE_DOMAIN.fullmatch(l.strip().rstrip('.')))
    if domain_lines >= len([l for l in lines[:20] if l.strip()]) * 0.7:
        return _FMT_PLAIN
    return _FMT_GENERIC


# ---------------------------------------------------------------------------
# Parsers — each yields (timestamp_str, domain, source_ip)
# ---------------------------------------------------------------------------

@dataclass
class _Entry:
    ts: str
    domain: str
    src: str


def _parse_pihole(lines: list[str]) -> Iterator[_Entry]:
    # Jun 15 10:23:45 dnsmasq[1234]: query[A] api.openai.com from 192.168.1.5
    pat = re.compile(
        r'^(\w+\s+\d+\s+[\d:]+)\s+(?:\S+\s+)?dnsmasq\[\d+\]:\s+query\[\w+\]\s+([\w.\-]+)\s+from\s+([\d.:a-fA-F]+)'
    )
    for line in lines:
        m = pat.search(line)
        if m:
            yield _Entry(ts=m.group(1), domain=m.group(2).rstrip('.'), src=m.group(3))


def _parse_bind(lines: list[str]) -> Iterator[_Entry]:
    # client @0x7f 192.168.1.5#54321 (api.openai.com): query: api.openai.com IN A
    pat = re.compile(
        r'^([\d\-\w\s:.]+?)\s+(?:queries:\s+\w+:\s+)?client\s+(?:@\S+\s+)?([\d.]+)#\d+.*?query:\s+([\w.\-]+)\s+IN'
    )
    for line in lines:
        m = pat.search(line)
        if m:
            yield _Entry(ts=m.group(1).strip(), domain=m.group(3).rstrip('.'), src=m.group(2))


def _parse_unbound(lines: list[str]) -> Iterator[_Entry]:
    # [1718444625] unbound[1234:0] info: 192.168.1.5 api.openai.com. A IN
    pat = re.compile(
        r'\[(\d+)\]\s+unbound\[\S+\]\s+info:\s+([\d.:a-fA-F]+)\s+([\w.\-]+)\.\s+\w+\s+IN'
    )
    for line in lines:
        m = pat.search(line)
        if m:
            yield _Entry(ts=m.group(1), domain=m.group(3).rstrip('.'), src=m.group(2))


def _parse_umbrella(lines: list[str]) -> Iterator[_Entry]:
    # "2026-06-15 10:23:45","identity","","Allowed","1.2.3.4","api.openai.com","A"
    reader = csv.reader(io.StringIO("\n".join(lines)))
    for row in reader:
        if not row or row[0].startswith('#') or 'timestamp' in row[0].lower():
            continue
        try:
            ts  = row[0].strip('"')
            # Umbrella: col 4 = internal IP, col 5 = domain (may vary by export version)
            src = row[4].strip('"') if len(row) > 4 else ""
            dom = row[5].strip('"') if len(row) > 5 else (row[3].strip('"') if len(row) > 3 else "")
            if dom:
                yield _Entry(ts=ts, domain=dom.rstrip('.'), src=src)
        except (IndexError, ValueError):
            continue


def _parse_nextdns(lines: list[str]) -> Iterator[_Entry]:
    # NextDNS CSV export (two known column layouts — camelCase and snake_case):
    # timestamp,domain,query_type,...,client_ip,...,device_name,device_model,device_local_ip,...
    # Normalise header by lowercasing and stripping underscores for flexible matching.
    reader = csv.reader(io.StringIO("\n".join(lines)))
    header: list[str] = []
    for row in reader:
        if not row:
            continue
        if not header:
            # normalise: lowercase + strip underscores/spaces
            header = [h.strip().lower().replace("_", "").replace(" ", "") for h in row]
            continue
        try:
            def col(name: str, fallback: int = -1) -> str:
                idx = next((i for i, h in enumerate(header) if h == name), fallback)
                return row[idx].strip() if 0 <= idx < len(row) else ""
            ts     = col("timestamp", 0)
            domain = col("domain", 1).rstrip(".")
            # prefer internal/local IP → device name → public client IP
            src = (col("devicelocalip") or col("devicename") or
                   col("clientname") or col("clientip", 5))
            if domain:
                yield _Entry(ts=ts, domain=domain, src=src)
        except (IndexError, ValueError):
            continue


def _parse_windows_dns(lines: list[str]) -> Iterator[_Entry]:
    # 6/15/2026 10:23:45 AM ... api.openai.com
    ts_pat  = re.compile(r'(\d+/\d+/\d{4}\s+\d+:\d+:\d+\s+[AP]M)')
    ip_pat  = re.compile(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b')
    dom_pat = re.compile(r'\b((?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,})\b')
    for line in lines:
        ts_m = ts_pat.search(line)
        ip_m = ip_pat.search(line)
        doms = dom_pat.findall(line)
        if ts_m and doms:
            # Heuristic: longest domain that isn't an IP representation
            dom = max(doms, key=len)
            if not ip_pat.fullmatch(dom):
                yield _Entry(ts=ts_m.group(1), domain=dom.rstrip('.'), src=ip_m.group(1) if ip_m else "")


def _parse_plain(lines: list[str]) -> Iterator[_Entry]:
    for line in lines:
        dom = line.strip().rstrip('.')
        if dom and not dom.startswith('#'):
            yield _Entry(ts="", domain=dom, src="")


def _parse_generic(lines: list[str]) -> Iterator[_Entry]:
    ip_pat  = re.compile(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b')
    dom_pat = re.compile(r'\b((?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,})\b')
    # Exclude common non-DNS domain-looking strings
    _NOISE = frozenset({'example.com', 'localhost', 'local', 'internal', 'corp', 'lan'})
    for line in lines:
        doms = [d for d in dom_pat.findall(line) if d.lower() not in _NOISE]
        if doms:
            ip_m = ip_pat.search(line)
            dom  = max(doms, key=len)
            yield _Entry(ts="", domain=dom.rstrip('.'), src=ip_m.group(1) if ip_m else "")


_PARSERS: dict = {
    _FMT_PIHOLE:   _parse_pihole,
    _FMT_BIND:     _parse_bind,
    _FMT_UNBOUND:  _parse_unbound,
    _FMT_NEXTDNS:  _parse_nextdns,
    _FMT_UMBRELLA: _parse_umbrella,
    _FMT_WINDDNS:  _parse_windows_dns,
    _FMT_PLAIN:    _parse_plain,
    _FMT_GENERIC:  _parse_generic,
}


def parse_log(content: str, fmt: str | None = None) -> tuple[str, list[_Entry]]:
    """Parse DNS log content. Returns (detected_format, entries)."""
    lines = content.splitlines()
    detected = fmt or _detect_format(lines)
    parser   = _PARSERS.get(detected, _parse_generic)
    entries  = list(parser(lines))
    return detected, entries


# ---------------------------------------------------------------------------
# Catalog lookup — suffix match
# ---------------------------------------------------------------------------

def _catalog_lookup(domain: str) -> dict | None:
    d = domain.lower()
    # Exact match first
    if d in _CATALOG:
        return {"matched_domain": d, **_CATALOG[d]}
    # Suffix match: walk up the domain tree
    parts = d.split('.')
    for i in range(1, len(parts)):
        candidate = '.'.join(parts[i:])
        if candidate in _CATALOG:
            return {"matched_domain": candidate, **_CATALOG[candidate]}
    # Wildcard patterns
    for suffix, meta in _WILDCARD_PATTERNS:
        if d.endswith(suffix) or d == suffix.lstrip('.'):
            return {"matched_domain": suffix.lstrip('.'), **meta}
    return None


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

@dataclass
class DnsInventoryResult:
    source: str
    fmt: str
    total_queries: int = 0
    ai_queries: int = 0
    unique_sources: list = field(default_factory=list)
    services: list = field(default_factory=list)
    shadow_ai: list = field(default_factory=list)
    by_source: dict = field(default_factory=dict)
    policy_gaps: list = field(default_factory=list)
    errors: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "source":         self.source,
            "format":         self.fmt,
            "total_queries":  self.total_queries,
            "ai_queries":     self.ai_queries,
            "unique_sources": self.unique_sources,
            "services":       self.services,
            "shadow_ai":      self.shadow_ai,
            "by_source":      self.by_source,
            "policy_gaps":    self.policy_gaps,
            "errors":         self.errors,
        }


def analyze(
    entries: list[_Entry],
    approved_domains: list[str] | None = None,
) -> DnsInventoryResult:
    """
    Match DNS entries against the AI catalog and return an inventory result.

    approved_domains: list of base domains the org has explicitly sanctioned
                      (e.g. ["openai.azure.com", "copilot.microsoft.com"]).
                      If None, shadow AI detection is skipped.
    """
    approved_set = set(d.lower() for d in (approved_domains or []))

    # Per-service aggregation keyed by matched_domain
    service_agg: dict[str, dict] = {}
    # Per-source-IP aggregation
    source_agg:  dict[str, set] = defaultdict(set)
    total = 0

    for entry in entries:
        total += 1
        match = _catalog_lookup(entry.domain)
        if not match:
            continue

        key = match["matched_domain"]
        if key not in service_agg:
            service_agg[key] = {
                "domain":          key,
                "queried_as":      set(),
                "vendor":          match["vendor"],
                "product":         match["product"],
                "category":        match["category"],
                "risk":            match["risk"],
                "query_count":     0,
                "unique_sources":  set(),
                "first_seen":      entry.ts,
                "last_seen":       entry.ts,
            }

        svc = service_agg[key]
        svc["queried_as"].add(entry.domain)
        svc["query_count"] += 1
        if entry.src:
            svc["unique_sources"].add(entry.src)
            source_agg[entry.src].add(key)
        if entry.ts and svc["first_seen"] and entry.ts < svc["first_seen"]:
            svc["first_seen"] = entry.ts
        if entry.ts and entry.ts > svc["last_seen"]:
            svc["last_seen"] = entry.ts

    ai_queries = sum(s["query_count"] for s in service_agg.values())

    # Serialise sets → lists, determine approved status
    services = []
    shadow   = []
    for svc in sorted(service_agg.values(), key=lambda s: -s["query_count"]):
        svc_out = {
            **svc,
            "queried_as":     sorted(svc["queried_as"]),
            "unique_sources": sorted(svc["unique_sources"]),
        }
        if approved_set:
            is_approved = any(
                q == d or q.endswith('.' + d)
                for q in svc["queried_as"]
                for d in approved_set
            ) or svc["domain"] in approved_set
            svc_out["approved"] = is_approved
            if not is_approved:
                shadow.append(svc_out["domain"])
        else:
            svc_out["approved"] = None
        services.append(svc_out)

    # Policy gaps
    gaps = []
    high_risk = [s for s in services if s["risk"] == "high"]
    if high_risk:
        gaps.append({
            "id":       "DNS-001",
            "severity": "high",
            "title":    "High-risk AI services detected",
            "detail":   f"{len(high_risk)} service(s) flagged high-risk: " +
                        ", ".join(s['product'] for s in high_risk),
            "remediation": "Review and block or explicitly approve these services via policy.",
        })
    if shadow:
        gaps.append({
            "id":       "DNS-002",
            "severity": "medium",
            "title":    "Shadow AI detected",
            "detail":   f"{len(shadow)} AI service(s) in use that are not in the approved list: " +
                        ", ".join(shadow),
            "remediation": "Add to approved list or block via DNS/firewall policy.",
        })
    multi_vendor = {s["vendor"] for s in services}
    if len(multi_vendor) > 5:
        gaps.append({
            "id":       "DNS-003",
            "severity": "low",
            "title":    "Broad AI vendor sprawl",
            "detail":   f"{len(multi_vendor)} different AI vendors detected. Consolidation reduces risk surface.",
            "remediation": "Establish a preferred vendor list and route usage accordingly.",
        })

    by_source = {
        ip: sorted(domains)
        for ip, domains in sorted(source_agg.items())
    }

    return DnsInventoryResult(
        source         = "",
        fmt            = "",
        total_queries  = total,
        ai_queries     = ai_queries,
        unique_sources = sorted({src for svc in service_agg.values() for src in svc["unique_sources"]}),
        services       = services,
        shadow_ai      = shadow,
        by_source      = by_source,
        policy_gaps    = gaps,
    )


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def connect(
    log_path: str | None = None,
    log_content: str | None = None,
    approved_domains: list[str] | None = None,
    fmt: str | None = None,
) -> dict:
    """
    Parse a DNS log and return a structured AI inventory.

    Pass either:
      log_path     — path to a DNS log file on disk
      log_content  — raw log text (for browser/API uploads)

    approved_domains: list of sanctioned base domains. When provided, any
                      detected AI service not matching this list is flagged
                      as shadow AI.

    Returns a dict (call .to_dict() compatible shape) with:
      format, total_queries, ai_queries, unique_sources,
      services, shadow_ai, by_source, policy_gaps, errors
    """
    result = DnsInventoryResult(source=log_path or "<inline>", fmt="")
    content = ""

    try:
        if log_content is not None:
            content = log_content.lstrip('﻿')  # strip BOM if present
        elif log_path:
            content = Path(log_path).read_text(encoding="utf-8-sig", errors="replace")
        else:
            result.errors.append("No log_path or log_content provided.")
            return result.to_dict()
    except OSError as e:
        result.errors.append(f"Failed to read log file: {e}")
        return result.to_dict()

    detected_fmt, entries = parse_log(content, fmt=fmt)
    analysis = analyze(entries, approved_domains=approved_domains)

    analysis.source = result.source
    analysis.fmt    = detected_fmt
    return analysis.to_dict()


# ---------------------------------------------------------------------------
# CLI — quick local test
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(description="Arckon DNS Log Connector")
    parser.add_argument("log", help="Path to DNS log file")
    parser.add_argument("--approved", nargs="*", default=None,
                        help="Space-separated list of approved AI domains")
    parser.add_argument("--fmt", default=None,
                        help="Force log format (pihole|bind|unbound|umbrella_csv|windows_dns|plain_domains|generic)")
    parser.add_argument("--out", default=None, help="Write JSON output to file")
    args = parser.parse_args()

    result = connect(log_path=args.log, approved_domains=args.approved, fmt=args.fmt)

    output = json.dumps(result, indent=2, default=str)
    if args.out:
        Path(args.out).write_text(output, encoding="utf-8")
        print(f"Results written to {args.out}")
    else:
        print(output)
