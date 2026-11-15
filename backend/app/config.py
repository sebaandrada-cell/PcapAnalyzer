"""Runtime configuration, overridable via environment variables.

A `backend/.env` file (see .env.example) is loaded first, so credentials like
ANTHROPIC_API_KEY can live there instead of the shell environment.
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import List

from dotenv import load_dotenv

# backend/.env — anchored to this file so it works regardless of cwd.
load_dotenv(Path(__file__).resolve().parents[1] / ".env")


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


# Explicit tshark binary location; auto-discovered when unset.
TSHARK_PATH_ENV = "TSHARK_PATH"

# Upload / execution limits.
MAX_UPLOAD_MB = _int_env("MAX_UPLOAD_MB", 200)
MAX_DECOMPRESSED_MB = _int_env("MAX_DECOMPRESSED_MB", 500)
TSHARK_TIMEOUT_S = _int_env("TSHARK_TIMEOUT_S", 300)
API_TOKENS: List[str] = [
    token.strip()
    for token in os.environ.get("API_TOKENS", "").split(",")
    if token.strip()
]
API_MAX_REQUESTS_PER_MINUTE = _int_env("API_MAX_REQUESTS_PER_MINUTE", 30)
API_MAX_JOBS_PER_TOKEN = _int_env("API_MAX_JOBS_PER_TOKEN", 2)
# Abuse/cost guards (0 disables a limit). The IP limit runs before auth so
# unauthenticated floods and bots are throttled; the LLM caps are hard daily
# ceilings on paid Anthropic calls, per principal and across the whole service.
IP_MAX_REQUESTS_PER_MINUTE = _int_env("IP_MAX_REQUESTS_PER_MINUTE", 120)
IP_MAX_UPLOADS_PER_MINUTE = _int_env("IP_MAX_UPLOADS_PER_MINUTE", 6)
# Proxies between the client and the app that append to X-Forwarded-For
# (0 = the last entry is the client, as with the bundled nginx; Render behind
# Cloudflare appends two: the Cloudflare edge and Render's own proxy).
TRUSTED_PROXY_HOPS = _int_env("TRUSTED_PROXY_HOPS", 0)
LLM_MAX_CALLS_PER_DAY = _int_env("LLM_MAX_CALLS_PER_DAY", 20)
LLM_MAX_CALLS_PER_DAY_GLOBAL = _int_env("LLM_MAX_CALLS_PER_DAY_GLOBAL", 200)

# Investigation sessions and the AI agent
# (see docs/superpowers/specs/2026-11-01-ai-investigation-agent-design.md).
# The capture is kept encrypted on local disk while the user investigates it;
# the key only lives in process memory. Every cap below is a hard ceiling.
SESSIONS_ENABLED = os.environ.get("SESSIONS_ENABLED", "1").lower() in ("1", "true", "yes")
SESSION_DIR = os.environ.get(
    "SESSION_DIR",
    os.path.join(tempfile.gettempdir(), "pcapanalyzer", "sessions"),
)
SESSION_TTL_MINUTES = _int_env("SESSION_TTL_MINUTES", 60)
MAX_SESSIONS = _int_env("MAX_SESSIONS", 20)
MAX_SESSION_BYTES = _int_env("MAX_SESSION_BYTES", 2 * 1024 ** 3)
SESSION_MAX_TOKENS = _int_env("SESSION_MAX_TOKENS", 2_000_000)
TOOL_TIMEOUT_S = _int_env("TOOL_TIMEOUT_S", 30)
TOOL_MAX_ROWS = _int_env("TOOL_MAX_ROWS", 200)
TOOL_MAX_OUTPUT_BYTES = _int_env("TOOL_MAX_OUTPUT_BYTES", 65536)
AGENT_MAX_TOOL_CALLS = _int_env("AGENT_MAX_TOOL_CALLS", 25)
AGENT_MAX_MODEL_CALLS = _int_env("AGENT_MAX_MODEL_CALLS", 20)
AGENT_TASK_BUDGET_TOKENS = _int_env("AGENT_TASK_BUDGET_TOKENS", 60_000)
AGENT_WORKERS = _int_env("AGENT_WORKERS", 2)
AGENT_EFFORT = os.environ.get("AGENT_EFFORT", "high").strip().lower()
if AGENT_EFFORT not in {"low", "medium", "high", "xhigh", "max"}:
    raise ValueError("AGENT_EFFORT must be one of low, medium, high, xhigh, max.")
AGENT_COMPACT_TOKENS = _int_env("AGENT_COMPACT_TOKENS", 150_000)
# stream_detail parses the whole flow (metrics must cover it); this bounds RAM, not rows.
TOOL_STREAM_MAX_BYTES = _int_env("TOOL_STREAM_MAX_BYTES", 64 * 1024 * 1024)
AGENT_PARALLEL_TOOLS = _int_env("AGENT_PARALLEL_TOOLS", 4)
if AGENT_TASK_BUDGET_TOKENS < 20_000:
    raise ValueError("AGENT_TASK_BUDGET_TOKENS must be at least 20000 (API minimum).")
# Interactive API docs expose the full schema to scanners; off unless asked.
DOCS_ENABLED = os.environ.get("DOCS_ENABLED", "").lower() in ("1", "true", "yes")

# Shared SaaS infrastructure. Supabase mode is enabled explicitly and requires
# Auth, Postgres, and a private Storage bucket.
AUTH_MODE = os.environ.get("AUTH_MODE", "token").strip().lower()
if AUTH_MODE not in {"token", "supabase"}:
    raise ValueError("AUTH_MODE must be either 'token' or 'supabase'.")
SUPABASE_URL = os.environ.get("SUPABASE_URL", "").rstrip("/")
SUPABASE_ANON_KEY = os.environ.get("SUPABASE_ANON_KEY", "")
SUPABASE_SERVICE_ROLE_KEY = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "")
SUPABASE_DB_URL = os.environ.get("SUPABASE_DB_URL", "")
SUPABASE_JWT_SECRET = os.environ.get("SUPABASE_JWT_SECRET", "")
SUPABASE_STORAGE_BUCKET = os.environ.get("SUPABASE_STORAGE_BUCKET", "pcap-captures")
SUPABASE_ENABLED = AUTH_MODE == "supabase"

# CORS origins for the future React frontend (comma-separated).
CORS_ORIGINS = [
    origin.strip()
    for origin in os.environ.get(
        "CORS_ORIGINS", "http://localhost:5173,http://localhost:3000"
    ).split(",")
    if origin.strip()
]

# Issue-detection thresholds (see CLAUDE.md: >2% retransmissions is critical).
RETRANS_MIN_PACKETS = _int_env("RETRANS_MIN_PACKETS", 5)   # ignore tiny conversations
RETRANS_WARN_PCT = float(os.environ.get("RETRANS_WARN_PCT", 1.0))
RETRANS_CRIT_PCT = float(os.environ.get("RETRANS_CRIT_PCT", 2.0))
SYN_RST_MAX_DELAY_S = float(os.environ.get("SYN_RST_MAX_DELAY_S", 1.0))
DNS_SLOW_THRESHOLD_S = float(os.environ.get("DNS_SLOW_THRESHOLD_S", 0.5))
DNS_NXDOMAIN_MIN = _int_env("DNS_NXDOMAIN_MIN", 3)
TCP_HANDSHAKE_SLOW_S = float(os.environ.get("TCP_HANDSHAKE_SLOW_S", 0.5))
MSS_LOW_THRESHOLD = _int_env("MSS_LOW_THRESHOLD", 1300)
PMTUD_MIN_FULLSIZE_RETRANS = _int_env("PMTUD_MIN_FULLSIZE_RETRANS", 3)
FRAG_HIGH_PCT = float(os.environ.get("FRAG_HIGH_PCT", 5.0))
ESP_ONE_WAY_MIN = _int_env("ESP_ONE_WAY_MIN", 3)
IKE_NO_RESPONSE_MIN = _int_env("IKE_NO_RESPONSE_MIN", 2)
TOP_TALKERS_LIMIT = _int_env("TOP_TALKERS_LIMIT", 10)

# AI layer (Fase 3). Credentials come from the environment (ANTHROPIC_API_KEY
# or an `ant auth login` profile); only the model and limits live here.
LLM_MODEL = os.environ.get("LLM_MODEL", "claude-opus-5-5")
LLM_MAX_TOKENS = _int_env("LLM_MAX_TOKENS", 4096)
LLM_TIMEOUT_S = _int_env("LLM_TIMEOUT_S", 120)
# Demo mode: deterministic fake AI responses, no API calls or credentials.
LLM_DEMO = os.environ.get("LLM_DEMO", "").lower() in ("1", "true", "yes")

# Async analysis queue (Fase 4): in-process worker pool for large captures.
ANALYZE_WORKERS = _int_env("ANALYZE_WORKERS", 2)
MAX_QUEUED_JOBS = _int_env("MAX_QUEUED_JOBS", 4)
MAX_PENDING_CAPTURE_BYTES = _int_env("MAX_PENDING_CAPTURE_BYTES", 1024 * 1024 * 1024)
MAX_RETAINED_JOBS = _int_env("MAX_RETAINED_JOBS", 20)
JOB_TTL_S = _int_env("JOB_TTL_S", 3600)

# Bounded in-memory analysis state.
MAX_CONVERSATIONS = _int_env("MAX_CONVERSATIONS", 20000)
MAX_TRACKED_TALKERS = _int_env("MAX_TRACKED_TALKERS", 20000)
MAX_TIME_SERIES_BUCKETS = _int_env("MAX_TIME_SERIES_BUCKETS", 100000)
MAX_DNS_TRANSACTIONS = _int_env("MAX_DNS_TRANSACTIONS", 20000)
MAX_HTTP_REQUESTS = _int_env("MAX_HTTP_REQUESTS", 10000)
MAX_TLS_SESSIONS = _int_env("MAX_TLS_SESSIONS", 10000)
MAX_TLS_ALERTS = _int_env("MAX_TLS_ALERTS", 5000)
MAX_FRAGMENT_GROUPS = _int_env("MAX_FRAGMENT_GROUPS", 20000)
MAX_ICMP_EVENTS = _int_env("MAX_ICMP_EVENTS", 5000)
MAX_DHCP_TRANSACTIONS = _int_env("MAX_DHCP_TRANSACTIONS", 10000)
MAX_ISSUES = _int_env("MAX_ISSUES", 5000)
TCP_ZERO_WINDOW_MIN_EVENTS = _int_env("TCP_ZERO_WINDOW_MIN_EVENTS", 3)
# TCP analysis flags (Wireshark "SEQ/ACK analysis"). Counts are per conversation.
TCP_DUP_ACK_MIN = _int_env("TCP_DUP_ACK_MIN", 5)             # duplicate ACKs -> loss/reorder
TCP_OUT_OF_ORDER_MIN = _int_env("TCP_OUT_OF_ORDER_MIN", 5)   # reordered segments
TCP_LOST_SEGMENT_MIN = _int_env("TCP_LOST_SEGMENT_MIN", 1)   # "previous segment not captured"
TCP_WINDOW_FULL_MIN = _int_env("TCP_WINDOW_FULL_MIN", 3)     # sender filled the receive window
TCP_RESET_MIN_CONVS = _int_env("TCP_RESET_MIN_CONVS", 3)     # conversations reset after being established
# ICMP errors: a single unreachable is already a signal; TTL exceeded needs a pattern.
ICMP_UNREACHABLE_MIN = _int_env("ICMP_UNREACHABLE_MIN", 1)
ICMP_TTL_EXCEEDED_MIN = _int_env("ICMP_TTL_EXCEEDED_MIN", 5)
MAX_ARP_CLAIMS = _int_env("MAX_ARP_CLAIMS", 20000)
MAX_ARP_MACS_PER_IP = _int_env("MAX_ARP_MACS_PER_IP", 32)
MAX_EXPERT_ENTRIES = _int_env("MAX_EXPERT_ENTRIES", 500)       # per severity band (see engine)
MAX_ICMP_ERROR_GROUPS = _int_env("MAX_ICMP_ERROR_GROUPS", 500)
MAX_RESOLVED_NAMES = _int_env("MAX_RESOLVED_NAMES", 5000)

# Packet list returned to the UI (Wireshark-style view), capped for size.
PACKET_LIST_MAX = _int_env("PACKET_LIST_MAX", 1000)

# --- Application-layer detectors (detectors/http_errors.py) ---
HTTP_SLOW_THRESHOLD_S = float(os.environ.get("HTTP_SLOW_THRESHOLD_S", 1.0))
HTTP_5XX_MIN = _int_env("HTTP_5XX_MIN", 1)
HTTP_4XX_MIN = _int_env("HTTP_4XX_MIN", 5)
# "Mostly failing": this share of at least this many responses raises the severity.
HTTP_ERROR_CRIT_PCT = float(os.environ.get("HTTP_ERROR_CRIT_PCT", 50.0))
HTTP_ERROR_CRIT_MIN_RESPONSES = _int_env("HTTP_ERROR_CRIT_MIN_RESPONSES", 5)
# DISCOVER/REQUEST attempts from one MAC before "no answer" is reported: a capture
# on another host sees a neighbour's broadcast but not the unicast OFFER/ACK.
DHCP_NO_RESPONSE_MIN_ATTEMPTS = _int_env("DHCP_NO_RESPONSE_MIN_ATTEMPTS", 2)

# --- Packet queries over the kept capture (POST /sessions/{id}/packets) ---
PACKET_QUERY_MAX_ROWS = _int_env("PACKET_QUERY_MAX_ROWS", 1000)
PACKET_QUERY_WORKERS = _int_env("PACKET_QUERY_WORKERS", 2)  # concurrent tshark runs
PACKET_QUERY_TIMEOUT_S = _int_env("PACKET_QUERY_TIMEOUT_S", 60)
# Frame numbers of duplicated frames remembered so later queries can mark them.
MAX_DUPLICATE_FRAMES_TRACKED = _int_env("MAX_DUPLICATE_FRAMES_TRACKED", 500000)

# --- Capture quality (limits of the capture itself, see analysis/quality.py) ---
# A frame identical to one seen within this window is a capture duplicate (port
# mirror copying ingress and egress, capture on several interfaces). A real
# retransmission arrives after an RTO or a few RTTs, far outside it.
DUP_FRAME_WINDOW_S = float(os.environ.get("DUP_FRAME_WINDOW_S", 0.001))
DUP_FRAME_TRACK = _int_env("DUP_FRAME_TRACK", 256)  # recent frames remembered
QUALITY_DUP_WARN_PCT = float(os.environ.get("QUALITY_DUP_WARN_PCT", 1.0))
QUALITY_MIN_CONV_PACKETS = _int_env("QUALITY_MIN_CONV_PACKETS", 4)
QUALITY_ONE_WAY_MIN_CONVS = _int_env("QUALITY_ONE_WAY_MIN_CONVS", 3)
QUALITY_ONE_WAY_INFO_PCT = float(os.environ.get("QUALITY_ONE_WAY_INFO_PCT", 10.0))
QUALITY_ONE_WAY_WARN_PCT = float(os.environ.get("QUALITY_ONE_WAY_WARN_PCT", 50.0))
QUALITY_MIDSTREAM_INFO_PCT = float(os.environ.get("QUALITY_MIDSTREAM_INFO_PCT", 50.0))
