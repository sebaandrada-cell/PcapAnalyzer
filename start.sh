#!/usr/bin/env bash
# PcapAnalyzer — one-command start for macOS / Linux (and Git Bash / WSL on Windows).
#
#   ./start.sh
#
# What it does:
#   1. Checks that Docker (with the compose plugin) is available.
#   2. Makes sure .env has a real, random API_TOKENS value. It is generated the
#      first time and never overwritten afterwards, and your other .env lines
#      are left alone. The token is shown once, when it is created.
#   3. Runs `docker compose up --build`.
#
# Paste the token into the "Token API" field (top right) of the web UI.
set -eu

cd "$(dirname "$0")"

ENV_FILE=".env"
EXAMPLE_FILE=".env.example"
# Value that older versions of .env.example shipped; it is public, so never use it.
PLACEHOLDER="replace-with-a-long-random-token"

say() { printf '%s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

# ── 1. Docker ────────────────────────────────────────────────────────────
command -v docker >/dev/null 2>&1 || die "Docker no está instalado / Docker is not installed.
  Instálalo desde https://docs.docker.com/get-docker/ y vuelve a ejecutar ./start.sh"

if docker compose version >/dev/null 2>&1; then
  COMPOSE="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE="docker-compose"
else
  die "Falta Docker Compose / Docker Compose is missing.
  Instala Docker Desktop, o el plugin 'docker compose'."
fi

# ── 2. Token ─────────────────────────────────────────────────────────────
new_token() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 32
  elif command -v python3 >/dev/null 2>&1; then
    python3 -c 'import secrets; print(secrets.token_hex(32))'
  else
    # POSIX fallback: 32 random bytes as hex.
    head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'
    echo
  fi
}

env_value() {
  # Last KEY= line of .env, value only; empty if the file or the key is missing.
  [ -f "$ENV_FILE" ] || return 0
  sed -n "s/^$1=//p" "$ENV_FILE" | tail -n 1 | tr -d '\r"'"'"' '
}

set_var() {
  # Replace the KEY= line in place (or append it), keeping everything else.
  key="$1"
  value="$2"
  tmp="$(mktemp "${TMPDIR:-/tmp}/pcap-env.XXXXXX")"
  if [ -f "$ENV_FILE" ] && grep -q "^$key=" "$ENV_FILE"; then
    awk -v key="$key" -v val="$value" '
      index($0, key "=") == 1 { if (!done) { print key "=" val; done = 1 } ; next }
      { print }
    ' "$ENV_FILE" > "$tmp"
  else
    [ -f "$ENV_FILE" ] && cat "$ENV_FILE" > "$tmp"
    printf '%s=%s\n' "$key" "$value" >> "$tmp"
  fi
  # `cat >` rewrites the existing file, so its 600 permissions are kept.
  cat "$tmp" > "$ENV_FILE"
  rm -f "$tmp"
}

if [ ! -f "$ENV_FILE" ]; then
  if [ -f "$EXAMPLE_FILE" ]; then
    cp "$EXAMPLE_FILE" "$ENV_FILE"
    say "Creado $ENV_FILE a partir de $EXAMPLE_FILE / Created $ENV_FILE from $EXAMPLE_FILE"
  else
    : > "$ENV_FILE"
  fi
fi
chmod 600 "$ENV_FILE" 2>/dev/null || true

TOKEN="$(env_value API_TOKENS)"
if [ -z "$TOKEN" ] || [ "$TOKEN" = "$PLACEHOLDER" ]; then
  TOKEN="$(new_token)"
  [ -n "$TOKEN" ] || die "No se pudo generar un token aleatorio / Could not generate a random token."
  set_var API_TOKENS "$TOKEN"
  say ""
  say "════════════════════════════════════════════════════════════════════"
  say " Tu token de acceso / Your access token (se muestra una sola vez):"
  say ""
  say "   $TOKEN"
  say ""
  say " Pégalo en el campo «Token API» (arriba a la derecha) de la web."
  say " Paste it in the \"API token\" field (top right) of the web UI."
  say " Queda guardado en $ENV_FILE (solo legible por ti)."
  say "════════════════════════════════════════════════════════════════════"
  say ""
else
  say "Usando el token ya guardado en $ENV_FILE / Using the token already in $ENV_FILE"
  say "  (para verlo: grep API_TOKENS $ENV_FILE)"
fi

# ── 3. AI mode ───────────────────────────────────────────────────────────
# No Anthropic key and no explicit choice -> demo mode (simulated diagnosis, no
# cost), so the AI panel works out of the box. Demo mode wins over a real key,
# so warn when both are present.
AI_KEY="$(env_value ANTHROPIC_API_KEY)"
AI_DEMO="$(env_value LLM_DEMO)"
case "$AI_DEMO" in 1|true|TRUE|True|yes|YES|Yes) DEMO_ON=1 ;; *) DEMO_ON=0 ;; esac
if [ -z "$AI_KEY" ] && [ -z "$AI_DEMO" ]; then
  set_var LLM_DEMO 1
  say "Sin clave de Anthropic: modo demo activado (diagnóstico simulado, sin coste)."
  say "No Anthropic key: demo mode on (simulated diagnosis, no cost)."
elif [ -n "$AI_KEY" ] && [ "$DEMO_ON" = 1 ]; then
  say "AVISO: tienes ANTHROPIC_API_KEY pero LLM_DEMO=1 sigue activo, así que se usará el"
  say "  modo demo. Para usar la IA real pon LLM_DEMO=0 en $ENV_FILE."
  say "NOTE: ANTHROPIC_API_KEY is set but LLM_DEMO=1 is still on, so demo mode is used."
  say "  Set LLM_DEMO=0 in $ENV_FILE to use the real model."
fi

# ── 4. Run ───────────────────────────────────────────────────────────────
PORT_NUM="$(env_value PCAPANALYZER_PORT)"
say "Arrancando en / Starting on http://localhost:${PORT_NUM:-8080}  (Ctrl+C para parar / to stop)"
exec $COMPOSE up --build
