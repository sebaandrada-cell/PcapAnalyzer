#!/usr/bin/env bash
# End-to-end check of the customer bundle, the way a buyer uses it.
#
#   scripts/verify-bundle.sh release/pcapanalyzer-1.1.0.tar.gz
#       Unpacks the bundle in a temp dir, runs the SHIPPED ./start.sh (needs
#       Docker), waits for the stack and exercises it through the real nginx
#       proxy. Tears everything down at the end. Used by CI, also runnable on
#       any machine with Docker.
#
#   scripts/verify-bundle.sh --checks-only <base-url> <token> <sample.pcap> [--no-frontend]
#       Only the HTTP assertions, against a stack that is already running.
#
# Exit status: 0 = all checks passed, 1 = some check failed, 2 = usage/setup.
set -u

PASS=0
FAIL=0
WORK=""
START_PID=""
BUNDLE_DIR=""

die() { printf 'ERROR: %s\n' "$*" >&2; exit 2; }
ok()  { printf '  ✔ %s\n' "$*"; PASS=$((PASS + 1)); }
ko()  { printf '  ✘ %s\n' "$*" >&2; FAIL=$((FAIL + 1)); }

cleanup() {
  if [ -n "$START_PID" ] && kill -0 "$START_PID" 2>/dev/null; then
    kill -INT "$START_PID" 2>/dev/null || true
    sleep 3
    kill "$START_PID" 2>/dev/null || true
  fi
  if [ -n "$BUNDLE_DIR" ] && [ -d "$BUNDLE_DIR" ]; then
    (cd "$BUNDLE_DIR" && docker compose down -v --remove-orphans >/dev/null 2>&1) || true
  fi
  if [ -n "$WORK" ] && [ -d "$WORK" ]; then rm -rf "$WORK"; fi
}
trap cleanup EXIT

command -v curl >/dev/null 2>&1 || die "Falta curl."
command -v python3 >/dev/null 2>&1 || die "Falta python3."

# ── helpers ──────────────────────────────────────────────────────────────
BODY=""
# curl already prints 000 as the status when it cannot connect.
http() { curl -sS -m 180 -o "$BODY" -w '%{http_code}' "$@" 2>/dev/null || true; }
# Evaluate a python expression on the last JSON response (bound to `d`).
json() { python3 -c 'import json, sys; d = json.load(open(sys.argv[1])); '"$1" "$BODY" 2>/dev/null; }

run_checks() {
  base="$1"; token="$2"; sample="$3"; frontend="$4"
  auth="Authorization: Bearer $token"

  echo "Salud y arranque / health"
  c=$(http "$base/health")
  [ "$c" = 200 ] && ok "/health → 200" || ko "/health → $c"
  [ "$(json 'print(d["auth"]["enabled"] and d["auth"]["mode"] == "token")')" = True ] \
    && ok "autenticación por token activa" || ko "la autenticación por token no está activa"
  [ "$(json 'print(d["tshark"]["available"])')" = True ] \
    && ok "tshark disponible en el contenedor" || ko "tshark no disponible"
  [ "$(json 'print(d["ai"]["model"])')" = demo ] \
    && ok "IA en modo demo, sin clave de Anthropic" || ko "la IA no está en modo demo"

  if [ "$frontend" = 1 ]; then
    echo "Frontend (nginx)"
    c=$(http "$base/")
    if [ "$c" = 200 ] && grep -q 'id="root"' "$BODY"; then ok "la web carga"; else ko "la web no carga (HTTP $c)"; fi
    c=$(http "$base/sample.pcap")
    magic=$(head -c4 "$BODY" | od -An -tx1 | tr -d ' \n')
    case "$magic" in
      a1b2c3d4|d4c3b2a1|a1b23c4d|4d3cb2a1|0a0d0d0a)
        ok "la captura de ejemplo se sirve ($(wc -c < "$BODY" | tr -d ' ') bytes)"
        cp "$BODY" "$WORK/sample.pcap"; sample="$WORK/sample.pcap" ;;
      *) ko "/sample.pcap no es una captura (HTTP $c, magic=$magic)" ;;
    esac
  fi
  [ -f "$sample" ] || { ko "no hay captura de muestra para probar"; return; }

  echo "Autenticación / auth"
  c=$(http -X POST "$base/analyze" -F "file=@$sample")
  [ "$c" = 401 ] && ok "sin token → 401" || ko "sin token → $c (debería ser 401)"
  c=$(http -X POST "$base/analyze" -H "Authorization: Bearer token-incorrecto" -F "file=@$sample")
  [ "$c" = 401 ] && ok "token incorrecto → 401" || ko "token incorrecto → $c (debería ser 401)"

  echo "Análisis / analysis"
  c=$(http -X POST "$base/analyze" -H "$auth" -F "file=@$sample")
  packets=$(json 'print(d["summary"]["packets"])'); issues=$(json 'print(len(d["issues"]))')
  if [ "$c" = 200 ] && [ "${packets:-0}" = 56 ] && [ "${issues:-0}" -ge 10 ]; then
    ok "token correcto + muestra → 200 ($packets paquetes, $issues problemas)"
    cp "$BODY" "$WORK/analysis.json"
  else
    ko "análisis de la muestra: HTTP $c, paquetes=${packets:-?}, problemas=${issues:-?}"
  fi
  gzip -c "$sample" > "$WORK/sample.pcap.gz"
  c=$(http -X POST "$base/analyze" -H "$auth" -F "file=@$WORK/sample.pcap.gz")
  [ "$c" = 200 ] && ok "captura .pcap.gz → 200" || ko ".pcap.gz → $c"
  printf 'esto no es una captura de red' > "$WORK/not-a-capture.txt"
  c=$(http -X POST "$base/analyze" -H "$auth" -F "file=@$WORK/not-a-capture.txt")
  [ "$c" = 400 ] && ok "archivo que no es captura → 400" || ko "archivo que no es captura → $c"

  c=$(http -X POST "$base/analyze/async" -H "$auth" -F "file=@$sample")
  if [ "$c" = 202 ]; then
    job=$(json 'print(d["job_id"])'); st=""
    for _ in $(seq 1 45); do
      c=$(http -H "$auth" "$base/jobs/$job"); st=$(json 'print(d["status"])')
      [ "$st" = done ] || [ "$st" = error ] && break
      sleep 2
    done
    [ "$st" = done ] && ok "cola asíncrona: trabajo terminado" || ko "cola asíncrona: estado final '${st:-?}'"
  else
    ko "/analyze/async → $c (debería ser 202)"
  fi

  echo "IA (demo) e informe PDF"
  if [ -f "$WORK/analysis.json" ]; then
    python3 -c 'import json,sys; print(json.dumps({"analysis": json.load(open(sys.argv[1])), "lang": "es"}))' \
      "$WORK/analysis.json" > "$WORK/diag.json"
    c=$(http -X POST "$base/diagnose" -H "$auth" -H 'Content-Type: application/json' --data @"$WORK/diag.json")
    if [ "$c" = 200 ] && grep -q 'modo demo' "$BODY"; then ok "/diagnose → 200, marcado «modo demo»"; else ko "/diagnose → $c"; fi
    python3 -c 'import json,sys; print(json.dumps({"analysis": json.load(open(sys.argv[1])), "diagnosis": "texto de prueba"}))' \
      "$WORK/analysis.json" > "$WORK/report.json"
    c=$(http -X POST "$base/report" -H "$auth" -H 'Content-Type: application/json' --data @"$WORK/report.json")
    if [ "$c" = 200 ] && [ "$(head -c4 "$BODY")" = "%PDF" ]; then ok "/report → PDF válido ($(wc -c < "$BODY" | tr -d ' ') bytes)"; else ko "/report → $c"; fi
    # Investigation sessions: the analysis carries a session and the demo agent streams a report.
    sid=$(python3 -c 'import json,sys; s=json.load(open(sys.argv[1])).get("session") or {}; print(s.get("id",""))' "$WORK/analysis.json")
    if [ -n "$sid" ]; then ok "/analyze devuelve una sesión de investigación"; else ko "/analyze no devuelve session.id"; fi
    if [ -n "$sid" ]; then
      c=$(http -X POST "$base/sessions/$sid/chat" -H "$auth" -H 'Content-Type: application/json' --data '{"message":"__investigate__","lang":"es"}')
      if [ "$c" = 200 ] && grep -q '^event: done' "$BODY" && grep -q 'filter: tcp.stream' "$BODY"; then ok "/sessions/{id}/chat (demo) → informe por SSE con evidencia"; else ko "/sessions/{id}/chat → $c"; fi
      # Real display filters over the kept capture (packets beyond the list sample).
      c=$(http -X POST "$base/sessions/$sid/packets" -H "$auth" -H 'Content-Type: application/json' --data '{"filter":"tcp.flags.reset == 1","limit":50}')
      if [ "$c" = 200 ] && python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); rows=d["rows"]; sys.exit(0 if rows and all("RST" in r["tcp_flags"] for r in rows) else 1)' "$BODY"; then ok "/sessions/{id}/packets → filtro real de Wireshark sobre la captura"; else ko "/sessions/{id}/packets → $c"; fi
    else
      ko "sin sesión: se omiten /sessions/{id}/chat y /sessions/{id}/packets"
    fi
  else
    ko "sin análisis previo: se omiten /diagnose y /report"
  fi
}

summary() {
  echo
  echo "RESULTADO: $PASS correctos, $FAIL fallos"
  [ "$FAIL" -eq 0 ]
}

# ── modo --checks-only ───────────────────────────────────────────────────
if [ "${1:-}" = "--checks-only" ]; then
  [ $# -ge 4 ] || die "Uso: $0 --checks-only <base-url> <token> <sample.pcap> [--no-frontend]"
  WORK="$(mktemp -d "${TMPDIR:-/tmp}/pcap-verify.XXXXXX")"; BODY="$WORK/body"
  front=1; [ "${5:-}" = "--no-frontend" ] && front=0
  run_checks "${2%/}" "$3" "$4" "$front"
  summary && exit 0 || exit 1
fi

# ── modo paquete completo ────────────────────────────────────────────────
TARBALL="${1:-}"
[ -n "$TARBALL" ] && [ -f "$TARBALL" ] || die "Uso: $0 <paquete.tar.gz>   (o --checks-only ...)"
command -v docker >/dev/null 2>&1 || die "Docker no está instalado: esta comprobación lo necesita."
docker compose version >/dev/null 2>&1 || die "Falta el plugin 'docker compose'."

WORK="$(mktemp -d "${TMPDIR:-/tmp}/pcap-verify.XXXXXX")"; BODY="$WORK/body"
tar -xzf "$TARBALL" -C "$WORK"
BUNDLE_DIR="$(find "$WORK" -mindepth 1 -maxdepth 1 -type d | head -n 1)"
[ -n "$BUNDLE_DIR" ] && [ -x "$BUNDLE_DIR/start.sh" ] || die "El paquete no trae un start.sh ejecutable."

PORT="${VERIFY_PORT:-18080}"
BASE="http://127.0.0.1:$PORT"
export PCAPANALYZER_PORT="$PORT" COMPOSE_PROJECT_NAME=pcapverify

echo "Arrancando el paquete con su propio ./start.sh (la primera vez construye las imágenes)..."
( cd "$BUNDLE_DIR" && exec ./start.sh ) > "$WORK/start.log" 2>&1 &
START_PID=$!

deadline=$(( $(date +%s) + ${VERIFY_TIMEOUT_S:-900} ))
healthy=0
while [ "$(date +%s)" -lt "$deadline" ]; do
  if ! kill -0 "$START_PID" 2>/dev/null; then break; fi
  if curl -fsS -m 3 -o /dev/null "$BASE/health" 2>/dev/null; then healthy=1; break; fi
  sleep 3
done

dump_logs() {
  echo "──── últimas líneas de start.sh ────" >&2
  tail -n 80 "$WORK/start.log" >&2 || true
  echo "──── docker compose logs ────" >&2
  (cd "$BUNDLE_DIR" && docker compose logs --tail=80 2>&1) >&2 || true
}

if [ "$healthy" != 1 ]; then
  ko "la aplicación no llegó a responder en $BASE"
  dump_logs
  summary; exit 1
fi
echo "La aplicación responde. Comprobando lo que hace start.sh..."

echo "start.sh"
ENV_FILE="$BUNDLE_DIR/.env"
[ -f "$ENV_FILE" ] && ok "crea .env" || ko "no creó .env"
mode=$(python3 -c 'import os, sys; print(oct(os.stat(sys.argv[1]).st_mode & 0o777))' "$ENV_FILE" 2>/dev/null)
[ "$mode" = 0o600 ] && ok ".env con permisos 600" || ko ".env con permisos $mode (debería ser 0o600)"
TOKEN="$(sed -n 's/^API_TOKENS=//p' "$ENV_FILE" | tail -n 1)"
printf '%s' "$TOKEN" | grep -qE '^[0-9a-f]{64}$' && ok "token aleatorio de 64 caracteres hex" || ko "token con formato inesperado"
count=$(grep -cF -- "$TOKEN" "$WORK/start.log")
[ "$count" = 1 ] && ok "el token se muestra una sola vez y no aparece en los logs" || ko "el token aparece $count veces en la salida (debería ser 1)"
grep -q '^LLM_DEMO=1' "$ENV_FILE" && ok "modo demo activado por defecto" || ko "LLM_DEMO no está a 1"

run_checks "$BASE" "$TOKEN" "" 1
if summary; then exit 0; else dump_logs; exit 1; fi
