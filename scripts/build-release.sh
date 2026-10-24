#!/usr/bin/env bash
# Build the customer download (tar.gz) from the COMMITTED state of the repo and
# refuse to produce it if anything private slipped in.
#
#   scripts/build-release.sh 1.1.0     ->  release/pcapanalyzer-1.1.0.tar.gz
#
# It uses `git archive`, so only tracked files can ever enter the bundle (no
# .env, node_modules, .venv, ...), and files marked `export-ignore` in
# .gitattributes are left out. The result is then unpacked and checked for:
#   - files that must not ship / files that must ship
#   - secrets (Anthropic keys, Supabase service_role JWTs, DB URLs with password)
#   - identifiers of our own infrastructure
# On any failure the tarball is deleted and the script exits non-zero.
set -eu

cd "$(dirname "$0")/.."

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

VERSION="${1:-}"
[ -n "$VERSION" ] || die "Uso: scripts/build-release.sh <versión>   (p. ej. 1.1.0)"
case "$VERSION" in
  *[!0-9A-Za-z.+-]*) die "Versión no válida: $VERSION (solo letras, números, . + -)" ;;
esac

git rev-parse --git-dir >/dev/null 2>&1 || die "No es un repositorio git."
if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
  git status --short --untracked-files=no >&2
  die "Hay cambios sin commitear en archivos rastreados. El paquete se construye desde HEAD: haz commit primero."
fi

NAME="pcapanalyzer-${VERSION}"
OUT="release/${NAME}.tar.gz"
mkdir -p release
rm -f "$OUT"

# gzip -n: no timestamp/name in the header, so the same commit gives the same bytes.
git archive --format=tar --prefix="${NAME}/" HEAD | gzip -n -9 > "$OUT"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/pcap-release.XXXXXX")"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT
tar -xzf "$OUT" -C "$WORK"
ROOT="$WORK/$NAME"

fail=0
bad() { printf '  ✘ %s\n' "$*" >&2; fail=1; }
good() { printf '  ✔ %s\n' "$*"; }

echo "Verificando $OUT ..."

# ── Must NOT ship ────────────────────────────────────────────────────────
for p in .env backend/.env .git .claude CLAUDE.md PLAN-DIFUSION.md landing.html \
         render.yaml scripts release backend/.venv frontend/node_modules frontend/dist \
         frontend/public/demo marketing; do
  [ -e "$ROOT/$p" ] && bad "no debería incluirse: $p"
done
found_env="$(find "$ROOT" -name '.env' -o -name '*.pem' -o -name '*.key' -o -name '.webui_secret_key' 2>/dev/null | head -5)"
[ -z "$found_env" ] || bad "archivos sensibles dentro del paquete: $found_env"

# ── Must ship ────────────────────────────────────────────────────────────
for p in start.sh .env.example docker-compose.yml README.md QUICKSTART.md LICENSE.txt \
         backend/Dockerfile backend/requirements.txt backend/app/main.py \
         frontend/Dockerfile frontend/nginx.conf frontend/package.json frontend/public/sample.pcap; do
  [ -e "$ROOT/$p" ] || bad "falta un archivo necesario: $p"
done
[ -x "$ROOT/start.sh" ] || bad "start.sh no es ejecutable en el paquete"
bash -n "$ROOT/start.sh" 2>/dev/null || bad "start.sh tiene errores de sintaxis"
grep -q '^API_TOKENS=$' "$ROOT/.env.example" 2>/dev/null || bad ".env.example debe traer API_TOKENS vacío (sin token de ejemplo)"
grep -q 'LLM_DEMO' "$ROOT/docker-compose.yml" 2>/dev/null || bad "docker-compose.yml no pasa LLM_DEMO (el modo demo no funcionaría)"

# ── Secrets (names only, values are never printed) ───────────────────────
scan() { # $1=label  $2=ERE
  hits="$(grep -rIlE -- "$2" "$ROOT" 2>/dev/null | sed "s#^$ROOT/##" | head -5)"
  [ -z "$hits" ] || bad "$1 en: $(echo "$hits" | tr '\n' ' ')"
}
scan "clave de Anthropic (sk-ant-)"            'sk-ant-api[0-9]{2}-[A-Za-z0-9_-]{16,}'
scan "URL de Postgres con contraseña"           'postgres(ql)?://[^:@/[:space:]<>]+:[^@[:space:]<>[]{4,}@'

# Supabase service_role keys are JWTs. A fixed base64 fragment is NOT reliable
# (the encoding of `"role":"service_role"` changes with its offset in the
# payload), so decode every JWT-looking string and check its `role` claim.
command -v python3 >/dev/null 2>&1 || die "Se necesita python3 para verificar los JWT del paquete."
jwt_hits="$(python3 - "$ROOT" <<'PY'
import base64, json, os, re, sys

root = sys.argv[1]
jwt = re.compile(rb"eyJ[A-Za-z0-9_-]{8,}\.(eyJ[A-Za-z0-9_-]{8,})\.[A-Za-z0-9_-]{8,}")
found = set()
for base, _dirs, files in os.walk(root):
    for name in files:
        path = os.path.join(base, name)
        try:
            data = open(path, "rb").read()
        except OSError:
            continue
        if b"\0" in data[:4096]:
            continue  # binary file
        for match in jwt.finditer(data):
            payload = match.group(1)
            payload += b"=" * (-len(payload) % 4)
            try:
                claims = json.loads(base64.urlsafe_b64decode(payload))
            except Exception:
                continue
            if isinstance(claims, dict) and claims.get("role") == "service_role":
                found.add(os.path.relpath(path, root))
print("\n".join(sorted(found)))
PY
)"
[ -z "$jwt_hits" ] || bad "JWT de Supabase con role=service_role en: $(echo "$jwt_hits" | head -5 | tr '\n' ' ')"
scan "clave privada PEM"                        '-----BEGIN [A-Z ]*PRIVATE KEY-----'

# ── Our own infrastructure must not leak to customers ────────────────────
scan "ref. del proyecto Supabase propio"        'pmmnobjhjfafgdccsywy'
scan "dominio de la beta alojada"               'pcapanalyzer-api\.onrender\.com|pcap-analyzer-(seven|noviembrepunk)'

if [ "$fail" -ne 0 ]; then
  rm -f "$OUT"
  die "La verificación falló; se ha borrado $OUT. Corrige lo anterior y vuelve a ejecutar."
fi

good "no incluye archivos internos ni .env"
good "incluye todo lo necesario (start.sh ejecutable, compose, guías, licencia, muestra)"
good "sin secretos ni datos de nuestra infraestructura"
echo
echo "Listo: $OUT"
printf '  commit : %s\n' "$(git rev-parse --short HEAD)"
printf '  tamaño : %s\n' "$(du -h "$OUT" | cut -f1)"
printf '  sha256 : %s\n' "$( (shasum -a 256 "$OUT" 2>/dev/null || sha256sum "$OUT") | cut -d' ' -f1)"
printf '  ficheros: %s\n' "$(tar -tzf "$OUT" | grep -vc '/$')"
