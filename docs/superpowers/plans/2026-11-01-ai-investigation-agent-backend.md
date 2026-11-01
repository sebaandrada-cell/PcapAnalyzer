# Agente de investigación de capturas — Plan de implementación (parte 1: backend)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Que el backend conserve el pcap cifrado en una sesión temporal y exponga un agente de IA con seis herramientas sobre tshark, accesible por un endpoint de chat en streaming, con topes duros de coste.

**Architecture:** Un `SessionStore` en memoria guarda el pcap cifrado (AES-GCM por trozos, clave solo en RAM) junto al `AnalysisResult` y el historial. Un paquete `app/agent/` contiene las herramientas (funciones Python que invocan tshark con lista de argumentos y devuelven JSON acotado), los prompts, un bucle manual sobre `client.beta.messages.stream` que emite eventos, y un router FastAPI con SSE. La parte 2 (frontend, PDF, release) es otro plan.

**Tech Stack:** Python 3.9+ (compatibilidad con el Mac de desarrollo; el contenedor usa 3.12), FastAPI, `anthropic` 0.116 (`client.beta.messages.stream`, `fallbacks`, `output_config`, `context_management`), `cryptography` (ya presente vía `PyJWT[crypto]`), tshark 4.x (`-Y`, `-T fields`, `-z`), pytest.

**Spec:** `docs/superpowers/specs/2026-11-01-ai-investigation-agent-design.md`

## Global Constraints

- Código y comentarios en inglés; mensajes de error al usuario en español (convención del repo).
- Python 3.9 compatible: `from __future__ import annotations`, `Optional[...]`/`List[...]`, sin `match`, sin `X | Y` en runtime.
- tshark siempre por lista de argumentos con `subprocess`, nunca `shell=True`; siempre con `-n`.
- Umbrales y topes en `app/config.py` vía `_int_env`/`os.environ`, nunca hardcodeados en módulos.
- Nunca loguear contenido de paquetes ni claves de sesión. El pcap descifrado existe solo en un temporal 0600 mientras corre una herramienta.
- Modelo por defecto `claude-opus-5-5`; `thinking` adaptativo; `output_config.effort` desde `AGENT_EFFORT` (`high`); `max_retries=1` en el cliente (ya así en `llm/client.py`).
- Historial de sesión append-only: solo se persisten turnos completos.
- Todo test de herramientas usa el fixture `sample_pcap` de `tests/conftest.py` (`tests/fixtures/sample.pcap`, 56 paquetes) y se salta si no hay tshark, igual que `test_analyze.py`.
- En modo Supabase/cola compartida no se crean sesiones (`session: null`).

## Review Focus

1. **Subida gzip:** `/analyze` con `.pcap.gz` → la sesión guarda el pcap descomprimido y `filter_packets` funciona sobre él. Test en Task 2.
2. **Filtro hostil:** un `display_filter` con `;`, `$(…)`, saltos de línea o 10 000 caracteres nunca llega a una shell; un filtro inválido devuelve `is_error` con el mensaje de tshark, no un 500. Tests en Task 3.
3. **Salida enorme:** `filter_packets` con `_ws.col.info` y `limit=200` sobre una captura grande se corta en `TOOL_MAX_OUTPUT_BYTES` con `truncated: true` y JSON válido. Test en Task 8.
4. **Sesión que caduca a mitad de turno:** el pcap desaparece entre dos herramientas → la herramienta devuelve `is_error`, el turno termina con evento `error`, el historial no cambia. Test en Task 11.
5. **Huérfanos tras reinicio:** archivos `.pcap.enc` de un proceso anterior se borran en el arranque y nunca se pueden leer. Test en Task 1.

---

## Estructura de archivos

| Archivo | Responsabilidad |
|---|---|
| `backend/app/sessions.py` (crear) | `Session`, `SessionStore`, cifrado por trozos, TTL, límites, `session_store`, `session_info()` |
| `backend/app/models.py` (modificar) | `SessionInfo`; `AnalysisResult.session` |
| `backend/app/config.py` (modificar) | variables nuevas; `LLM_MODEL` → `claude-opus-5-5` |
| `backend/app/main.py` (modificar) | `/analyze` crea sesión; `lifespan` purga huérfanos y arranca el hilo de limpieza; incluye `agent.router` |
| `backend/app/jobs.py` (modificar) | `JobStore._run` crea sesión (no borra el pcap hasta haberlo cifrado) |
| `backend/app/agent/__init__.py` (crear) | vacío |
| `backend/app/agent/tshark_run.py` (crear) | `run_tshark`, `validate_filter`, `ToolError`, `ToolTimeout` |
| `backend/app/agent/fields.py` (crear) | lista blanca de campos, `check_fields` |
| `backend/app/agent/stats_parse.py` (crear) | parsers de `tshark -z` y de `follow` |
| `backend/app/agent/stream_metrics.py` (crear) | `compute_stream_metrics` (puro) |
| `backend/app/agent/masking.py` (crear) | `mask_sensitive` |
| `backend/app/agent/reference/*.md` (crear) | notas de protocolo |
| `backend/app/agent/tools.py` (crear) | `ToolContext`, `ToolResult`, las seis herramientas, `TOOL_DEFINITIONS`, `execute_tool` |
| `backend/app/agent/prompts.py` (crear) | `agent_system`, `investigate_request`, `limit_reached_note`, `INVESTIGATE_SENTINEL` |
| `backend/app/agent/runner.py` (crear) | `run_turn`, `TurnEvent`, `TurnResult`, `AgentLimitError` |
| `backend/app/agent/demo.py` (crear) | `demo_investigation`, `DEMO_CHAT_REPLY` |
| `backend/app/agent/router.py` (crear) | `GET/PATCH/DELETE /sessions/{id}`, `POST /sessions/{id}/chat` (SSE) |
| `backend/tests/test_sessions.py`, `test_agent_tools.py`, `test_agent_runner.py`, `test_agent_api.py` (crear) | tests |
| `.env.example`, `docker-compose.yml`, `README.md` (modificar) | documentación de variables |

---

### Task 1: SessionStore con pcap cifrado, TTL, límites y purga de huérfanos

**Files:**
- Create: `backend/app/sessions.py`
- Modify: `backend/app/config.py` (después de `LLM_MAX_CALLS_PER_DAY_GLOBAL`)
- Modify: `backend/app/models.py` (antes de `class AnalysisResult`; campo en `AnalysisResult`)
- Test: `backend/tests/test_sessions.py`

**Interfaces:**
- Consumes: `AnalysisResult` (`app/models.py`), `config._int_env`.
- Produces:
  ```python
  # app/config.py
  SESSIONS_ENABLED: bool            # env SESSIONS_ENABLED, default True ("1","true","yes"); "0" disables
  SESSION_DIR: str                  # env SESSION_DIR, default os.path.join(tempfile.gettempdir(), "pcapanalyzer", "sessions")
  SESSION_TTL_MINUTES: int = 60
  MAX_SESSIONS: int = 20
  MAX_SESSION_BYTES: int = 2 * 1024**3
  SESSION_MAX_TOKENS: int = 2_000_000
  TOOL_TIMEOUT_S: int = 30
  TOOL_MAX_ROWS: int = 200
  TOOL_MAX_OUTPUT_BYTES: int = 65536
  AGENT_MAX_TOOL_CALLS: int = 25
  AGENT_MAX_MODEL_CALLS: int = 20
  AGENT_TASK_BUDGET_TOKENS: int = 60_000
  AGENT_WORKERS: int = 2
  AGENT_EFFORT: str = "high"        # env AGENT_EFFORT; one of low|medium|high|xhigh|max, else ValueError
  AGENT_COMPACT_TOKENS: int = 150_000
  LLM_MODEL default -> "claude-opus-5-5"

  # app/models.py
  class SessionInfo(BaseModel):
      id: str
      expires_at: float            # epoch seconds
      ttl_minutes: int
      content_allowed: bool
  class AnalysisResult(...):
      session: Optional[SessionInfo] = None

  # app/sessions.py
  @dataclass
  class SessionUsage:
      input_tokens: int = 0; output_tokens: int = 0
      cache_read_tokens: int = 0; cache_write_tokens: int = 0; questions: int = 0
  @dataclass
  class Session:
      id: str; principal_id: str; filename: str; pcap_bytes: int
      created_at: float; last_used_at: float
      analysis: AnalysisResult
      content_allowed: bool = False
      messages: List[dict] = field(default_factory=list)
      usage: SessionUsage = field(default_factory=SessionUsage)
      lock: threading.Lock = field(default_factory=threading.Lock)
      def expires_at(self) -> float   # last_used_at + config.SESSION_TTL_MINUTES*60
  class SessionStore:
      def __init__(self, directory: Optional[str] = None) -> None
      def create(self, principal_id: str, pcap_path: str, filename: str, analysis: AnalysisResult) -> Session
      def get(self, session_id: str, principal_id: str) -> Optional[Session]      # renews last_used_at; None if missing/expired/foreign
      def peek(self, session_id: str, principal_id: str) -> Optional[Session]     # no renewal
      def delete(self, session_id: str, principal_id: str) -> bool
      def decrypted_pcap(self, session: Session) -> ContextManager[str]            # yields temp path (0600); deletes on exit
      def cleanup(self) -> int                                                     # expired + limits; returns count removed
      def purge_orphans(self) -> int                                               # deletes every *.pcap.enc in directory not tracked
      def total_bytes(self) -> int
      def count(self) -> int
  session_store = SessionStore()
  def session_info(session: Session) -> SessionInfo
  ```

- [ ] **Step 1: Añadir la configuración y el modelo**

En `app/config.py`, tras las variables `LLM_MAX_CALLS_PER_DAY*`, añade las variables de la lista anterior con esos valores por defecto y un comentario de bloque "Investigation sessions and the AI agent (see docs/superpowers/specs/2026-11-01-...)". Cambia el valor por defecto de `LLM_MODEL` a `claude-opus-5-5`. `AGENT_EFFORT` valida contra `{"low","medium","high","xhigh","max"}` y lanza `ValueError` como hace `AUTH_MODE`.

En `app/models.py`, añade `SessionInfo` y `session: Optional[SessionInfo] = None` al final de `AnalysisResult` (último campo, para no alterar el orden de los existentes).

- [ ] **Step 2: Escribir los tests que fallan**

```python
# backend/tests/test_sessions.py
from __future__ import annotations
import os, threading, time
import pytest
from app import config
from app.sessions import SessionStore, session_info
from tests.test_llm import make_analysis   # fixture-free AnalysisResult builder already in the repo

@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "SESSION_TTL_MINUTES", 60)
    monkeypatch.setattr(config, "MAX_SESSIONS", 20)
    monkeypatch.setattr(config, "MAX_SESSION_BYTES", 2 * 1024**3)
    return SessionStore(directory=str(tmp_path / "sessions"))

def _pcap(tmp_path, data=b"\xd4\xc3\xb2\xa1" + b"x" * 5000, name="a.pcap"):
    p = tmp_path / name; p.write_bytes(data); return str(p)

def test_create_encrypts_and_roundtrips(store, tmp_path):
    src = _pcap(tmp_path)
    s = store.create("tok", src, "a.pcap", make_analysis())
    assert s.pcap_bytes == 5004 and os.path.exists(src)           # source is left to the caller
    enc = [f for f in os.listdir(store.directory) if f.endswith(".pcap.enc")]
    assert len(enc) == 1 and b"xxxx" not in open(os.path.join(store.directory, enc[0]), "rb").read()
    with store.decrypted_pcap(s) as path:
        assert open(path, "rb").read() == open(src, "rb").read()
        assert oct(os.stat(path).st_mode & 0o777) == "0o600"
    assert not os.path.exists(path)                                 # temp removed on exit

def test_gzip_source_is_stored_decompressed(store, tmp_path):
    import gzip
    raw = b"\xd4\xc3\xb2\xa1" + b"y" * 3000
    p = tmp_path / "a.pcap.gz"; p.write_bytes(gzip.compress(raw))
    s = store.create("tok", str(p), "a.pcap.gz", make_analysis())
    assert s.pcap_bytes == len(raw)
    with store.decrypted_pcap(s) as path:
        assert open(path, "rb").read() == raw

def test_get_is_owner_scoped_and_renews(store, tmp_path):
    s = store.create("tok", _pcap(tmp_path), "a.pcap", make_analysis())
    assert store.get(s.id, "other") is None
    before = s.last_used_at; time.sleep(0.01)
    assert store.get(s.id, "tok") is s and s.last_used_at > before
    assert store.peek(s.id, "tok").last_used_at == s.last_used_at

def test_expiry_and_cleanup(store, tmp_path, monkeypatch):
    s = store.create("tok", _pcap(tmp_path), "a.pcap", make_analysis())
    monkeypatch.setattr(config, "SESSION_TTL_MINUTES", 0)
    assert store.get(s.id, "tok") is None
    assert store.cleanup() == 1 and store.count() == 0
    assert not any(f.endswith(".pcap.enc") for f in os.listdir(store.directory))

def test_limits_evict_oldest(store, tmp_path, monkeypatch):
    monkeypatch.setattr(config, "MAX_SESSIONS", 2)
    a = store.create("tok", _pcap(tmp_path, name="1.pcap"), "1", make_analysis())
    b = store.create("tok", _pcap(tmp_path, name="2.pcap"), "2", make_analysis())
    c = store.create("tok", _pcap(tmp_path, name="3.pcap"), "3", make_analysis())
    assert store.peek(a.id, "tok") is None and store.peek(b.id, "tok") and store.peek(c.id, "tok")
    monkeypatch.setattr(config, "MAX_SESSION_BYTES", 6000)   # each pcap is 5004 bytes
    d = store.create("tok", _pcap(tmp_path, name="4.pcap"), "4", make_analysis())
    assert store.count() == 1 and store.peek(d.id, "tok")

def test_delete_removes_file(store, tmp_path):
    s = store.create("tok", _pcap(tmp_path), "a.pcap", make_analysis())
    assert store.delete(s.id, "other") is False
    assert store.delete(s.id, "tok") is True and store.count() == 0
    assert not any(f.endswith(".pcap.enc") for f in os.listdir(store.directory))

def test_purge_orphans_on_startup(tmp_path):
    d = tmp_path / "sessions"; d.mkdir()
    (d / "stale.pcap.enc").write_bytes(b"garbage")
    store = SessionStore(directory=str(d))
    assert store.purge_orphans() == 1 and not os.listdir(d)

def test_session_info_shape(store, tmp_path):
    s = store.create("tok", _pcap(tmp_path), "a.pcap", make_analysis())
    info = session_info(s)
    assert info.id == s.id and info.ttl_minutes == 60 and info.content_allowed is False
    assert abs(info.expires_at - (s.last_used_at + 3600)) < 1
```

- [ ] **Step 3: Ejecutar y ver que fallan**

Run: `cd backend && .venv/bin/python -m pytest -q tests/test_sessions.py`
Expected: FAIL, `ModuleNotFoundError: app.sessions`.

- [ ] **Step 4: Implementar `app/sessions.py`**

Cifrado: AES-256-GCM por trozos de 4 MiB con `cryptography.hazmat.primitives.ciphers.aead.AESGCM`. Formato del archivo: cabecera `b"PCAS1"`, luego por trozo `len(4 bytes big-endian) || nonce(12) || ciphertext`; nonce = 4 bytes aleatorios fijos por archivo + contador de trozo de 8 bytes. Clave `os.urandom(32)` guardada solo en el objeto `Session` (atributo privado `_key`, no en `__repr__`). Al crear, si los 2 primeros bytes del origen son `1f 8b` se lee con `gzip.open`; `pcap_bytes` es el tamaño descomprimido. `create()` llama a `cleanup()` primero y vuelve a comprobar límites tras añadir (expulsando la sesión con `last_used_at` menor hasta cumplir `MAX_SESSIONS` y `MAX_SESSION_BYTES`; la recién creada nunca se expulsa). `decrypted_pcap` escribe con `tempfile.NamedTemporaryFile(dir=directory, suffix=".pcap", delete=False)` + `os.chmod(0o600)` y borra en `finally`. `purge_orphans()` borra todo `*.pcap.enc` del directorio al construir el store si no está registrado. `directory` se crea con `os.makedirs(exist_ok=True, mode=0o700)`. Todo bajo un `threading.Lock` del store.

- [ ] **Step 5: Ejecutar y ver que pasan**

Run: `cd backend && .venv/bin/python -m pytest -q tests/test_sessions.py tests/test_llm.py`
Expected: todos PASS (test_llm sigue pasando con el modelo nuevo por defecto porque usa cliente simulado).

- [ ] **Step 6: Commit**

```bash
git add backend/app/sessions.py backend/app/config.py backend/app/models.py backend/tests/test_sessions.py
git commit -m "feat(sessions): encrypted temporary capture sessions with TTL and limits"
```

---

### Task 2: Crear la sesión en `/analyze` y en la cola local; endpoints GET/PATCH/DELETE

**Files:**
- Create: `backend/app/agent/__init__.py`, `backend/app/agent/router.py`
- Modify: `backend/app/main.py` (`/analyze`, `lifespan`, `include_router`), `backend/app/jobs.py:107-131`
- Test: `backend/tests/test_agent_api.py`

**Interfaces:**
- Consumes: `session_store`, `session_info` (Task 1); `Principal`, `require_api_token_no_rate_limit` (`app/auth.py`).
- Produces:
  ```python
  # app/agent/router.py
  router = APIRouter()
  class SessionPatch(BaseModel): content_allowed: bool
  class SessionStatus(BaseModel): id: str; expires_at: float; ttl_minutes: int; content_allowed: bool; usage: Dict[str, int]; messages: int
  GET    /sessions/{session_id} -> SessionStatus        (404 "Sesión no encontrada o caducada.")
  PATCH  /sessions/{session_id} -> SessionStatus
  DELETE /sessions/{session_id} -> 204
  # app/main.py
  def _attach_session(result: AnalysisResult, principal: Principal, pcap_path: str, filename: str) -> None
      # no-op when not config.SESSIONS_ENABLED or principal.auth_mode == "supabase"
  ```

- [ ] **Step 1: Tests que fallan**

```python
# backend/tests/test_agent_api.py
from __future__ import annotations
import gzip, shutil
import pytest
from app import config
from app.tshark import find_tshark

pytestmark = pytest.mark.skipif(find_tshark() is None, reason="tshark not installed")

def _analyze(client, sample_pcap, name="sample.pcap", data=None):
    data = data if data is not None else sample_pcap.read_bytes()
    return client.post("/analyze", files={"file": (name, data, "application/octet-stream")})

def test_analyze_returns_session(client, sample_pcap):
    r = _analyze(client, sample_pcap); assert r.status_code == 200
    s = r.json()["session"]
    assert s and s["ttl_minutes"] == 60 and s["content_allowed"] is False
    status = client.get("/sessions/%s" % s["id"]).json()
    assert status["messages"] == 0 and status["usage"]["questions"] == 0

def test_gzip_upload_gets_session_with_decompressed_pcap(client, sample_pcap):
    from app.sessions import session_store
    r = _analyze(client, sample_pcap, "sample.pcap.gz", gzip.compress(sample_pcap.read_bytes()))
    sid = r.json()["session"]["id"]
    session = session_store.peek(sid, "test-token")
    assert session.pcap_bytes == sample_pcap.stat().st_size

def test_session_patch_and_delete(client, sample_pcap):
    sid = _analyze(client, sample_pcap).json()["session"]["id"]
    assert client.patch("/sessions/%s" % sid, json={"content_allowed": True}).json()["content_allowed"] is True
    assert client.delete("/sessions/%s" % sid).status_code == 204
    assert client.get("/sessions/%s" % sid).status_code == 404

def test_foreign_token_gets_404(client, sample_pcap, monkeypatch):
    sid = _analyze(client, sample_pcap).json()["session"]["id"]
    monkeypatch.setattr(config, "API_TOKENS", ["test-token", "other"])
    r = client.get("/sessions/%s" % sid, headers={"Authorization": "Bearer other"})
    assert r.status_code == 404

def test_sessions_disabled_returns_null(client, sample_pcap, monkeypatch):
    monkeypatch.setattr(config, "SESSIONS_ENABLED", False)
    assert _analyze(client, sample_pcap).json()["session"] is None

def test_async_job_creates_session(client, sample_pcap):
    import time
    r = client.post("/analyze/async", files={"file": ("s.pcap", sample_pcap.read_bytes(), "application/octet-stream")})
    job_id = r.json()["job_id"]
    for _ in range(100):
        job = client.get("/jobs/%s" % job_id).json()
        if job["status"] in ("done", "error"): break
        time.sleep(0.1)
    assert job["status"] == "done" and job["result"]["session"]["id"]
```

- [ ] **Step 2: Ejecutar y ver que fallan**

Run: `cd backend && PATH="$PATH:/Applications/Wireshark.app/Contents/MacOS" .venv/bin/python -m pytest -q tests/test_agent_api.py`
Expected: FAIL (`session` ausente / 404 en `/sessions`).

- [ ] **Step 3: Implementar**

`app/main.py`: `_attach_session` crea la sesión con `session_store.create(principal.tenant_id, pcap_path, filename, result)` y asigna `result.session = session_info(session)`; captura `OSError` y lo registra como warning dejando `session=None` (la respuesta del análisis nunca falla por la sesión). Llamar antes del `finally` que borra `tmp_path` en `/analyze`. En `lifespan`, al arrancar: `session_store.purge_orphans()` y un `threading.Thread(daemon=True)` que llama a `session_store.cleanup()` cada 60 s. `app.include_router(agent_router)` junto al `ai_router`.

`app/jobs.py`: `JobStore.submit` recibe además `principal_id: str` (ya tiene `owner_id`; úsalo) y `_run` crea la sesión tras `analyze_pcap` y antes de `os.unlink(pcap_path)`, misma política de errores. `/analyze/async` en `main.py` ya pasa `owner_id`; no cambia su firma pública.

`app/agent/router.py`: los tres endpoints con `Depends(require_api_token_no_rate_limit)`; `GET` usa `peek` (consultar el estado no renueva el TTL), `PATCH` usa `get`. `SessionStatus.usage` = `dataclasses.asdict(session.usage)`; `messages` = número de mensajes con `role == "user"` del historial.

- [ ] **Step 4: Ejecutar toda la suite**

Run: `cd backend && PATH="$PATH:/Applications/Wireshark.app/Contents/MacOS" .venv/bin/python -m pytest -q`
Expected: PASS (136 existentes + nuevos). Si `test_analyze.py` compara la respuesta completa, actualizarlo para ignorar `session`.

- [ ] **Step 5: Commit**

```bash
git add backend/app/agent/__init__.py backend/app/agent/router.py backend/app/main.py backend/app/jobs.py backend/tests
git commit -m "feat(sessions): attach investigation sessions to analyses and expose session endpoints"
```

---

### Task 3: Ejecución segura de tshark, validación de filtros y lista blanca de campos

**Files:**
- Create: `backend/app/agent/tshark_run.py`, `backend/app/agent/fields.py`
- Test: `backend/tests/test_agent_tools.py` (primera parte)

**Interfaces:**
- Consumes: `find_tshark` (`app/tshark.py`), `config.TOOL_TIMEOUT_S`, `config.TOOL_MAX_OUTPUT_BYTES`.
- Produces:
  ```python
  # app/agent/tshark_run.py
  class ToolError(Exception): ...
  class ToolTimeout(ToolError): ...
  def run_tshark(args: List[str], timeout_s: Optional[int] = None, max_bytes: Optional[int] = None) -> str
      # runs [find_tshark(), "-n", *args]; returns stdout text (utf-8, errors="replace");
      # raises ToolTimeout on timeout (kills process), ToolError(stderr tail) on non-zero exit,
      # truncates stdout at max_bytes (default TOOL_MAX_OUTPUT_BYTES*4) and appends nothing (caller handles)
  def validate_filter(pcap_path: str, display_filter: str) -> None
      # raises ToolError("Filtro no válido: <tshark message>") when tshark rejects it; len > 2000 -> ToolError
  # app/agent/fields.py
  ALLOWED_PREFIXES: Tuple[str, ...]   # "frame.", "eth.", "ip.", "ipv6.", "tcp.", "udp.", "icmp.", "icmpv6.", "arp.", "dns.", "http.request.", "http.response.", "http.host", "http.user_agent", "http.content_type", "http.content_length", "tls.handshake.", "tls.record.", "tls.alert_message", "dhcp.", "_ws.col.", "_ws.expert"
  CONTENT_FIELDS: Tuple[str, ...]     # "data", "data.data", "tcp.payload", "udp.payload", "http.file_data", "http.request.line", "http.response.line", "http.cookie", "http.authorization", "dns.txt", "smb", "smb2", "sip.msg_body", "ftp.request.arg", "imf.", "mime_multipart."
  def check_fields(fields: List[str], content_allowed: bool) -> List[str]
      # returns the rejected names: not matching ALLOWED_PREFIXES, or in CONTENT_FIELDS (prefix match) when not content_allowed; also rejects anything with chars outside [A-Za-z0-9_.]
  ```

- [ ] **Step 1: Tests que fallan**

```python
# backend/tests/test_agent_tools.py (inicio del archivo)
from __future__ import annotations
import pytest
from app import config
from app.agent.fields import check_fields
from app.agent.tshark_run import ToolError, ToolTimeout, run_tshark, validate_filter
from app.tshark import find_tshark

needs_tshark = pytest.mark.skipif(find_tshark() is None, reason="tshark not installed")

def test_check_fields_allowlist():
    assert check_fields(["frame.number", "tcp.flags.syn", "_ws.col.info"], False) == []
    assert check_fields(["tcp.payload", "data.data", "http.file_data"], False) == ["tcp.payload", "data.data", "http.file_data"]
    assert check_fields(["tcp.payload"], True) == []
    assert check_fields(["frame.number; rm -rf /", "ssh.banner"], False) == ["frame.number; rm -rf /", "ssh.banner"]

@needs_tshark
def test_run_tshark_rejects_shell_metacharacters_as_plain_args(sample_pcap):
    out = run_tshark(["-r", str(sample_pcap), "-Y", 'frame.number == 1 && _ws.col.info contains "$(touch /tmp/x)"', "-T", "fields", "-e", "frame.number"])
    assert out.strip() == ""            # no match, no crash, nothing executed

@needs_tshark
def test_validate_filter_errors(sample_pcap):
    validate_filter(str(sample_pcap), "tcp.flags.reset == 1")
    with pytest.raises(ToolError) as exc: validate_filter(str(sample_pcap), "tcp.flags.reset ==== 1")
    assert "Filtro no válido" in str(exc.value)
    with pytest.raises(ToolError): validate_filter(str(sample_pcap), "a" * 2001)
    with pytest.raises(ToolError): validate_filter(str(sample_pcap), "frame.number == 1\n&& tcp")

@needs_tshark
def test_run_tshark_timeout(sample_pcap, monkeypatch):
    monkeypatch.setattr("app.agent.tshark_run.find_tshark", lambda: "/bin/sleep")
    with pytest.raises(ToolTimeout): run_tshark(["5"], timeout_s=1)
```

- [ ] **Step 2: Ejecutar y ver que fallan**

Run: `cd backend && PATH="$PATH:/Applications/Wireshark.app/Contents/MacOS" .venv/bin/python -m pytest -q tests/test_agent_tools.py`
Expected: FAIL con `ModuleNotFoundError`.

- [ ] **Step 3: Implementar**

`run_tshark` usa `subprocess.run(cmd, capture_output=True, timeout=timeout_s)`; en `TimeoutExpired` lanza `ToolTimeout("tshark excedió %ds" % timeout_s)` (subprocess.run ya mata el proceso). `validate_filter` rechaza `\n`/`\r`/`\x00` y longitud > 2000 antes de llamar, y luego ejecuta `run_tshark(["-r", pcap_path, "-Y", display_filter, "-c", "1", "-T", "fields", "-e", "frame.number"])`; un `ToolError` de tshark se reenvuelve como `ToolError("Filtro no válido: " + última línea de stderr)`.

- [ ] **Step 4: Ejecutar y ver que pasan**

Run: igual que el paso 2. Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/app/agent/tshark_run.py backend/app/agent/fields.py backend/tests/test_agent_tools.py
git commit -m "feat(agent): safe tshark runner, filter validation and field allowlist"
```

---

### Task 4: Herramientas `capture_overview` y `filter_packets`

**Files:**
- Create: `backend/app/agent/tools.py`
- Test: `backend/tests/test_agent_tools.py` (añadir)

**Interfaces:**
- Consumes: Task 3; `Session` (Task 1); `AnalysisResult`.
- Produces:
  ```python
  # app/agent/tools.py
  @dataclass
  class ToolContext:
      session: Session
      pcap_path: str          # decrypted temp path, valid for the duration of one tool call
      tshark_path: str
  @dataclass
  class ToolResult:
      content: Any            # JSON-serializable
      is_error: bool = False
      truncated: bool = False
  def capture_overview(ctx: ToolContext) -> ToolResult
      # dict with keys: file, summary, protocols, tcp_conversations (<= TOOL_MAX_ROWS, sorted by bytes desc, with all TcpConversation fields),
      # udp_conversations (<= TOOL_MAX_ROWS), top_talkers, tunnels, issues (id, type, severity, title, detail, conversation, evidence),
      # expert_info, dns_queries (<= TOOL_MAX_ROWS), tls_sessions, http_requests (<= TOOL_MAX_ROWS), dhcp_leases, service_response_times,
      # resolved_names, truncated_sections (list of keys that hit TOOL_MAX_ROWS)
  def filter_packets(ctx: ToolContext, display_filter: str, fields: List[str], limit: int = 50, offset: int = 0) -> ToolResult
      # content: {"filter": str, "fields": [...], "rows": [{"frame": int, <field>: str|list[str]}...], "offset": int, "returned": int, "has_more": bool}
      # limit clamped to [1, TOOL_MAX_ROWS]; rejected fields -> ToolResult(is_error=True, content={"error": "fields_not_allowed", "fields": [...]})
      # invalid filter -> ToolResult(is_error=True, content={"error": "invalid_filter", "message": str})
  ```

- [ ] **Step 1: Tests que fallan**

```python
# añadir a tests/test_agent_tools.py
from app.agent.tools import ToolContext, capture_overview, filter_packets
from app.sessions import SessionStore
from app.analysis import analyze_pcap

@pytest.fixture
def ctx(sample_pcap, tmp_path):
    tshark = find_tshark()
    analysis = analyze_pcap(tshark_path=tshark, pcap_path=str(sample_pcap), original_filename="sample.pcap", size_bytes=sample_pcap.stat().st_size)
    store = SessionStore(directory=str(tmp_path / "s"))
    session = store.create("tok", str(sample_pcap), "sample.pcap", analysis)
    with store.decrypted_pcap(session) as path:
        yield ToolContext(session=session, pcap_path=path, tshark_path=tshark)

@needs_tshark
def test_capture_overview_is_complete(ctx):
    r = capture_overview(ctx)
    assert not r.is_error and r.content["summary"]["packets"] == 56
    assert len(r.content["issues"]) == 18 and len(r.content["tcp_conversations"]) == len(ctx.session.analysis.conversations.tcp)
    assert {"stream_id", "dup_acks", "rtt_avg_ms"} <= set(r.content["tcp_conversations"][0])

@needs_tshark
def test_filter_packets_rows_and_paging(ctx):
    r = filter_packets(ctx, "tcp.flags.syn == 1 && tcp.flags.ack == 0", ["frame.number", "ip.dst", "tcp.dstport"], limit=2)
    assert not r.is_error and r.content["returned"] == 2 and r.content["has_more"] is True
    assert r.content["rows"][0]["frame"] == 1 and r.content["rows"][0]["tcp.dstport"] == "80"
    r2 = filter_packets(ctx, "tcp.flags.syn == 1 && tcp.flags.ack == 0", ["frame.number"], limit=2, offset=2)
    assert r2.content["rows"][0]["frame"] > 1 and r2.content["offset"] == 2

@needs_tshark
def test_filter_packets_rejects_content_fields_unless_allowed(ctx):
    r = filter_packets(ctx, "tcp", ["tcp.payload"])
    assert r.is_error and r.content["error"] == "fields_not_allowed"
    ctx.session.content_allowed = True
    assert not filter_packets(ctx, "tcp", ["tcp.payload"]).is_error

@needs_tshark
def test_filter_packets_invalid_filter(ctx):
    r = filter_packets(ctx, "tcp.port ==== 80", ["frame.number"])
    assert r.is_error and r.content["error"] == "invalid_filter"
```

- [ ] **Step 2: Ejecutar y ver que fallan** — Run como en Task 3. Expected: FAIL (`ImportError`).

- [ ] **Step 3: Implementar**

`filter_packets`: tras `check_fields` y `validate_filter`, ejecuta `run_tshark(["-r", pcap, "-Y", filter, "-T", "fields", "-E", "separator=\t", "-E", "occurrence=a", "-E", "aggregator=|", "-e", "frame.number", *(["-e", f] for f in fields if f != "frame.number"), "-c", str(offset + limit + 1)])` y descarta las primeras `offset` líneas; `has_more` = había `offset+limit+1` líneas. Valores con `|` se devuelven como lista. `frame.number` siempre presente como `frame` entero. `capture_overview` serializa con `model_dump()` y recorta listas a `TOOL_MAX_ROWS` registrando la clave en `truncated_sections`.

- [ ] **Step 4: Ejecutar y ver que pasan.** Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/app/agent/tools.py backend/tests/test_agent_tools.py
git commit -m "feat(agent): capture_overview and filter_packets tools"
```

---

### Task 5: Herramienta `statistics` con parsers de `tshark -z`

**Files:**
- Create: `backend/app/agent/stats_parse.py`
- Modify: `backend/app/agent/tools.py`
- Test: `backend/tests/test_agent_tools.py` (añadir)

**Interfaces:**
- Produces:
  ```python
  # app/agent/stats_parse.py  (pure text parsers; each returns a list of dicts)
  def parse_conversations(text: str) -> List[dict]   # {"a": "10.0.0.1:34567", "b": "10.0.0.2:80", "frames_b_to_a", "bytes_b_to_a", "frames_a_to_b", "bytes_a_to_b", "frames", "bytes", "rel_start", "duration"}
  def parse_endpoints(text: str) -> List[dict]       # {"address", "packets", "bytes", "tx_packets", "tx_bytes", "rx_packets", "rx_bytes"}
  def parse_io_stat(text: str) -> List[dict]         # {"interval_start": float, "frames": int, "bytes": int}
  def parse_protocol_hierarchy(text: str) -> List[dict]  # {"protocol": "eth:ethertype:ip:tcp", "frames": int, "bytes": int}
  def parse_expert(text: str) -> List[dict]          # {"severity": "warning"|"note"|"chat"|"error", "frequency": int, "group": str, "protocol": str, "summary": str}
  def parse_dns_tree(text: str) -> dict              # {"queries": int, "responses": int, "rcodes": {...}, "qtypes": {...}} best effort
  def parse_srt(text: str) -> List[dict]             # {"procedure": str, "calls": int, "min_srt": float, "max_srt": float, "avg_srt": float}
  # app/agent/tools.py
  STAT_KINDS = ("conversations_tcp", "conversations_udp", "conversations_ip", "endpoints_ip", "io_per_interval", "protocol_hierarchy", "expert", "dns", "service_response_time")
  def statistics(ctx: ToolContext, kind: str, display_filter: Optional[str] = None, interval_s: int = 1, protocol: Optional[str] = None) -> ToolResult
      # content: {"kind": kind, "rows": [...], "returned": int, "truncated": bool}; unknown kind -> is_error {"error": "unknown_kind", "kinds": STAT_KINDS}
      # interval_s clamped to [1, 3600]; service_response_time requires protocol in ("dns", "http", "smb", "ldap", "rpc") -> tshark -z <proto>,srt
  ```

- [ ] **Step 1: Tests que fallan**

```python
from app.agent.stats_parse import parse_conversations, parse_expert, parse_io_stat
from app.agent.tools import statistics

def test_parse_conversations_from_tshark_text():
    text = """================================================================================
TCP Conversations
Filter:<No Filter>
                                                           |       <-      | |       ->      | |     Total     |    Relative    |   Duration   |
                                                           | Frames  Bytes | | Frames  Bytes | | Frames  Bytes |      Start     |              |
10.0.0.1:34567             <-> 10.0.0.2:80                      4 282 bytes       5 561 bytes       9 843 bytes     0.000000000         0.5500
================================================================================
"""
    rows = parse_conversations(text)
    assert rows == [{"a": "10.0.0.1:34567", "b": "10.0.0.2:80", "frames_b_to_a": 4, "bytes_b_to_a": 282,
                     "frames_a_to_b": 5, "bytes_a_to_b": 561, "frames": 9, "bytes": 843, "rel_start": 0.0, "duration": 0.55}]

def test_parse_expert_groups_by_severity():
    text = "\nWarns (3)\n=============\n   Frequency      Group           Protocol  Summary\n           1   Sequence                TCP  TCP Zero Window segment\n           1   Sequence                TCP  Connection reset (RST)\n\nNotes (1)\n=============\n   Frequency      Group           Protocol  Summary\n           5   Sequence                TCP  This frame is a (suspected) retransmission\n"
    rows = parse_expert(text)
    assert rows[0] == {"severity": "warning", "frequency": 1, "group": "Sequence", "protocol": "TCP", "summary": "TCP Zero Window segment"}
    assert rows[-1]["severity"] == "note" and rows[-1]["frequency"] == 5

@needs_tshark
def test_statistics_kinds_on_sample(ctx):
    conv = statistics(ctx, "conversations_tcp")
    assert not conv.is_error and any(r["b"] == "10.0.0.2:80" or r["a"] == "10.0.0.2:80" for r in conv.content["rows"])
    io = statistics(ctx, "io_per_interval", interval_s=2)
    assert len(io.content["rows"]) >= 7 and sum(r["frames"] for r in io.content["rows"]) == 56
    assert statistics(ctx, "expert").content["rows"]
    assert statistics(ctx, "protocol_hierarchy").content["rows"]
    assert statistics(ctx, "service_response_time", protocol="dns").content["kind"] == "service_response_time"
    assert statistics(ctx, "nope").is_error
    filtered = statistics(ctx, "conversations_tcp", display_filter="tcp.port == 80")
    assert len(filtered.content["rows"]) == 1
```

- [ ] **Step 2: Ejecutar y ver que fallan.**

- [ ] **Step 3: Implementar**

Mapa `kind → args`: `conversations_tcp → ["-z", "conv,tcp"]`, `conversations_udp → conv,udp`, `conversations_ip → conv,ip`, `endpoints_ip → endpoints,ip`, `io_per_interval → "io,stat,<interval_s>"`, `protocol_hierarchy → io,phs`, `expert → expert`, `dns → dns,tree`, `service_response_time → "<proto>,srt"`. Con `display_filter` validado, añadir `,<filter>` al argumento `-z` (tshark acepta `conv,tcp,<filter>`; para `io,stat` es `io,stat,<interval>,<filter>`). Siempre `-q`. Parsers con expresiones regulares sobre líneas; ignorar cabeceras y separadores; recortar a `TOOL_MAX_ROWS`.

- [ ] **Step 4: Ejecutar y ver que pasan.**

- [ ] **Step 5: Commit** — `git commit -m "feat(agent): statistics tool over tshark -z"`

---

### Task 6: Herramienta `stream_detail` con métricas por flujo

**Files:**
- Create: `backend/app/agent/stream_metrics.py`
- Modify: `backend/app/agent/tools.py`
- Test: `backend/tests/test_agent_tools.py` (añadir)

**Interfaces:**
- Produces:
  ```python
  # app/agent/stream_metrics.py
  @dataclass
  class StreamPacket:
      frame: int; time: float; src: str; sport: int; dst: str; dport: int
      flags: List[str]; seq: Optional[int]; ack: Optional[int]; length: int   # tcp.len / udp.length
      window: Optional[int]; analysis: List[str]; ack_rtt: Optional[float]; delta: float
  def compute_stream_metrics(packets: List[StreamPacket]) -> dict
      # {"endpoints": {"a": "ip:port", "b": "ip:port"} (a = first packet's source),
      #  "packets": int, "bytes_a_to_b": int, "bytes_b_to_a": int, "duration_s": float,
      #  "handshake_rtt_ms": Optional[float],
      #  "ack_rtt_ms": {"a_to_b": {"avg","p95","max","samples"}, "b_to_a": {...}},
      #  "throughput_bps": {"a_to_b": float, "b_to_a": float},
      #  "largest_gap": {"after_frame": int, "before_frame": int, "seconds": float, "last_sender": "a"|"b"} | None,
      #  "events": {"retransmission": [frames], "dup_ack": [...], "zero_window": [...], "window_full": [...], "out_of_order": [...], "lost_segment": [...]},
      #  "close": {"type": "fin"|"rst"|"none", "initiator": "a"|"b"|None, "frame": Optional[int], "seconds_after_last_data": Optional[float]}}
  def select_rows(packets: List[StreamPacket], max_rows: int) -> Tuple[List[StreamPacket], bool]
      # keeps all when len <= max_rows; otherwise the first 5, the last 5, and windows of ±3 around every event/gap frame, deduplicated, ordered; returns (rows, truncated)
  # app/agent/tools.py
  def stream_detail(ctx: ToolContext, stream_id: int, protocol: str = "tcp") -> ToolResult
      # content: {"stream_id", "protocol", "metrics": compute_stream_metrics(...), "rows": [StreamPacket as dict with "direction": "a_to_b"|"b_to_a"], "rows_truncated": bool}
      # unknown stream -> is_error {"error": "stream_not_found"}; protocol not in ("tcp","udp") -> is_error
  ```

- [ ] **Step 1: Tests que fallan**

```python
from app.agent.stream_metrics import StreamPacket, compute_stream_metrics, select_rows
from app.agent.tools import stream_detail

def _pk(frame, t, a_to_b=True, flags=(), seq=None, ack=None, length=0, analysis=(), rtt=None):
    src, sport, dst, dport = ("10.0.0.1", 1000, "10.0.0.2", 80) if a_to_b else ("10.0.0.2", 80, "10.0.0.1", 1000)
    return StreamPacket(frame, t, src, sport, dst, dport, list(flags), seq, ack, length, 65535, list(analysis), rtt, 0.0)

def test_compute_stream_metrics_synthetic():
    pk = [_pk(1, 0.0, True, ["SYN"]), _pk(2, 0.05, False, ["SYN", "ACK"], rtt=0.05), _pk(3, 0.06, True, ["ACK"], rtt=0.01),
          _pk(4, 0.1, True, ["PSH", "ACK"], length=100), _pk(5, 0.3, False, ["ACK"], rtt=0.2),
          _pk(6, 2.3, True, ["PSH", "ACK"], length=100, analysis=["retransmission"]), _pk(7, 2.4, False, ["RST", "ACK"])]
    m = compute_stream_metrics(pk)
    assert m["handshake_rtt_ms"] == 50.0 and m["bytes_a_to_b"] == 200 and m["packets"] == 7
    assert m["largest_gap"] == {"after_frame": 5, "before_frame": 6, "seconds": 2.0, "last_sender": "b"}
    assert m["events"]["retransmission"] == [6]
    assert m["close"] == {"type": "rst", "initiator": "b", "frame": 7, "seconds_after_last_data": pytest.approx(0.1)}
    assert m["ack_rtt_ms"]["b_to_a"]["max"] == 200.0

def test_select_rows_keeps_events():
    pk = [_pk(i, i * 0.01) for i in range(1, 501)]
    pk[249].analysis = ["retransmission"]
    rows, truncated = select_rows(pk, 50)
    assert truncated and [r.frame for r in rows[:5]] == [1, 2, 3, 4, 5] and 250 in [r.frame for r in rows] and rows[-1].frame == 500

@needs_tshark
def test_stream_detail_on_sample(ctx):
    r = stream_detail(ctx, 0)
    assert not r.is_error and r.content["metrics"]["endpoints"] == {"a": "10.0.0.1:34567", "b": "10.0.0.2:80"}
    assert r.content["metrics"]["events"]["retransmission"] == [5, 6] and 7 in r.content["metrics"]["events"]["zero_window"]
    r1 = stream_detail(ctx, 1)
    assert r1.content["metrics"]["close"]["type"] == "rst" and r1.content["metrics"]["handshake_rtt_ms"] is None
    assert stream_detail(ctx, 999).is_error and stream_detail(ctx, 0, protocol="sctp").is_error
```

- [ ] **Step 2: Ejecutar y ver que fallan.**

- [ ] **Step 3: Implementar**

`stream_detail` ejecuta `run_tshark(["-r", pcap, "-Y", "tcp.stream eq N" | "udp.stream eq N", "-T", "fields", "-E", "separator=\t", "-E", "occurrence=f", "-e", ...])` con los campos: `frame.number frame.time_relative frame.time_delta_displayed ip.src ipv6.src tcp.srcport udp.srcport ip.dst ipv6.dst tcp.dstport udp.dstport tcp.flags.str tcp.seq tcp.ack tcp.len udp.length tcp.window_size tcp.analysis.ack_rtt` más una `-e` por cada bandera de `_ANALYSIS_FLAGS` del engine (`tcp.analysis.retransmission`, …: presentes → `"1"`). Convierte a `StreamPacket` (flags desde `tcp.flags.str` tipo `·······A···S·` → nombres `SYN, ACK, FIN, RST, PSH, URG`). p95 = percentil con `sorted(values)[int(round(0.95*(n-1)))]`. `largest_gap.last_sender` = sentido del paquete anterior al hueco. `close.seconds_after_last_data` = tiempo desde el último paquete con `length > 0`.

- [ ] **Step 4: Ejecutar y ver que pasan.**

- [ ] **Step 5: Commit** — `git commit -m "feat(agent): stream_detail tool with per-stream metrics"`

---

### Task 7: `follow_stream` con enmascarado y `protocol_reference`

**Files:**
- Create: `backend/app/agent/masking.py`, `backend/app/agent/reference/{tcp_analysis,icmp,tls,dns,dhcp,vpn,pmtud,rtt_window}.md`
- Modify: `backend/app/agent/tools.py`
- Test: `backend/tests/test_agent_tools.py` (añadir)

**Interfaces:**
- Produces:
  ```python
  # app/agent/masking.py
  def mask_sensitive(text: str) -> str
      # header values of Authorization, Proxy-Authorization, Cookie, Set-Cookie, X-API-Key, X-Auth-Token (case-insensitive, up to end of line) -> "***";
      # form/query pairs password=, passwd=, pwd=, token=, secret= -> key=***; "Basic <b64>" / "Bearer <tok>" anywhere -> "Basic ***"/"Bearer ***"
  # app/agent/tools.py
  REFERENCE_TOPICS = ("tcp_analysis", "icmp", "tls", "dns", "dhcp", "vpn", "pmtud", "rtt_window")
  def follow_stream(ctx: ToolContext, stream_id: int, protocol: str = "tcp", direction: str = "both", max_bytes: int = 16384) -> ToolResult
      # not ctx.session.content_allowed -> is_error {"error": "content_disabled", "hint": "..."}; direction in ("both","a_to_b","b_to_a");
      # content {"stream_id", "nodes": {"a": "ip:port", "b": "ip:port"}, "text": masked ascii, "bytes_returned": int, "truncated": bool}; max_bytes clamped to [256, 65536]
  def protocol_reference(topic: str) -> ToolResult
      # content {"topic": str, "text": str}; unknown -> is_error {"error": "unknown_topic", "topics": REFERENCE_TOPICS}
  ```

- [ ] **Step 1: Tests que fallan**

```python
from app.agent.masking import mask_sensitive
from app.agent.tools import REFERENCE_TOPICS, follow_stream, protocol_reference

def test_mask_sensitive():
    raw = "GET /login?user=bob&password=hunter2 HTTP/1.1\r\nAuthorization: Basic Ym9iOmh1bnRlcjI=\r\nCookie: sid=abc\r\nHost: x\r\n"
    out = mask_sensitive(raw)
    assert "hunter2" not in out and "Ym9i" not in out and "sid=abc" not in out and "Host: x" in out
    assert "password=***" in out and "Authorization: ***" in out

@needs_tshark
def test_follow_stream_requires_content_switch(ctx):
    r = follow_stream(ctx, 0)
    assert r.is_error and r.content["error"] == "content_disabled"
    ctx.session.content_allowed = True
    r = follow_stream(ctx, 0)
    assert not r.is_error and "GET / HTTP/1.1" in r.content["text"] and r.content["nodes"]["b"] == "10.0.0.2:80"
    small = follow_stream(ctx, 0, max_bytes=256)
    assert small.content["truncated"] is True and small.content["bytes_returned"] <= 256

def test_protocol_reference_topics():
    for topic in REFERENCE_TOPICS:
        r = protocol_reference(topic); assert not r.is_error and len(r.content["text"]) > 200
    assert protocol_reference("quantum").is_error
```

- [ ] **Step 2: Ejecutar y ver que fallan.**

- [ ] **Step 3: Implementar**

`follow_stream` ejecuta `run_tshark(["-r", pcap, "-q", "-z", "follow,tcp,ascii,N"])` (udp igual) y usa `stats_parse.parse_follow(text) -> {"nodes": {...}, "chunks": [{"direction": "a_to_b"|"b_to_a", "text": str}]}` (añadir a `stats_parse.py`; en la salida de tshark los trozos del nodo 1 van indentados con un tabulador). Concatena los trozos del sentido pedido con separadores `--- a_to_b ---`, enmascara, corta a `max_bytes`. Las notas de referencia se escriben en inglés (son prompt), 200-600 palabras cada una, con la semántica de banderas de análisis TCP de Wireshark, códigos ICMP/ICMPv6 tipo 3/11 y 1/3, alertas TLS por código, rcodes DNS, estados DHCP, IKE/ESP, PMTUD y cómo interpretar RTT/ventana/throughput. Se cargan con `importlib.resources`/`pathlib` relativo al módulo.

- [ ] **Step 4: Ejecutar y ver que pasan.**

- [ ] **Step 5: Commit** — `git commit -m "feat(agent): follow_stream with masking, protocol_reference notes"`

---

### Task 8: Definiciones de herramientas para la API y `execute_tool`

**Files:**
- Modify: `backend/app/agent/tools.py`
- Test: `backend/tests/test_agent_tools.py` (añadir)

**Interfaces:**
- Produces:
  ```python
  TOOL_DEFINITIONS: List[dict]   # Anthropic tool params; one per tool; each has "strict": True, "input_schema" with additionalProperties False and required; descriptions tell the model when to use each and that outputs may be truncated
  def execute_tool(ctx: ToolContext, name: str, tool_input: dict) -> ToolResult
      # unknown name -> is_error {"error": "unknown_tool"}; input validated against the schema (type/enum/range) -> is_error {"error": "invalid_input", "message"};
      # ToolTimeout -> is_error {"error": "timeout"}; ToolError -> is_error {"error": "tool_failed", "message"}; any other exception -> is_error {"error": "internal"} (logged without payload)
  def serialize_result(result: ToolResult, max_bytes: Optional[int] = None) -> Tuple[str, bool]
      # json.dumps(content, ensure_ascii=False); if longer than max_bytes (default TOOL_MAX_OUTPUT_BYTES): rows/text are cut until it fits and {"truncated": true, "note": "..."} is set; returns (text, truncated)
  def tool_result_block(tool_use_id: str, result: ToolResult) -> dict
      # {"type": "tool_result", "tool_use_id": ..., "content": serialized text, "is_error": result.is_error}
  ```

- [ ] **Step 1: Tests que fallan**

```python
import json
from app.agent.tools import TOOL_DEFINITIONS, execute_tool, serialize_result, tool_result_block, ToolResult

def test_tool_definitions_are_strict_and_complete():
    names = {t["name"] for t in TOOL_DEFINITIONS}
    assert names == {"capture_overview", "filter_packets", "stream_detail", "statistics", "follow_stream", "protocol_reference"}
    for t in TOOL_DEFINITIONS:
        assert t["strict"] is True and t["input_schema"]["additionalProperties"] is False and "required" in t["input_schema"]

def test_serialize_result_truncates_to_valid_json():
    big = ToolResult(content={"rows": [{"frame": i, "_ws.col.info": "x" * 500} for i in range(400)]})
    text, truncated = serialize_result(big, max_bytes=20000)
    assert truncated and len(text.encode()) <= 20000
    data = json.loads(text); assert data["truncated"] is True and len(data["rows"]) < 400

@needs_tshark
def test_execute_tool_dispatch_and_errors(ctx):
    assert not execute_tool(ctx, "capture_overview", {}).is_error
    assert execute_tool(ctx, "nope", {}).content["error"] == "unknown_tool"
    assert execute_tool(ctx, "filter_packets", {"display_filter": "tcp", "fields": ["frame.number"], "limit": 10**9}).content["returned"] <= config.TOOL_MAX_ROWS
    assert execute_tool(ctx, "stream_detail", {"stream_id": "zero"}).content["error"] == "invalid_input"
    block = tool_result_block("tu_1", execute_tool(ctx, "protocol_reference", {"topic": "tls"}))
    assert block["type"] == "tool_result" and block["is_error"] is False and "tls" in block["content"]

@needs_tshark
def test_execute_tool_timeout_is_reported_not_raised(ctx, monkeypatch):
    from app.agent import tshark_run
    def boom(*a, **k): raise tshark_run.ToolTimeout("slow")
    monkeypatch.setattr("app.agent.tools.run_tshark", boom)
    assert execute_tool(ctx, "statistics", {"kind": "expert"}).content["error"] == "timeout"
```

- [ ] **Step 2: Ejecutar y ver que fallan.**

- [ ] **Step 3: Implementar.** Validación de entrada manual contra el propio `input_schema` (tipos, enum, mínimos/máximos) sin dependencias nuevas; clamp de `limit`/`offset`/`max_bytes`/`interval_s` dentro de cada herramienta ya definido en tareas anteriores. En `serialize_result`, recorte por mitades de `rows` (o del campo `text`) hasta caber, máximo 12 iteraciones.

- [ ] **Step 4: Ejecutar y ver que pasan.**

- [ ] **Step 5: Commit** — `git commit -m "feat(agent): strict tool definitions, dispatcher and bounded serialization"`

---

### Task 9: Prompts del agente

**Files:**
- Create: `backend/app/agent/prompts.py`
- Test: `backend/tests/test_agent_runner.py` (primera parte)

**Interfaces:**
- Produces:
  ```python
  INVESTIGATE_SENTINEL = "__investigate__"
  EVIDENCE_HELP: str   # the exact mark syntax: [[pkt: N]], [[pkt: N-M]], [[filter: <wireshark display filter>]]
  def agent_system(lang: str) -> str          # stable across turns for a language (cacheable): role, workflow, evidence rules, honesty rules, untrusted-data rule, content-switch rule, language
  def investigate_request(lang: str) -> str   # the user-turn text for the automatic investigation: the 5-section report structure of spec §5.1 with the literal section headers for that language
  def limit_reached_note(lang: str) -> str    # mid-conversation system message: no more tools, close with what you have, say what is missing
  REPORT_HEADERS = {"es": ("Veredicto", "Hallazgos", "Causa raíz probable", "Qué hacer", "Límites de esta captura"), "en": ("Verdict", "Findings", "Probable root cause", "What to do", "Limits of this capture")}
  ```

- [ ] **Step 1: Tests que fallan**

```python
# backend/tests/test_agent_runner.py
from __future__ import annotations
from app.agent import prompts

def test_prompts_are_stable_and_contain_rules():
    assert prompts.agent_system("es") == prompts.agent_system("es")
    for lang in ("es", "en"):
        s = prompts.agent_system(lang)
        assert "capture_overview" in s and "[[pkt:" in s and "[[filter:" in s and "untrusted" in s.lower()
        req = prompts.investigate_request(lang)
        for header in prompts.REPORT_HEADERS[lang]: assert header in req
    assert "Spanish" in prompts.agent_system("es") and "English" in prompts.agent_system("en")
    assert prompts.limit_reached_note("en")
```

- [ ] **Step 2: Ejecutar y ver que falla.** — **Step 3: Escribir los prompts** (inglés; reglas del spec §4.4; sin fecha ni nada volátil). — **Step 4: Ver que pasa.**

- [ ] **Step 5: Commit** — `git commit -m "feat(agent): system and investigation prompts"`

---

### Task 10: Bucle del agente (`run_turn`)

**Files:**
- Create: `backend/app/agent/runner.py`
- Test: `backend/tests/test_agent_runner.py` (añadir)

**Interfaces:**
- Consumes: `TOOL_DEFINITIONS`, `execute_tool`, `tool_result_block`, `ToolContext` (Task 8); `session_store.decrypted_pcap` (Task 1); `prompts` (Task 9); `get_client` (`app/llm/client.py`).
- Produces:
  ```python
  @dataclass
  class TurnEvent:
      type: str      # "tool_start" | "tool_end" | "text" | "usage" | "done" | "error"
      data: dict
  @dataclass
  class TurnResult:
      text: str; stop_reason: str; limited: bool; usage: Dict[str, int]
  class AgentLimitError(RuntimeError): ...     # session token cap exceeded before starting
  def run_turn(session: Session, user_text: str, lang: str, tshark_path: str, emit: Callable[[TurnEvent], None], client=None) -> TurnResult
      # client defaults to llm.client.get_client(); raises AIUnavailableError when None.
      # Loop: build messages = session.messages + [{"role":"user","content": text}] (text = investigate_request(lang) when user_text == INVESTIGATE_SENTINEL);
      # each iteration: with client.beta.messages.stream(model=config.LLM_MODEL, max_tokens=16000, system=[{text: agent_system(lang), cache_control: ephemeral}],
      #   tools=TOOL_DEFINITIONS (last one carries cache_control), messages=..., thinking={"type":"adaptive"},
      #   output_config={"effort": config.AGENT_EFFORT, "task_budget": {"type":"tokens","total": config.AGENT_TASK_BUDGET_TOKENS}},
      #   betas=["server-side-fallback-2026-07-01", "task-budgets-2026-03-13", "compact-2026-01-12"], fallbacks="default",
      #   context_management={"edits":[{"type":"compact_20260112"}]} only when estimated history tokens > config.AGENT_COMPACT_TOKENS) as stream:
      #   emit text deltas as they arrive; final = stream.get_final_message()
      # append {"role":"assistant","content": final.content} (full blocks); if stop_reason == "tool_use": run every tool_use block (ThreadPoolExecutor, max 4) under ONE decrypted_pcap,
      #   emit tool_start/tool_end per tool, append ONE user message with all tool_result blocks, continue.
      # Caps: tool calls > AGENT_MAX_TOOL_CALLS or model calls >= AGENT_MAX_MODEL_CALLS -> append {"role":"system","content": limit_reached_note(lang)} and do a final call with tools=[] ; limited=True.
      # stop_reason "max_tokens" -> one continuation call; "refusal" -> raise AIServiceError("El modelo no procesó esta pregunta.").
      # Accumulate usage (input/output/cache_read/cache_write) from every response; on success: session.messages = new history (append-only), session.usage += totals, session.usage.questions += 1; on any exception: session.messages unchanged.
      # Before the first call: if session.usage.input_tokens + output_tokens >= config.SESSION_MAX_TOKENS -> AgentLimitError.
      # Emits usage {input_tokens, output_tokens, cache_read_tokens, cache_write_tokens, session_total_tokens} and done {stop_reason, limited}.
  ```

- [ ] **Step 1: Escribir el cliente simulado y los tests que fallan**

```python
# añadir a tests/test_agent_runner.py
import json
from types import SimpleNamespace
import pytest
from app import config
from app.agent import runner
from app.agent.prompts import INVESTIGATE_SENTINEL
from app.sessions import SessionStore
from tests.test_llm import make_analysis

def _usage(i=100, o=50): return SimpleNamespace(input_tokens=i, output_tokens=o, cache_read_input_tokens=0, cache_creation_input_tokens=0)
def _text(t): return SimpleNamespace(type="text", text=t)
def _tool(id_, name, inp): return SimpleNamespace(type="tool_use", id=id_, name=name, input=inp)
def _msg(content, stop="end_turn"): return SimpleNamespace(content=content, stop_reason=stop, usage=_usage(), model="claude-opus-5-5")

class FakeStream:
    def __init__(self, msg): self.msg = msg
    def __enter__(self): return self
    def __exit__(self, *a): return False
    @property
    def text_stream(self):
        for b in self.msg.content:
            if b.type == "text": yield b.text
    def get_final_message(self): return self.msg

class FakeClient:
    def __init__(self, scripted): self.scripted = list(scripted); self.calls = []
    class beta:
        pass
    def __post_init__(self): pass
def make_client(scripted):
    c = FakeClient(scripted)
    def stream(**kwargs):
        c.calls.append(kwargs); return FakeStream(c.scripted.pop(0))
    c.beta = SimpleNamespace(messages=SimpleNamespace(stream=stream)); return c

@pytest.fixture
def session(tmp_path, sample_pcap):
    store = SessionStore(directory=str(tmp_path / "s"))
    s = store.create("tok", str(sample_pcap), "sample.pcap", make_analysis())
    runner.session_store = store   # the runner decrypts through the store
    return s

def test_run_turn_executes_tools_and_persists_complete_turn(session):
    client = make_client([
        _msg([_tool("t1", "protocol_reference", {"topic": "tls"}), _tool("t2", "protocol_reference", {"topic": "dns"})], stop="tool_use"),
        _msg([_text("Veredicto: todo bien [[pkt: 1]]")]),
    ])
    events = []
    result = runner.run_turn(session, INVESTIGATE_SENTINEL, "es", "/usr/bin/tshark", events.append, client=client)
    assert result.text.startswith("Veredicto") and result.limited is False
    types = [e.type for e in events]
    assert types.count("tool_start") == 2 and types.count("tool_end") == 2 and types[-1] == "done" and "usage" in types
    assert [m["role"] for m in session.messages] == ["user", "assistant", "user", "assistant"]
    assert len(session.messages[2]["content"]) == 2 and all(b["type"] == "tool_result" for b in session.messages[2]["content"])
    assert session.usage.questions == 1 and session.usage.input_tokens == 200
    first = client.calls[0]
    assert first["model"] == config.LLM_MODEL and first["fallbacks"] == "default" and first["output_config"]["effort"] == config.AGENT_EFFORT
    assert first["system"][0]["cache_control"] == {"type": "ephemeral"} and first["tools"][-1]["cache_control"] == {"type": "ephemeral"}
    assert "context_management" not in first

def test_run_turn_enforces_tool_cap(session, monkeypatch):
    monkeypatch.setattr(config, "AGENT_MAX_TOOL_CALLS", 2)
    client = make_client([
        _msg([_tool("a", "protocol_reference", {"topic": "tls"})], stop="tool_use"),
        _msg([_tool("b", "protocol_reference", {"topic": "tls"})], stop="tool_use"),
        _msg([_tool("c", "protocol_reference", {"topic": "tls"})], stop="tool_use"),   # would be the 3rd -> not executed
        _msg([_text("cierre")]),
    ])
    result = runner.run_turn(session, "hola", "es", "/usr/bin/tshark", lambda e: None, client=client)
    assert result.limited is True and result.text == "cierre"
    last = client.calls[-1]
    assert last["tools"] == [] and last["messages"][-1]["role"] == "system"

def test_run_turn_failure_leaves_history_untouched(session):
    client = make_client([_msg([_tool("a", "protocol_reference", {"topic": "tls"})], stop="tool_use")])  # 2nd call -> IndexError
    with pytest.raises(Exception): runner.run_turn(session, "hola", "es", "/usr/bin/tshark", lambda e: None, client=client)
    assert session.messages == [] and session.usage.questions == 0

def test_run_turn_refusal(session):
    from app.llm.service import AIServiceError
    client = make_client([_msg([], stop="refusal")])
    with pytest.raises(AIServiceError): runner.run_turn(session, "hola", "es", "/usr/bin/tshark", lambda e: None, client=client)

def test_run_turn_session_token_cap(session, monkeypatch):
    monkeypatch.setattr(config, "SESSION_MAX_TOKENS", 10)
    session.usage.input_tokens = 20
    with pytest.raises(runner.AgentLimitError): runner.run_turn(session, "hola", "es", "/usr/bin/tshark", lambda e: None, client=make_client([]))

def test_run_turn_compacts_when_history_is_large(session, monkeypatch):
    monkeypatch.setattr(config, "AGENT_COMPACT_TOKENS", 10)
    session.messages = [{"role": "user", "content": "x" * 400}, {"role": "assistant", "content": [{"type": "text", "text": "y" * 400}]}]
    client = make_client([_msg([_text("ok")])])
    runner.run_turn(session, "más", "es", "/usr/bin/tshark", lambda e: None, client=client)
    assert client.calls[0]["context_management"] == {"edits": [{"type": "compact_20260112"}]}
```

- [ ] **Step 2: Ejecutar y ver que fallan.**

- [ ] **Step 3: Implementar `app/agent/runner.py`** según la interfaz. Estimación de tokens del historial: `len(json.dumps(messages)) // 4`. Los bloques de `final.content` se convierten a dict con `block.model_dump()` cuando exista, si no con `vars()`; `thinking`/`compaction` se conservan tal cual. La ejecución de herramientas abre `session_store.decrypted_pcap(session)` una vez por lote. Los `tool_start` llevan `{"name", "label"}` con `label` legible (p. ej. `filter_packets: tcp.stream eq 7`); los `tool_end` llevan `{"name", "ms", "is_error", "truncated"}`.

- [ ] **Step 4: Ejecutar y ver que pasan.**

- [ ] **Step 5: Commit** — `git commit -m "feat(agent): tool-use loop with caps, caching, compaction and append-only history"`

---

### Task 11: Endpoint de chat SSE, presupuesto diario, bloqueo por sesión y modo demo

**Files:**
- Create: `backend/app/agent/demo.py`
- Modify: `backend/app/agent/router.py`
- Test: `backend/tests/test_agent_api.py` (añadir)

**Interfaces:**
- Consumes: `run_turn`, `TurnEvent`, `AgentLimitError` (Task 10); `llm_budget` (`app/guards.py`); `AIUnavailableError`, `AIServiceError` (`app/llm/service.py`); `demo_diagnosis` (`app/llm/demo.py`).
- Produces:
  ```python
  # app/agent/demo.py
  def demo_investigation(analysis: AnalysisResult, lang: str) -> str
      # demo_diagnosis(analysis, lang)["diagnosis"] + a "Hallazgos"/"Findings" section listing each issue with an evidence mark built from its evidence:
      # stream_id/tcp_stream -> [[filter: tcp.stream eq N]]; stream_ids -> [[filter: tcp.stream in {…}]]; icmp reporter -> [[filter: ip.src == R && icmp]]; dns query_name -> [[filter: dns && _ws.col.info contains "name"]]; else none
  DEMO_CHAT_REPLY = {"es": "...", "en": "..."}   # explains ANTHROPIC_API_KEY + LLM_DEMO=0
  # app/agent/router.py
  class ChatRequest(BaseModel): message: str = Field(min_length=1, max_length=4000); lang: Literal["es","en"] = "es"
  POST /sessions/{session_id}/chat -> StreamingResponse(media_type="text/event-stream")
      # SSE frames "event: <type>\ndata: <json>\n\n"; a sync generator runs run_turn in a thread (semaphore of config.AGENT_WORKERS) and drains a queue.Queue.
      # 404 unknown session; 409 {"detail": "Hay una investigación en curso en esta sesión."} when session.lock is held or when message == INVESTIGATE_SENTINEL and session.messages;
      # demo/no-key: in demo mode the sentinel streams demo_investigation as text events and the rest DEMO_CHAT_REPLY, without charging llm_budget;
      # otherwise llm_budget.consume(principal.tenant_id) BEFORE starting (429 propagates as HTTP); AIUnavailableError -> 503 before streaming;
      # errors inside the stream (AgentLimitError, AIServiceError, unexpected) -> event "error" {"code": "session_tokens"|"model"|"internal", "message"} then end.
  ```

- [ ] **Step 1: Tests que fallan**

```python
# añadir a tests/test_agent_api.py
import json, threading, time
from app.agent import router as agent_router, runner
from app.agent.prompts import INVESTIGATE_SENTINEL

def _events(resp):
    out = []
    for frame in resp.text.strip().split("\n\n"):
        lines = frame.split("\n"); ev = lines[0][len("event: "):]; data = json.loads(lines[1][len("data: "):]); out.append((ev, data))
    return out

def test_chat_streams_events_from_runner(client, sample_pcap, monkeypatch):
    sid = _analyze(client, sample_pcap).json()["session"]["id"]
    def fake_run_turn(session, text, lang, tshark_path, emit, client=None):
        emit(runner.TurnEvent("tool_start", {"name": "capture_overview", "label": "capture_overview"}))
        emit(runner.TurnEvent("tool_end", {"name": "capture_overview", "ms": 3, "is_error": False, "truncated": False}))
        emit(runner.TurnEvent("text", {"delta": "Veredicto [[pkt: 1]]"}))
        emit(runner.TurnEvent("usage", {"input_tokens": 1, "output_tokens": 1, "cache_read_tokens": 0, "cache_write_tokens": 0, "session_total_tokens": 2}))
        emit(runner.TurnEvent("done", {"stop_reason": "end_turn", "limited": False}))
        return runner.TurnResult("Veredicto [[pkt: 1]]", "end_turn", False, {})
    monkeypatch.setattr(agent_router, "run_turn", fake_run_turn)
    monkeypatch.setattr(agent_router, "ai_available", lambda: True)
    r = client.post("/sessions/%s/chat" % sid, json={"message": INVESTIGATE_SENTINEL, "lang": "es"})
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/event-stream")
    assert [e for e, _ in _events(r)] == ["tool_start", "tool_end", "text", "usage", "done"]

def test_chat_demo_mode_streams_report_without_budget(client, sample_pcap, monkeypatch):
    monkeypatch.setattr(config, "LLM_DEMO", True)
    sid = _analyze(client, sample_pcap).json()["session"]["id"]
    ev = _events(client.post("/sessions/%s/chat" % sid, json={"message": INVESTIGATE_SENTINEL}))
    text = "".join(d["delta"] for e, d in ev if e == "text")
    assert "[[filter: tcp.stream eq" in text and ev[-1][0] == "done"
    reply = _events(client.post("/sessions/%s/chat" % sid, json={"message": "¿por qué?"}))
    assert "ANTHROPIC_API_KEY" in "".join(d["delta"] for e, d in reply if e == "text")

def test_chat_409_when_turn_in_progress_or_repeated_investigate(client, sample_pcap, monkeypatch):
    from app.sessions import session_store
    sid = _analyze(client, sample_pcap).json()["session"]["id"]
    session = session_store.peek(sid, "test-token")
    monkeypatch.setattr(agent_router, "ai_available", lambda: True)
    assert session.lock.acquire(blocking=False)
    try:
        assert client.post("/sessions/%s/chat" % sid, json={"message": "hola"}).status_code == 409
    finally:
        session.lock.release()
    session.messages = [{"role": "user", "content": "x"}]
    assert client.post("/sessions/%s/chat" % sid, json={"message": INVESTIGATE_SENTINEL}).status_code == 409

def test_chat_charges_daily_budget_and_reports_503_without_key(client, sample_pcap, monkeypatch):
    from app.llm.service import AIUnavailableError
    sid = _analyze(client, sample_pcap).json()["session"]["id"]
    monkeypatch.setattr(agent_router, "ai_available", lambda: False)
    assert client.post("/sessions/%s/chat" % sid, json={"message": "hola"}).status_code == 503
    monkeypatch.setattr(agent_router, "ai_available", lambda: True)
    monkeypatch.setattr(config, "LLM_MAX_CALLS_PER_DAY", 1)
    calls = []
    def fake(session, text, lang, tshark_path, emit, client=None):
        calls.append(text); emit(runner.TurnEvent("done", {"stop_reason": "end_turn", "limited": False})); return runner.TurnResult("", "end_turn", False, {})
    monkeypatch.setattr(agent_router, "run_turn", fake)
    assert client.post("/sessions/%s/chat" % sid, json={"message": "uno"}).status_code == 200
    assert client.post("/sessions/%s/chat" % sid, json={"message": "dos"}).status_code == 429 and calls == ["uno"]

def test_chat_error_event_when_pcap_vanishes_mid_turn(client, sample_pcap, monkeypatch):
    sid = _analyze(client, sample_pcap).json()["session"]["id"]
    monkeypatch.setattr(agent_router, "ai_available", lambda: True)
    def fake(session, text, lang, tshark_path, emit, client=None):
        emit(runner.TurnEvent("text", {"delta": "a"})); raise FileNotFoundError("pcap gone")
    monkeypatch.setattr(agent_router, "run_turn", fake)
    ev = _events(client.post("/sessions/%s/chat" % sid, json={"message": "hola"}))
    assert ev[-1] == ("error", {"code": "internal", "message": "La investigación falló; inténtalo de nuevo."})
```

- [ ] **Step 2: Ejecutar y ver que fallan.**

- [ ] **Step 3: Implementar.** En `router.py`, `ai_available = lambda: get_client() is not None` como nombre de módulo (para poder simularlo) y `from .runner import run_turn` importado como atributo de módulo. Generador síncrono: hilo `threading.Thread(target=worker)` que adquiere `session.lock` (ya comprobado con `acquire(blocking=False)` antes de responder), llama a `run_turn` y pone los `TurnEvent` en una `queue.Queue`; el generador hace `yield` de cada evento y termina con `done` o `error`. Semáforo global `threading.BoundedSemaphore(config.AGENT_WORKERS)`; si no hay hueco en 0 s, responder 429 "Hay demasiadas investigaciones en curso.". `tshark_path = find_tshark()`; si es None → 503 con `install_instructions()`.

- [ ] **Step 4: Ejecutar toda la suite.** Run: `cd backend && PATH="$PATH:/Applications/Wireshark.app/Contents/MacOS" .venv/bin/python -m pytest -q`. Expected: PASS.

- [ ] **Step 5: Commit** — `git commit -m "feat(agent): SSE chat endpoint with daily budget, per-session lock and demo mode"`

---

### Task 12: Configuración documentada y comprobación de humo con la clave real

**Files:**
- Modify: `.env.example`, `docker-compose.yml`, `README.md`, `backend/app/llm/client.py` (ninguna firma cambia)
- Test: `scripts/verify-bundle.sh` no cambia; comprobación manual.

- [ ] **Step 1: Documentar variables.** Añadir a `.env.example` y al bloque `environment` de `docker-compose.yml` las 14 variables de la spec §10 con sus valores por defecto y un comentario de una línea cada una; cambiar `LLM_MODEL` por defecto en el compose a `claude-opus-5-5`. En `README.md`, nueva sección "Investigación con IA (sesiones)" explicando: qué se guarda y cuánto tiempo, el interruptor de contenido, los topes y el coste orientativo (rellenar tras el paso 3), y que en modo cola compartida no hay sesiones.

- [ ] **Step 2: Comprobar que el arranque sigue limpio.** Run: `cd backend && PATH="$PATH:/Applications/Wireshark.app/Contents/MacOS" .venv/bin/python -c "import app.main"` y `.venv/bin/python -m pytest -q`. Expected: sin errores; PASS.

- [ ] **Step 3: Humo con la clave real (solo en local, con el `.env` del desarrollador).** Arrancar `uvicorn app.main:app --port 8000` con `LLM_DEMO=0`, subir `tests/fixtures/sample.pcap` con `curl -F file=@... -H "Authorization: Bearer <token>" localhost:8000/analyze`, lanzar `curl -N -X POST localhost:8000/sessions/<id>/chat -H 'Content-Type: application/json' -d '{"message":"__investigate__","lang":"es"}'`. Anotar en `README.md`: duración, nº de herramientas usadas, tokens y coste calculado con la tabla de precios ($4/$20 por MTok; caché $0.20 lectura). Repetir con el pcap de troubleshooting (`tests/pcap_builder.py` → `build_troubleshooting_packets`). Si el informe no respeta la estructura o inventa cifras, ajustar `prompts.py` y repetir; no tocar topes sin medir.

- [ ] **Step 4: Commit** — `git commit -m "docs: investigation sessions and agent configuration; measured costs"`

---

## Self-review

- **Cobertura de la spec:** §2 sesiones → Tasks 1-2; §3 herramientas → Tasks 3-8; §4 bucle, topes, prompts, demo, endpoint → Tasks 9-11; §6 errores → Tasks 8, 10, 11; §7 pruebas → cada task; §10 variables → Tasks 1 y 12. §5 (frontend, PDF) y §8 pasos 4-6 quedan para el plan de la parte 2. Fuera de la spec no se añade nada.
- **Tipos consistentes:** `ToolResult(content, is_error, truncated)` igual en Tasks 4-8 y 10; `TurnEvent(type, data)` en Tasks 10-11; `session_store.decrypted_pcap` en Tasks 1, 4 (fixture) y 10; `SessionInfo` en Tasks 1-2.
- **Review Focus:** 1 → Task 2 (`test_gzip_upload…`); 2 → Task 3 (`test_run_tshark_rejects…`, `test_validate_filter_errors`); 3 → Task 8 (`test_serialize_result_truncates…`); 4 → Task 11 (`test_chat_error_event_when_pcap_vanishes…`); 5 → Task 1 (`test_purge_orphans_on_startup`).
- **Proporción:** el plan fija firmas, valores y tests; los cuerpos quedan al implementador salvo el formato de cifrado y el criterio de `select_rows`, que los tests no determinan.
