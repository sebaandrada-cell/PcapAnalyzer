# Agente de investigación de capturas — Plan de implementación (parte 2: interfaz, PDF, demo, release)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Que el usuario vea la investigación automática en streaming nada más analizar, pueda preguntar y comprobar cada afirmación con un clic, controle la sesión (contenido, caducidad, coste, borrado) y lo tenga también en el PDF, la demo pública y la documentación de la release 1.3.0.

**Architecture:** La lógica nueva vive en módulos puros con tests `node --test` (`sse.ts` parser de eventos, `evidence.ts` marcas `[[pkt]]`/`[[filter]]` + markdown mínimo, `pricing.ts` coste). Los componentes React (`InvestigationPanel`, `EvidenceText`, `SessionBar`) sustituyen a `DiagnosisPanel` y `QueryBar` y se verifican en el navegador contra el backend en modo demo (`LLM_DEMO=1`, sin coste) y, si hay clave válida, real. El backend solo cambia en el PDF (`report.py`) y en el generador de la demo.

**Tech Stack:** React 19 + TypeScript (Vite, `erasableSyntaxOnly`, sin enums), `fetch` + `ReadableStream` para SSE (EventSource no admite cabecera `Authorization`), `node --test` con type stripping (Node 24), reportlab, Python 3.9.

**Spec:** `docs/superpowers/specs/2026-11-01-ai-investigation-agent-design.md` (§4.1 eventos, §5 respuesta y frontend, §6 errores). Parte 1 (backend) ya fusionada en `main`.

## Global Constraints

- Código y comentarios en inglés; textos de interfaz vía `i18n.ts` en ES y EN (ninguna cadena literal en componentes).
- Imports con extensión `.ts` en los módulos puros y sus tests (como `displayFilter.ts`); nada de React ni DOM en ellos.
- Todo texto del modelo se renderiza como texto (sin `dangerouslySetInnerHTML`); los filtros se aplican con el `compileFilter` existente, nunca se evalúan como código.
- La petición SSE lleva la misma `Authorization` que el resto (`authHeaders()` de `api.ts`) y respeta `API_BASE`.
- Eventos SSE del backend (fijos): `tool_start {name,label}`, `tool_end {name,ms,is_error,truncated}`, `text {delta}`, `usage {input_tokens,output_tokens,cache_read_tokens,cache_write_tokens,session_total_tokens}`, `done {stop_reason,limited,demo?}`, `error {code: session_expired|session_tokens|model|internal, message}`. Códigos HTTP antes del stream: 404 sesión, 409 en curso / investigación repetida, 429 cupo, 503 sin IA.
- El sentinel de la investigación automática es `__investigate__`; solo se envía una vez por sesión y nunca en la demo pública.
- Precios (orientativos, en `pricing.ts`, marcados «aprox.»): `claude-opus-5-5` 4/20 $ por MTok (caché lectura 0,20, escritura 5); `claude-sonnet-5-5` 2/10 (0,20 / 2,5); `claude-haiku-5-5` 0,10/0,50 (0,01 / 0,125); `claude-fable-5-1` 10/50 (0,25 / 12,5); modelo desconocido → sin estimación.
- Cambios públicos (landing, Gumroad, textos de difusión, subir release) requieren OK explícito del usuario: el plan prepara y se detiene.

## Review Focus

1. **Recarga de página con sesión viva:** el estado React se pierde pero la sesión sigue en el backend; el sentinel devuelve 409 «ya se hizo». El panel debe explicarlo y dejar preguntar, no quedarse en blanco. Test en Task 4 (manual) y lógica en `investigationState.ts` (Task 2).
2. **Filtro que la lista local no sabe aplicar** (`tls.handshake.type == 1`, `http.response.code >= 500`): «Ver paquetes» no debe fallar en silencio; se ofrece solo «Copiar» con el aviso. Test en Task 2.
3. **Texto del modelo con marcas rotas o maliciosas** (`[[pkt: abc]]`, `[[filter: ]]`, HTML `<img onerror>` en el texto): se muestran como texto plano, sin ejecutar ni interpretar. Test en Task 2.
4. **Corte de red a mitad del streaming:** el turno queda marcado como interrumpido, el botón «Reenviar» repite la pregunta y la sesión sigue usable. Test del parser con stream truncado en Task 1; comprobación manual en Task 4.
5. **Caducidad mientras el usuario lee:** al llegar `error.code = session_expired` o al expirar la cuenta atrás, el panel bloquea la entrada con «vuelve a analizarla» y mantiene el informe ya recibido. Test de reducer en Task 2.

---

## Estructura de archivos

| Archivo | Responsabilidad |
|---|---|
| `frontend/src/sse.ts` (crear) | `SseParser` incremental (texto → eventos), puro |
| `frontend/src/api.ts` (modificar) | tipos `SessionInfo`/`SessionStatus`, `AnalysisResult.session`, `getSession`, `patchSession`, `deleteSession`, `chatStream` |
| `frontend/src/evidence.ts` (crear) | `parseInline` (texto, negrita, código, `pkt`, `filter`), `parseBlocks` (encabezados, viñetas, párrafos), `filterApplicability` |
| `frontend/src/pricing.ts` (crear) | `estimateCostUsd(usage, model)` |
| `frontend/src/investigationState.ts` (crear) | reducer puro del panel: turnos, pasos, streaming, errores, sesión |
| `frontend/src/components/EvidenceText.tsx` (crear) | renderiza bloques/segmentos con botones de evidencia |
| `frontend/src/components/SessionBar.tsx` (crear) | cuenta atrás, interruptor de contenido, coste, borrar |
| `frontend/src/components/InvestigationPanel.tsx` (crear) | informe inicial en streaming + chat + sugerencias + estados |
| `frontend/src/App.tsx` (modificar) | sustituye `QueryBar`/`DiagnosisPanel`; pasa `showPackets`, selección de paquete y texto del informe al PDF |
| `frontend/src/components/DiagnosisPanel.tsx`, `QueryBar.tsx` (borrar) | reemplazados |
| `frontend/src/i18n.ts` (modificar) | bloque `investigation`, `session`; borrar `diagnosis` y `query` |
| `frontend/src/index.css` (modificar) | estilos del panel, pasos, evidencia, barra de sesión |
| `frontend/vite.config.ts` (modificar) | proxy `/sessions` |
| `frontend/src/demo.ts`, `scripts/make-demo-data.py`, `frontend/public/demo/demo.json` (modificar) | `investigation: {es,en}` pregenerado |
| `backend/app/report.py` (modificar) | secciones y marcas de evidencia en el PDF |
| `backend/tests/test_report_investigation.py` (crear) | tests del PDF |
| `QUICKSTART.md`, `README.md`, `landing.html`, `marketing/*`, `scripts/verify-bundle.sh`, `backend/app/__init__.py` (modificar) | documentación, comprobaciones CI y versión 1.3.0 |

---

### Task 1: Parser SSE y cliente de sesiones/chat

**Files:**
- Create: `frontend/src/sse.ts`, `frontend/src/sse.test.ts`
- Modify: `frontend/src/api.ts`, `frontend/vite.config.ts`

**Interfaces:**
- Produces:
  ```ts
  // sse.ts
  export interface SseEvent { event: string; data: unknown }
  export class SseParser {
    push(chunk: string): SseEvent[]      // returns the complete events found so far; keeps the partial tail
    flush(): SseEvent[]                   // at stream end: a complete trailing frame without final blank line
  }
  // api.ts
  export interface SessionInfo { id: string; expires_at: number; ttl_minutes: number; content_allowed: boolean }
  export interface SessionStatus extends SessionInfo { usage: Record<string, number>; messages: number }
  export interface AnalysisResult { ...; session?: SessionInfo | null }
  export async function getSession(id: string): Promise<SessionStatus>
  export async function patchSession(id: string, contentAllowed: boolean): Promise<SessionStatus>
  export async function deleteSession(id: string): Promise<void>
  export interface ChatHandlers {
    onToolStart(d: {name: string; label: string}): void
    onToolEnd(d: {name: string; ms: number; is_error: boolean; truncated: boolean}): void
    onText(delta: string): void
    onUsage(d: Record<string, number>): void
    onDone(d: {stop_reason: string; limited: boolean; demo?: boolean}): void
    onError(d: {code: string; message: string}): void
  }
  export class ChatHttpError extends Error { status: number }   // 404/409/429/503 before the stream starts; message = detail
  export async function chatStream(sessionId: string, message: string, lang: 'es'|'en', handlers: ChatHandlers, signal?: AbortSignal): Promise<void>
    // POST `${API_BASE}/sessions/${id}/chat` with authHeaders + JSON; non-2xx -> throw ChatHttpError; reads response.body with TextDecoder(stream) and SseParser; resolves when the stream ends; rejects with the fetch error on network failure (AbortError included)
  export const INVESTIGATE_SENTINEL = '__investigate__'
  ```

- [ ] **Step 1: Test que falla** (`frontend/src/sse.test.ts`)

```ts
import assert from 'node:assert/strict'
import { test } from 'node:test'
import { SseParser } from './sse.ts'

test('parses complete frames and keeps the partial tail', () => {
  const p = new SseParser()
  assert.deepEqual(p.push('event: text\ndata: {"delta":"ho'), [])
  assert.deepEqual(p.push('la"}\n\nevent: done\ndata: {"stop_reason":"end_turn","limited":false}\n\n'), [
    { event: 'text', data: { delta: 'hola' } },
    { event: 'done', data: { stop_reason: 'end_turn', limited: false } },
  ])
})

test('tolerates CRLF, comments and a trailing frame without blank line', () => {
  const p = new SseParser()
  assert.deepEqual(p.push(': keepalive\r\nevent: usage\r\ndata: {"input_tokens":1}\r\n\r\nevent: done\ndata: {}'), [
    { event: 'usage', data: { input_tokens: 1 } },
  ])
  assert.deepEqual(p.flush(), [{ event: 'done', data: {} }])
})

test('a truncated stream yields only the frames that completed', () => {
  const p = new SseParser()
  assert.deepEqual(p.push('event: text\ndata: {"delta":"a"}\n\nevent: text\ndata: {"del'), [{ event: 'text', data: { delta: 'a' } }])
  assert.deepEqual(p.flush(), [])   // unparseable tail is dropped, never thrown
})
```

- [ ] **Step 2: Ejecutar** — Run: `cd frontend && node --test src/sse.test.ts` — Expected: FAIL (módulo inexistente).
- [ ] **Step 3: Implementar `sse.ts`** (split por `\n\n` tras normalizar `\r\n`; `data:` multilínea se une con `\n`; `JSON.parse` fallido → se descarta el evento) y añadir a `api.ts` los tipos y funciones de la interfaz; en `vite.config.ts` añadir `'/sessions': 'http://127.0.0.1:8000'`.
- [ ] **Step 4: Ejecutar** — `node --test src/sse.test.ts` PASS; `npx tsc -p tsconfig.app.json --noEmit` sin errores (tarda minutos en esta máquina; lanzar en segundo plano).
- [ ] **Step 5: Commit** — `git commit -m "feat(frontend): SSE parser and session/chat API client"`

---

### Task 2: Evidencia, markdown mínimo, coste y reducer del panel

**Files:**
- Create: `frontend/src/evidence.ts`, `frontend/src/evidence.test.ts`, `frontend/src/pricing.ts`, `frontend/src/pricing.test.ts`, `frontend/src/investigationState.ts`, `frontend/src/investigationState.test.ts`

**Interfaces:**
- Consumes: `compileFilter` (`displayFilter.ts`).
- Produces:
  ```ts
  // evidence.ts
  export type Inline =
    | { kind: 'text'; text: string } | { kind: 'bold'; text: string } | { kind: 'code'; text: string }
    | { kind: 'pkt'; from: number; to: number } | { kind: 'filter'; filter: string }
  export type Block =
    | { kind: 'heading'; level: 2 | 3; inlines: Inline[] } | { kind: 'bullet'; inlines: Inline[] }
    | { kind: 'paragraph'; inlines: Inline[] } | { kind: 'code'; text: string }
  export function parseInline(text: string): Inline[]
    // [[pkt: 12]] -> pkt 12..12; [[pkt: 12-15]] -> 12..15; [[filter: X]] -> filter "X" (trimmed, non-empty) ;
    // malformed marks ([[pkt: abc]], [[filter: ]], unclosed) stay literal text; **bold** and `code` supported; everything else text
  export function parseBlocks(markdown: string): Block[]
    // '## ' / '### ' headings, '- ' or '* ' bullets, ``` fences as code blocks, blank-line separated paragraphs; never HTML
  export function filterApplicability(filter: string, knownProtocols: ReadonlySet<string>): 'local' | 'copy-only'
    // 'local' when compileFilter(filter, knownProtocols).ok, else 'copy-only'

  // pricing.ts
  export interface Usage { input_tokens: number; output_tokens: number; cache_read_tokens: number; cache_write_tokens: number }
  export function estimateCostUsd(usage: Usage, model: string): number | null   // table from Global Constraints; prefix match on model id

  // investigationState.ts
  export interface Step { name: string; label: string; ms?: number; isError?: boolean; truncated?: boolean; done: boolean }
  export interface Turn { id: number; question: string | null /* null = automatic investigation */; text: string; steps: Step[]; usage?: Usage; limited: boolean; error?: {code: string; message: string}; interrupted: boolean; streaming: boolean }
  export interface PanelState {
    turns: Turn[]; sessionId: string | null; expiresAt: number | null; contentAllowed: boolean
    expired: boolean; totalUsage: Usage; investigated: boolean; blockedReason: 'expired' | 'tokens' | null
  }
  export type Action =
    | { type: 'start'; question: string | null } | { type: 'tool_start'; name: string; label: string }
    | { type: 'tool_end'; name: string; ms: number; is_error: boolean; truncated: boolean }
    | { type: 'text'; delta: string } | { type: 'usage'; usage: Usage } | { type: 'done'; limited: boolean }
    | { type: 'error'; code: string; message: string } | { type: 'interrupted' }
    | { type: 'http_error'; status: number; message: string }
    | { type: 'session'; info: {expires_at: number; content_allowed: boolean} } | { type: 'expired' } | { type: 'reset' }
  export function initialState(sessionId: string | null, expiresAt: number | null, contentAllowed: boolean): PanelState
  export function reduce(state: PanelState, action: Action): PanelState
    // 'start' appends a streaming turn; tool_end closes the first open step with that name; 'done' ends streaming and sets investigated when question === null;
    // 'error' with code session_expired -> expired=true, blockedReason='expired'; session_tokens -> blockedReason='tokens';
    // 'http_error' 409 for the automatic turn -> investigated=true, turn removed, note kept in state.notice = 'already_investigated'; 'interrupted' -> turn.interrupted=true, streaming=false
  ```

- [ ] **Step 1: Tests que fallan**

```ts
// evidence.test.ts
test('parses evidence marks and keeps malformed ones literal', () => {
  assert.deepEqual(parseInline('RST a los 5 ms [[pkt: 11]] y [[pkt: 10-11]] [[filter: tcp.stream eq 1]].'), [
    { kind: 'text', text: 'RST a los 5 ms ' }, { kind: 'pkt', from: 11, to: 11 }, { kind: 'text', text: ' y ' },
    { kind: 'pkt', from: 10, to: 11 }, { kind: 'text', text: ' ' }, { kind: 'filter', filter: 'tcp.stream eq 1' }, { kind: 'text', text: '.' },
  ])
  assert.deepEqual(parseInline('[[pkt: abc]] [[filter: ]] [[pkt: 3'), [{ kind: 'text', text: '[[pkt: abc]] [[filter: ]] [[pkt: 3' }])
  assert.deepEqual(parseInline('ver **esto** y `tcp.port == 80`'), [
    { kind: 'text', text: 'ver ' }, { kind: 'bold', text: 'esto' }, { kind: 'text', text: ' y ' }, { kind: 'code', text: 'tcp.port == 80' },
  ])
})
test('html stays text', () => {
  assert.deepEqual(parseInline('<img src=x onerror=alert(1)>'), [{ kind: 'text', text: '<img src=x onerror=alert(1)>' }])
})
test('blocks: headings, bullets, paragraphs, fences', () => {
  const blocks = parseBlocks('## Veredicto\nTodo bien.\n\n- uno [[pkt: 1]]\n- dos\n\n```\ntcp.stream eq 1\n```')
  assert.deepEqual(blocks.map((b) => b.kind), ['heading', 'paragraph', 'bullet', 'bullet', 'code'])
  assert.equal((blocks[0] as any).level, 2)
})
test('filter applicability uses the local engine', () => {
  assert.equal(filterApplicability('tcp.stream eq 1', new Set()), 'local')
  assert.equal(filterApplicability('tls.handshake.type == 1', new Set()), 'copy-only')
  assert.equal(filterApplicability('tcp.port ==== 1', new Set()), 'copy-only')
})
// pricing.test.ts
test('cost table', () => {
  const u = { input_tokens: 1_000_000, output_tokens: 100_000, cache_read_tokens: 500_000, cache_write_tokens: 0 }
  assert.equal(estimateCostUsd(u, 'claude-opus-5-5'), 4 + 2 + 0.1)
  assert.equal(estimateCostUsd(u, 'claude-sonnet-5-5'), 2 + 1 + 0.1)
  assert.equal(estimateCostUsd(u, 'gpt-x'), null)
})
// investigationState.test.ts  (cover: automatic turn lifecycle with 2 steps and usage; 'error' session_expired blocks input but keeps text;
//  'http_error' 409 on the automatic turn marks investigated with notice; 'interrupted' keeps partial text; totalUsage accumulates)
```

- [ ] **Step 2: Ejecutar** `node --test src/evidence.test.ts src/pricing.test.ts src/investigationState.test.ts` — FAIL.
- [ ] **Step 3: Implementar los tres módulos.** `parseInline` con un escáner lineal (no regex global anidada) para que `[[` sin cierre quede literal.
- [ ] **Step 4: Ejecutar** — PASS; `npm test` completo PASS.
- [ ] **Step 5: Commit** — `git commit -m "feat(frontend): evidence/markdown parsing, cost estimate and investigation reducer"`

---

### Task 3: Componentes `EvidenceText`, `SessionBar`, `InvestigationPanel`, i18n y CSS

**Files:**
- Create: `frontend/src/components/EvidenceText.tsx`, `SessionBar.tsx`, `InvestigationPanel.tsx`
- Modify: `frontend/src/i18n.ts`, `frontend/src/index.css`

**Interfaces:**
- Consumes: Task 1 (`chatStream`, `getSession`, `patchSession`, `deleteSession`, `ChatHttpError`, `INVESTIGATE_SENTINEL`), Task 2 (`parseBlocks`, `filterApplicability`, `estimateCostUsd`, `reduce`), `compileFilter` knownProtocols = protocolos de `result.packet_list.rows` en minúsculas (como en `PacketList`).
- Produces:
  ```tsx
  // EvidenceText.tsx
  export default function EvidenceText(props: { text: string; knownProtocols: ReadonlySet<string>; onShowPackets(filter: string): void; onSelectPacket(n: number): void }): JSX.Element
    // pkt -> button "#N" (range -> "#N–M" applying filter `frame.number >= N && frame.number <= M`); filter -> [Ver paquetes] when 'local' + [Copiar]; 'copy-only' -> only [Copiar] with title t('investigation.copyOnly')
  // SessionBar.tsx
  export default function SessionBar(props: { expiresAt: number | null; expired: boolean; contentAllowed: boolean; onToggleContent(next: boolean): void; costUsd: number | null; totalTokens: number; onDelete(): void; demo: boolean }): JSX.Element
    // countdown mm:ss updated every second; content switch opens a confirm (window.confirm with t('session.contentWarning')) before enabling
  // InvestigationPanel.tsx
  export default function InvestigationPanel(props: {
    result: AnalysisResult; demo: boolean; demoText?: string; model?: string
    onShowPackets(filter: string): void; onSelectPacket(n: number): void
    onReportText(text: string | null): void           // the automatic report, for the PDF
    onSessionDeleted(): void
  }): JSX.Element
    // mounts -> if result.session && !demo: dispatch start(null) and chatStream(sentinel) (once per session id, useRef)
    // suggestions: up to 3 buttons built from result.issues titles ("¿Por qué …?") shown while no user turn exists
    // input disabled while streaming, when expired/blocked, in demo (shows t('investigation.demoChat')), or when !result.session (t('investigation.unavailable'))
    // every turn renders its steps (collapsible list with label · ms · error/truncated marks), then EvidenceText; limited -> note; interrupted -> [Reenviar]
    // after each 'done': getSession(id) to refresh expires_at/usage
  ```
- i18n (ES/EN) claves nuevas: `investigation.title`, `.subtitle`, `.investigating`, `.steps`, `.ask`, `.placeholder`, `.send`, `.resend`, `.limited`, `.interrupted`, `.alreadyInvestigated`, `.unavailable`, `.demoChat`, `.demoNote`, `.copyOnly`, `.showPackets`, `.copy`, `.copied`, `.suggestion` (`'¿Por qué {title}?'` / `'Why {title}?'`), `.errorInternal`; `session.expiresIn`, `.expired`, `.content`, `.contentWarning`, `.cost` (`'≈ {usd} $ · {tokens} tokens'`), `.costUnknown`, `.delete`, `.deleteConfirm`, `.deleted`. Borrar bloques `diagnosis` y `query`.
- CSS: `.investigation` (reutiliza el fondo `--accent-wash` de `.diagnosis`), `.turn`, `.turn.user`, `.steps` (`<details>`), `.step.error`, `.evidence-btn` (chip pequeño monoespaciado), `.session-bar` (flex, wrap, `--wash`), `.session-bar .expired`, `.chat-input` (textarea + botón), responsive ≤640px en columna.

- [ ] **Step 1: Escribir i18n + CSS + los tres componentes** siguiendo la interfaz. No hay test unitario de React en el repo (sin vitest): la lógica está en los módulos de la Task 2; este paso se verifica en la Task 4 en el navegador.
- [ ] **Step 2: `npx tsc -p tsconfig.app.json --noEmit` y `npm run lint`** — Expected: sin errores (solo los dos avisos `only-export-components` preexistentes).
- [ ] **Step 3: Commit** — `git commit -m "feat(frontend): investigation panel, evidence rendering and session bar"`

---

### Task 4: Integrar en `App.tsx`, retirar `QueryBar`/`DiagnosisPanel`, verificar en el navegador

**Files:**
- Modify: `frontend/src/App.tsx`
- Delete: `frontend/src/components/DiagnosisPanel.tsx`, `frontend/src/components/QueryBar.tsx`
- Modify: `frontend/src/api.ts` (eliminar `diagnose`, `queryFilter`, `QueryResponse`, `DiagnoseResponse` si ya no se usan)

- [ ] **Step 1: Cablear.** En `Dashboard`: quitar `query*`/`diagnosis` y `matchedStreamIds`/`visibleIssues` (los issues vuelven a mostrarse todos; la lista de paquetes recibe `queryFilter={null}`), añadir `reportText` (estado) → `Header diagnosis={reportText}`; `<InvestigationPanel result demo demoText={demo?.investigation[lang]} onShowPackets={showPackets} onSelectPacket={(n) => showPackets(`frame.number == ${n}`)} onReportText={setReportText} onSessionDeleted={() => setResult(null)} />` en el lugar de `QueryBar` (arriba, bajo el `Header`) y eliminar el `DiagnosisPanel` de abajo. Al pulsar «Analizar otra captura» con sesión viva: `deleteSession(result.session.id)` (ignorar errores) antes de `setResult(null)`.
- [ ] **Step 2: Tipos y lint.** `npx tsc -p tsconfig.app.json --noEmit`, `npm run lint`, `npm test` — PASS.
- [ ] **Step 3: Verificación manual en el navegador (modo demo, sin coste).** Arrancar el backend con `LLM_DEMO=1 API_TOKENS=dev-test-token` y `preview_start` `frontend`; subir la captura de ejemplo y comprobar: (a) el informe aparece solo, con 18 viñetas y botones «Ver paquetes»; (b) un clic en `[[filter: tcp.stream eq 1]]` filtra la lista a 2 filas; (c) una pregunta devuelve el aviso de modo demo; (d) la barra de sesión muestra cuenta atrás y coste «—»; (e) activar contenido pide confirmación y hace `PATCH`; (f) «Borrar captura» hace `DELETE` y vuelve a la pantalla de subida; (g) recargar la página con la sesión viva y volver a subir → sesión nueva; forzar 409 (segundo `__investigate__` vía `curl`) muestra `alreadyInvestigated`; (h) móvil 375 px sin desbordes. Capturas de pantalla de (a) y (b) en el mensaje final.
- [ ] **Step 4: Verificación con clave real (solo si el usuario la ha corregido; el backend responde `ai.model` ≠ `demo` en `/health`).** Repetir (a)-(b) con `LLM_DEMO=0`; anotar duración, nº de pasos y tokens del evento `usage` para la Task 7.
- [ ] **Step 5: Commit** — `git commit -m "feat(frontend): investigation panel replaces diagnosis and query bar"`

---

### Task 5: Demo pública con informe pregenerado

**Files:**
- Modify: `scripts/make-demo-data.py`, `frontend/src/demo.ts`, `frontend/src/components/DemoBanner.tsx` (si hace falta texto), `frontend/public/demo/demo.json`

- [ ] **Step 1:** En `make-demo-data.py`, tras `/analyze`, leer `analysis["session"]["id"]`, llamar a `POST /sessions/{id}/chat` con `{"message": "__investigate__", "lang": lang}` para `es` y `en` (la segunda vez devuelve 409: crear una sesión por idioma analizando dos veces, o borrar y re-analizar), concatenar los `delta` de los eventos `text` y guardar `investigation: {es, en}` junto a `diagnosis` (mantener `diagnosis` por compatibilidad). Poner `analysis["session"] = None` en el JSON (la demo no tiene sesión).
- [ ] **Step 2:** `demo.ts`: `DemoData.investigation: Record<Lang, string>`. El panel en demo muestra `demoText` como informe (con botones de evidencia funcionales) y el chat deshabilitado con `investigation.demoChat` + enlace de compra (`BUY_URL`).
- [ ] **Step 3:** `backend/.venv/bin/python scripts/make-demo-data.py` → `demo.json` con `investigation`; comprobar en el navegador `#demo` (build alojado requiere Supabase; en local basta `frontend-hosted` con las variables públicas) que el informe se ve y «Ver paquetes» funciona.
- [ ] **Step 4: Commit** — `git commit -m "feat(demo): pre-generated investigation report in the public demo"`

---

### Task 6: PDF con el informe y sus evidencias

**Files:**
- Modify: `backend/app/report.py`
- Create: `backend/tests/test_report_investigation.py`

**Interfaces:**
- Produces: `report.py` → `_investigation_flowables(text: str, styles) -> List[Flowable]`: `## X`/`### X` → `styles["h2"]`/`styles["h3"]` (añadir `h3` a `_styles`), `- ` → párrafo con viñeta «•», `[[pkt: N]]` → `paquete N`, `[[pkt: N-M]]` → `paquetes N–M`, `[[filter: X]]` → `<font face="Courier">X</font>` (escapado), `**x**` → `<b>`; `_(…)_` → cursiva. `build_report` usa esta función cuando `diagnosis` contiene `## ` y titula la sección «Investigación asistida por IA»; si no, mantiene `_diagnosis_paragraphs` y el título actual.

- [ ] **Step 1: Test que falla**
```python
def test_report_renders_investigation_marks(sample_analysis):
    text = "## Veredicto\nRST a los 5 ms [[pkt: 11]] [[filter: tcp.stream eq 1]].\n\n## Hallazgos\n- uno [[pkt: 10-11]]\n- **dos**"
    pdf = build_report(sample_analysis, text)
    content = _pdf_text(pdf)   # helper: extract text with pypdf if available, else assert on the reportlab story via monkeypatching Paragraph
    assert "Investigación asistida por IA" in content and "paquete 11" in content and "paquetes 10–11" in content
    assert "[[pkt" not in content and "tcp.stream eq 1" in content
```
  (`sample_analysis` = `make_analysis()` de `tests/test_llm.py`; si `pypdf` no está disponible, capturar los `Paragraph` creados con `monkeypatch` sobre `app.report.Paragraph`.)
- [ ] **Step 2: Ejecutar** — FAIL. **Step 3: Implementar.** **Step 4:** `pytest -q backend/tests` PASS.
- [ ] **Step 5: Commit** — `git commit -m "feat(report): investigation report with evidence marks in the PDF"`

---

### Task 7: Documentación, comprobaciones del paquete y release 1.3.0 (se detiene antes de publicar)

**Files:**
- Modify: `QUICKSTART.md` (ES y EN: sección «Investigación con IA», coste medido o estimado, requisito Docker ya existente), `README.md` («Qué incluye el dashboard» + sección de sesiones con cifras reales si la Task 4 paso 4 se pudo hacer), `scripts/verify-bundle.sh` (dos comprobaciones nuevas: `/analyze` devuelve `session.id`; `POST /sessions/{id}/chat` en modo demo responde `200` y `text/event-stream` con un evento `done`), `backend/app/__init__.py` (`__version__ = "1.3.0"`), `frontend/package.json` `version`, `landing.html` + `marketing/linkedin.md` + `PLAN-DIFUSION.md` (texto «investigación con IA que usa herramientas sobre la captura», sin publicar).

- [ ] **Step 1:** Documentación y versión; `scripts/verify-bundle.sh` con las dos comprobaciones (contar: 21).
- [ ] **Step 2:** `scripts/build-release.sh 1.3.0` → `release/pcapanalyzer-1.3.0.tar.gz` verificado (sin secretos, 128+ ficheros); `npm run build` del frontend sin errores; suite backend PASS.
- [ ] **Step 3: Commit** — `git commit -m "release: 1.3.0 — AI investigation agent (docs, bundle checks, version)"`.
- [ ] **Step 4: PARAR.** Presentar al usuario: sha256 del paquete, resumen de cambios de ficha/landing/posts propuestos (sin aplicar), y pedir OK para (a) subir a Gumroad, (b) republicar la landing, (c) push a `origin/main`. Ninguna de las tres se hace sin respuesta explícita.

---

## Self-review

- **Cobertura de la spec:** §4.1 eventos → Task 1; §5.1/5.2 informe y marcas → Task 2 y 3; §5.3 panel, barra de sesión, estados, demo → Tasks 3-5; §5.4 PDF → Task 6; §6 errores (caducada, tope, red, 409) → reducer Task 2 + panel Task 3 + verificación Task 4; §8 pasos 4-6 → Tasks 4-7. Fuera de alcance: nada añadido.
- **Tipos consistentes:** `Usage` de `pricing.ts` es el que usa el reducer; `SessionInfo` de `api.ts` el que consume `SessionBar`; `INVESTIGATE_SENTINEL` exportado desde `api.ts` (único sitio).
- **Review Focus:** 1 → reducer `http_error 409` (Task 2) + manual (Task 4 g); 2 → `filterApplicability` (Task 2) y `EvidenceText` (Task 3); 3 → tests de `parseInline` (Task 2); 4 → parser truncado (Task 1) + manual; 5 → reducer `error session_expired` (Task 2).
- **Proporción:** los componentes React se describen por interfaz y comportamiento, no por código; la lógica con test está en módulos puros.
