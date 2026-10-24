# PcapAnalyzer — Guía de inicio rápido

Gracias por tu compra. PcapAnalyzer analiza capturas de red `.pcap` / `.pcapng`
(también comprimidas con gzip, `.pcap.gz`) y te da un panel con métricas,
conversaciones, tablas de protocolo (HTTP, DNS, TLS), un motor que detecta
problemas automáticamente y un diagnóstico asistido por IA — todo **en tu propia
máquina**. Las capturas se analizan y se descartan; nunca se almacenan ni salen
de tu equipo (salvo el resumen JSON que se envía al modelo de IA si activas la IA
real).

*(English version below.)*

---

## Requisitos

- **Docker** y **Docker Compose** (Docker Desktop en Mac/Windows, o Docker Engine en Linux).
- *(Opcional)* Una clave de API de Anthropic si quieres el diagnóstico con IA real.
  Consíguela en <https://platform.claude.com> → API keys. Sin clave, la app
  funciona igual con un **modo demo** que simula el diagnóstico.

## Arranque en un comando

Descomprime el archivo, entra en la carpeta y ejecuta:

```bash
./start.sh
```

(Mac y Linux. En Windows, ejecútalo desde **Git Bash** o **WSL**; si prefieres no
usar bash, mira «Arranque manual» más abajo.)

El script:

1. comprueba que Docker está instalado;
2. crea el archivo `.env` y genera un **token de acceso aleatorio** (te lo muestra
   **una sola vez** y lo guarda en `.env`, legible solo por ti);
3. arranca la aplicación.

Cuando termine de construir (la primera vez tarda unos minutos), abre
<http://localhost:8080>, **pega el token** en el campo «Token API» (arriba a la
derecha) y sube una captura — o pulsa «Probar con la captura de ejemplo».

- El token se guarda solo en la pestaña del navegador: si abres otra pestaña o
  ventana, vuelve a pegarlo. Para volver a verlo: `grep API_TOKENS .env`.
- Para parar: `Ctrl+C`, o `docker compose down`.
- La aplicación solo escucha en tu propio equipo (`127.0.0.1`). Si quieres
  exponerla en tu red, hazlo detrás de un proxy inverso con autenticación: la API
  puede usar tu cuenta de IA.

### Arranque manual (sin `start.sh`)

```bash
cp .env.example .env
```

Edita `.env` y pon en `API_TOKENS=` una cadena aleatoria de 32 o más caracteres
(por ejemplo, la que genera tu gestor de contraseñas). Después:

```bash
docker compose up --build
```

## Diagnóstico con IA

Por defecto la app arranca en **modo demo**: el diagnóstico y la consulta en
lenguaje natural se generan a partir del propio análisis, sin coste y sin clave, y
aparecen marcados «(modo demo)». Sirve para probar la interfaz y el flujo completo.

Para usar el **modelo de IA real**, edita `.env`:

```
ANTHROPIC_API_KEY=sk-ant-tu-clave-aqui
LLM_DEMO=0
```

y reinicia (`Ctrl+C` y `./start.sh`). **Importante:** mientras `LLM_DEMO=1` el modo
demo tiene prioridad sobre tu clave, así que hay que ponerlo a `0`. Coste
orientativo: cada diagnóstico ~0,05–0,10 € con el modelo por defecto
(`claude-opus-4-8`); puedes usar uno más barato con `LLM_MODEL=claude-haiku-4-5`.

## Ajustes útiles (variables de entorno)

Puedes ponerlas en el `.env` de la raíz:

| Variable | Por defecto | Qué hace |
|---|---|---|
| `API_TOKENS` | *(lo genera `start.sh`)* | Token(s) de acceso, separados por comas |
| `LLM_DEMO` | `1` | `1` = IA simulada; `0` = IA real (necesita clave) |
| `ANTHROPIC_API_KEY` | *(vacío)* | Clave para el diagnóstico con IA real |
| `LLM_MODEL` | `claude-opus-4-8` | Modelo de IA a usar |
| `PCAPANALYZER_PORT` | `8080` | Puerto de la interfaz web |
| `MAX_UPLOAD_MB` | `200` | Tamaño máximo de subida |
| `ANALYZE_WORKERS` | `2` | Análisis en paralelo para capturas grandes |

## Preguntas frecuentes

- **¿Mis capturas salen de mi equipo?** No. El análisis es local. Solo si activas
  la IA real se envía un **resumen JSON** (nunca el pcap crudo) al modelo.
- **¿Necesito saber usar la terminal?** Solo para el arranque. El resto es en el
  navegador.
- **Idioma y tema**: hay un selector claro/oscuro y español/inglés arriba a la derecha.
- **«Se requiere un token Bearer…»**: falta pegar el token en el campo «Token API»
  (arriba a la derecha). Lo tienes en `.env` (`grep API_TOKENS .env`).
- **«Token Bearer inválido»**: el token pegado no coincide con el de `.env`.
- **«La API requiere configuración: define API_TOKENS…»**: `.env` no tiene
  `API_TOKENS`. Ejecuta `./start.sh` (lo genera) o añádelo a mano y reinicia.
- **«La capa IA no está configurada»**: pon `LLM_DEMO=1` (demo) o tu clave con
  `LLM_DEMO=0` en `.env` y reinicia.
- **No abre la web**: la primera vez, el build tarda unos minutos; espera a ver
  `frontend` y `backend` «running» en los logs de Docker y luego recarga.

---

# PcapAnalyzer — Quick start (English)

PcapAnalyzer analyzes `.pcap` / `.pcapng` network captures (gzip-compressed
`.pcap.gz` too) and gives you a dashboard with metrics, conversations, protocol
tables (HTTP, DNS, TLS), an engine that auto-detects problems, and an AI-assisted
diagnosis — all **on your own machine**. Captures are analyzed and discarded,
never stored.

## Requirements

- **Docker** and **Docker Compose**.
- *(Optional)* An Anthropic API key for the real AI diagnosis (get one at
  <https://platform.claude.com>). Without a key, a **demo mode** simulates it.

## One-command start

Unzip the archive, enter the folder and run:

```bash
./start.sh
```

(Mac and Linux. On Windows run it from **Git Bash** or **WSL**; or use the manual
start below.)

The script checks that Docker is installed, creates `.env` with a **random access
token** (shown **once**, stored in `.env` readable only by you) and starts the app.

When the first build finishes (a few minutes), open <http://localhost:8080>,
**paste the token** into the "API token" field (top right) and upload a capture —
or click "Try the sample capture".

- The token lives only in the browser tab: paste it again in a new tab or window.
  To see it again: `grep API_TOKENS .env`.
- Stop with `Ctrl+C` or `docker compose down`.
- The app listens on your own machine only (`127.0.0.1`). To expose it on your
  network, put it behind an authenticated reverse proxy: the API can use your AI
  account.

### Manual start (without `start.sh`)

```bash
cp .env.example .env
```

Edit `.env` and set `API_TOKENS=` to a random string of 32+ characters (your
password manager can generate one). Then:

```bash
docker compose up --build
```

## AI diagnosis

By default the app starts in **demo mode**: the diagnosis and the natural-language
query are generated from the analysis itself, at no cost and with no key, and are
marked "(modo demo)". It is meant for trying the interface and the full flow.

For the **real AI model**, edit `.env`:

```
ANTHROPIC_API_KEY=sk-ant-your-key-here
LLM_DEMO=0
```

and restart (`Ctrl+C`, then `./start.sh`). **Important:** while `LLM_DEMO=1`, demo
mode takes priority over your key, so it must be set to `0`. Roughly ~0.05–0.10 €
per diagnosis with the default model; use `LLM_MODEL=claude-haiku-4-5` for a
cheaper one.

## Troubleshooting

Server error messages are shown in Spanish:

- **"Se requiere un token Bearer…"** (a Bearer token is required) — paste the
  token into the "API token" field (top right). It is in `.env`
  (`grep API_TOKENS .env`).
- **"Token Bearer inválido"** (invalid token) — the pasted token does not match
  the one in `.env`.
- **"La API requiere configuración: define API_TOKENS…"** (API needs setup) —
  `.env` has no `API_TOKENS`. Run `./start.sh` (it creates one) or add it by hand
  and restart.
- **"La capa IA no está configurada"** (AI layer not configured) — set
  `LLM_DEMO=1` (demo) or your key with `LLM_DEMO=0` in `.env` and restart.

---

*Soporte / support: consulta el `README.md` incluido para el detalle técnico de
cada función y para arrancar sin Docker (modo desarrollo).*
