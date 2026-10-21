# PcapAnalyzer — Guía de inicio rápido

Gracias por tu compra. PcapAnalyzer analiza capturas de red `.pcap` / `.pcapng`
y te da un panel con métricas, conversaciones, tablas de protocolo (HTTP, DNS,
TLS), un motor que detecta problemas automáticamente y un diagnóstico asistido
por IA — todo **en tu propia máquina**. Las capturas se analizan y se descartan;
nunca se almacenan ni salen de tu equipo (salvo el resumen JSON que se envía al
modelo de IA si activas esa función).

*(English version below.)*

---

## Requisitos

- **Docker** y **Docker Compose** (Docker Desktop en Mac/Windows, o Docker Engine en Linux).
- *(Opcional)* Una clave de API de Anthropic si quieres el diagnóstico con IA real.
  Consíguela en <https://platform.claude.com> → API keys. Sin clave, la app
  funciona igual con un **modo demo** que simula el diagnóstico.

## Arranque en un comando

Desde la carpeta del proyecto:

```bash
docker compose up --build
```

Abre <http://localhost:8080> en tu navegador. Sube un `.pcap`/`.pcapng` (o pulsa
"Probar con la captura de ejemplo") y listo.

Para pararlo: `Ctrl+C`, o `docker compose down`.

## Activar el diagnóstico con IA (opcional)

Crea un archivo `.env` en la raíz del proyecto (junto a `docker-compose.yml`) con
tu clave:

```
ANTHROPIC_API_KEY=sk-ant-tu-clave-aqui
```

y reinicia (`docker compose up --build`). Docker Compose la inyecta
automáticamente en el backend. Coste orientativo: cada diagnóstico ~0,05–0,10 €
con el modelo por defecto (`claude-opus-4-8`); puedes usar uno más barato con
`LLM_MODEL=claude-haiku-4-5`.

**Sin clave**, deja el `.env` sin `ANTHROPIC_API_KEY` (o no lo crees): la app usa
el modo demo, que genera un diagnóstico simulado a partir del propio análisis.

## Ajustes útiles (variables de entorno)

Puedes ponerlas en el `.env` de la raíz:

| Variable | Por defecto | Qué hace |
|---|---|---|
| `PCAPANALYZER_PORT` | `8080` | Puerto de la interfaz web |
| `ANTHROPIC_API_KEY` | *(vacío)* | Clave para el diagnóstico con IA |
| `LLM_MODEL` | `claude-opus-4-8` | Modelo de IA a usar |
| `MAX_UPLOAD_MB` | `200` | Tamaño máximo de subida |
| `ANALYZE_WORKERS` | `2` | Análisis en paralelo para capturas grandes |

## Preguntas frecuentes

- **¿Mis capturas salen de mi equipo?** No. El análisis es local. Solo si activas
  la IA se envía un **resumen JSON** (nunca el pcap crudo) al modelo.
- **¿Necesito saber usar la terminal?** Solo para el arranque (`docker compose up`).
  El resto es en el navegador.
- **Idioma y tema**: hay un selector claro/oscuro y español/inglés arriba a la derecha.
- **No abre la web**: la primera vez, el build tarda unos minutos; espera a ver
  `frontend` y `backend` "running" en los logs de Docker y luego recarga.

---

# PcapAnalyzer — Quick start (English)

PcapAnalyzer analyzes `.pcap` / `.pcapng` network captures and gives you a
dashboard with metrics, conversations, protocol tables (HTTP, DNS, TLS), an
engine that auto-detects problems, and an AI-assisted diagnosis — all **on your
own machine**. Captures are analyzed and discarded, never stored.

## Requirements

- **Docker** and **Docker Compose**.
- *(Optional)* An Anthropic API key for the real AI diagnosis (get one at
  <https://platform.claude.com>). Without a key, a **demo mode** simulates it.

## One-command start

```bash
docker compose up --build
```

Open <http://localhost:8080>. Upload a `.pcap`/`.pcapng` (or click "Try the
sample capture"). Stop with `Ctrl+C` or `docker compose down`.

## Enable the AI diagnosis (optional)

Create a `.env` file next to `docker-compose.yml`:

```
ANTHROPIC_API_KEY=sk-ant-your-key-here
```

then `docker compose up --build`. Roughly ~0.05–0.10 € per diagnosis with the
default model; use `LLM_MODEL=claude-haiku-4-5` for a cheaper one. Without a key,
the app runs in demo mode.

---

*Soporte / support: consulta el `README.md` incluido para el detalle técnico de
cada función y para arrancar sin Docker (modo desarrollo).*
