# PcapAnalyzer

Analizador web de capturas de red `.pcap` / `.pcapng` (ver [SPEC.md](SPEC.md)): subes una captura y obtienes un dashboard con métricas, conversaciones, problemas detectados automáticamente, diagnóstico asistido por IA e informe PDF exportable. Las cuatro fases del SPEC están completadas: backend FastAPI + `tshark`, frontend React + Recharts, capa IA (Anthropic API) y empaquetado on-premise con Docker Compose.

## Arquitectura

```
wireapp/
├── backend/                  # Fase 1 (actual): API de análisis
│   ├── app/
│   │   ├── main.py           # Capa HTTP (FastAPI): /health, /analyze
│   │   ├── config.py         # Umbrales y configuración vía variables de entorno
│   │   ├── models.py         # Modelos Pydantic = contrato JSON de la API
│   │   ├── tshark.py         # Descubrimiento e invocación de tshark (subprocess + JSON)
│   │   ├── analysis/
│   │   │   └── engine.py     # Motor: una sola pasada sobre los paquetes
│   │   ├── llm/              # Fase 3: capa IA (Anthropic API)
│   │   │   ├── context.py    # Resumen JSON compacto que recibe el modelo
│   │   │   ├── prompts.py    # System prompts + esquema de salida estructurada
│   │   │   ├── service.py    # /diagnose y /query contra la Anthropic API
│   │   │   └── router.py     # Endpoints FastAPI
│   │   └── detectors/        # Un módulo por patrón, interfaz común detect(state)
│   │       ├── tcp_syn_rst.py
│   │       ├── tcp_retransmissions.py
│   │       ├── dns_problems.py
│   │       ├── tcp_zero_window.py
│   │       ├── tls_alerts.py
│   │       ├── mtu_mss.py
│   │       ├── ip_fragmentation.py
│   │       ├── vpn_tunnels.py
│   │       ├── tcp_handshake.py
│   │       ├── dns_errors.py
│   │       └── duplicate_ip.py
│   ├── tests/
│   │   ├── pcap_builder.py   # Genera el pcap sintético de fixtures (sin scapy)
│   │   ├── test_detectors.py # Test unitario por detector (sin tshark)
│   │   └── test_analyze.py   # Tests de integración del endpoint
│   ├── requirements.txt
│   └── requirements-dev.txt
├── docs/mockup.png           # Mockup de referencia del dashboard
└── frontend/                 # Fase 2 (actual): dashboard React + Recharts
    ├── src/api.ts            # Tipos espejo del contrato (models.py) + cliente
    ├── src/format.ts         # Formato es-ES (bytes, duración, números)
    └── src/components/       # UploadScreen, Header, QueryBar, MetricCards,
                              # ProtocolBars, TopTalkers, TrafficChart,
                              # IssuesList, ConversationModal, DiagnosisPanel
```

Decisiones pensadas para las fases siguientes:

- **La capa HTTP es mínima.** Toda la lógica vive en `app.analysis.analyze_pcap()`, una función pura reutilizable desde la capa IA (Fase 3) o un CLI sin pasar por HTTP. El LLM recibirá este JSON resumido, nunca el pcap crudo.
- **`app/models.py` es el contrato.** Los modelos Pydantic definen el JSON que consumirá el frontend React. FastAPI publica el esquema OpenAPI en `/docs`.
- **Detectores enchufables.** Cada patrón es un módulo en `app/detectors/` con la misma interfaz (`detect(state) -> List[Issue]`); añadir uno nuevo = nuevo módulo + registrarlo en `DETECTORS` + (si necesita campos nuevos) añadirlos a `FIELDS` en `tshark.py`.
- **CORS ya configurado** para `localhost:5173` / `localhost:3000` (variable `CORS_ORIGINS`).
- **Dos modos de despliegue**: el modo `token` local conserva estado/cola en proceso y no persiste resultados; el modo `supabase` usa Auth, tenants, cuotas y trabajos en Postgres compartido, con pcaps transitorios en un bucket privado que se borra tras el análisis.

### Por qué tshark por subprocess (y no pyshark)

pyshark envuelve tshark con parsing XML/JSON pesado y es demasiado lento para capturas grandes. Aquí se hace **una única invocación** de `tshark -T ek` (JSON delimitado por líneas) con `-e` para extraer solo los ~25 campos necesarios, y el motor la consume en streaming: una sola pasada y memoria plana independientemente del tamaño de la captura.

## Requisitos

- Python 3.9+
- **tshark** (viene con Wireshark). Comprobación: `tshark --version`
  - macOS: `brew install wireshark` (solo CLI) o `brew install --cask wireshark` (app completa). Si Wireshark.app está instalada manualmente, el backend también encuentra `/Applications/Wireshark.app/Contents/MacOS/tshark`.
  - Debian/Ubuntu: `sudo apt install tshark`
  - Fedora: `sudo dnf install wireshark-cli`
  - Windows: instalador de [wireshark.org](https://www.wireshark.org/download.html)
  - Ruta no estándar: exporta `TSHARK_PATH=/ruta/a/tshark`

La presencia de tshark se comprueba al arrancar (se loguea con claridad si falta) y `GET /health` la expone; sin tshark, `/analyze` responde `503` con las instrucciones de instalación.

## Puesta en marcha

### Beta pública gratuita

Para publicar una beta con frontend en Vercel, autenticación/almacenamiento en
Supabase y API/worker en Render, sigue [DEPLOYMENT.md](DEPLOYMENT.md). Render
asigna una URL gratuita para la API y Vercel un subdominio `vercel.app` para la
web. El plan gratuito de Render puede suspender el backend; es solo para pruebas
beta, no para vender con disponibilidad garantizada.

### Con Docker (variante on-premise, Fase 4)

```bash
export ANTHROPIC_API_KEY=sk-ant-...   # opcional: habilita la capa IA
export API_TOKENS="$(openssl rand -hex 32)" # requerido para usar la API
docker compose up --build
```

Aplicación completa en <http://localhost:8080> (puerto configurable con `PCAPANALYZER_PORT`). Pega el mismo token en el campo **Token API** de la barra superior. El token se mantiene solo en la sesión de esa pestaña. El backend se construye con Python 3.12 + tshark y corre como usuario sin privilegios; nginx sirve el frontend y proxya la API. El puerto del frontend queda ligado a loopback por defecto; antes de exponerlo a una red, configura TLS y un proxy con controles de acceso.

### Modo SaaS multi-tenant con Supabase

Este modo reemplaza los tokens estáticos y la cola local por Supabase Auth (email/contraseña), un espacio de trabajo privado por cuenta, cuotas y trabajos compartidos en Postgres, y capturas transitorias en Supabase Storage. La cola es una tabla PostgreSQL reclamada con `FOR UPDATE SKIP LOCKED`; varias réplicas del worker pueden consumirla. Los resultados viven en Postgres con TTL y un máximo de 20 por tenant.

1. Crea un proyecto Supabase y aplica la migración del repositorio:

   ```bash
   supabase link --project-ref <project-ref>
   supabase db push
   ```

   La migración crea tenants/membresías, tablas de cuota y trabajos con RLS habilitado, un espacio personal al registrarse y el bucket privado `pcap-captures` (límite inicial 200 MB).
2. Copia `.env.example` a `.env`. Configura `AUTH_MODE=supabase`, `SUPABASE_URL`, `SUPABASE_ANON_KEY`, `SUPABASE_SERVICE_ROLE_KEY` y `SUPABASE_DB_URL`. Usa una URI PostgreSQL de Supabase con TLS (`sslmode=require`); no expongas la clave service-role al frontend ni la guardes en Git. `SUPABASE_JWT_SECRET` solo se necesita en proyectos antiguos que aún firman con HS256.
3. En Supabase Auth, habilita email/contraseña y configura las URLs permitidas para el host de la aplicación.
4. Arranca API, frontend y worker:

   ```bash
   docker compose --profile supabase up --build --scale worker=2
   ```

   La UI muestra registro/inicio de sesión y obtiene automáticamente los JWT de usuario. `SUPABASE_ANON_KEY` se publica en el bundle web, como corresponde a una clave anon; la autorización debe seguir protegida por RLS. El backend y los workers usan la clave service-role solo para Storage y una conexión PostgreSQL privada.

Los límites se comparten por tenant: 30 solicitudes/minuto (ventana deslizante; los sondeos de `/jobs/{id}` no consumen cuota), 2 análisis activos, 4 trabajos en espera globales y 1 GiB de capturas pendientes. La cola registra la reserva del trabajo antes de subir el archivo; las cargas incompletas vencen a los 15 minutos para que el worker pueda limpiar sus objetos. La copia local se borra tras subirla a Storage; el worker elimina el objeto al completar o fallar el análisis. Si la limpieza falla, el worker la reintenta. Mantén `MAX_UPLOAD_MB` alineado con el límite del bucket.

El onboarding actual crea un espacio personal automáticamente. El esquema admite varias membresías, pero la UI aún no incluye invitaciones, cambio de workspace ni administración de miembros. El modo `token` sigue disponible para demos/on-premise de una sola instancia; sus cuotas y cola son locales y no deben usarse para aislar un SaaS.

### En local (desarrollo)

Backend (puerto 8000):

```bash
cd backend
python3 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
export API_TOKENS="$(openssl rand -hex 32)"
.venv/bin/uvicorn app.main:app --reload
```

API docs interactivas en <http://127.0.0.1:8000/docs>.

Frontend (puerto 5173, requiere Node 20+ y el backend arrancado):

```bash
cd frontend
npm install
npm run dev
```

Dashboard en <http://localhost:5173>. En modo `token`, introduce en **Token API** el mismo token configurado en el backend. En modo Supabase, copia `frontend/.env.example` a `frontend/.env` y configura URL + anon key para mostrar registro/inicio de sesión. El dev server de Vite proxya las rutas al backend; para otro despliegue, define `VITE_API_URL`. La pantalla de subida acepta drag&drop e incluye un botón **"Probar con la captura de ejemplo"** (sirve `frontend/public/sample.pcap`, copia del fixture de tests).

Para ver la web mientras desarrollas, deja backend y Vite ejecutándose y abre <http://127.0.0.1:5173/>. El despliegue Docker sirve la UI en <http://localhost:8080/>.

### Qué incluye el dashboard (Fase 2)

- Cabecera con metadatos del archivo y, debajo, el **panel de investigación con IA** (informe automático en streaming, chat de seguimiento, barra de sesión con cuenta atrás, interruptor de contenido, coste aproximado y borrado).
- Tarjetas de métricas: paquetes, duración, conversaciones y problemas detectados.
- Distribución de protocolos (barras horizontales) y top talkers con marca ⚠ en hosts implicados en issues, más túneles VPN detectados.
- Gráfico temporal (Recharts): paquetes/s en azul y retransmisiones/s en rojo, con tooltip. La serie se mantiene dispersa para evitar crear un punto por cada segundo de capturas largas.
- **Lista de paquetes estilo Wireshark** (nº, tiempo, origen, destino, protocolo, longitud e info) con **filtros de visualización estilo Wireshark** (subconjunto del lenguaje real evaluado en el navegador: `ip.addr == 10.0.0.0/8 && tcp.port in {80 443}`, `tcp.analysis.retransmission || tcp.flags.reset`, `_ws.col.info contains "SYN"`, `!`, `and/or/not`…; el filtro avisa de la posición del error y, si el texto no parece un filtro, se busca como texto libre), filtros rápidos con contadores (con problemas, retransmisiones, ACK duplicados, RST, ventana 0/llena, ICMP, DNS, experto), chips por protocolo, **colores** al estilo de las reglas de Wireshark, formatos de hora (desde el inicio, delta, UTC), **resolución de nombres** aprendida de las respuestas DNS de la captura, exportación a CSV (a prueba de inyección de fórmulas), panel de detalle del paquete (flags, seq/ack, ventana, TTL, RTT del ACK, análisis TCP e información experta) con «usar como filtro» / copiar, y columnas ordenables. Los issues y las conversaciones ofrecen «Ver paquetes» y «Copiar filtro Wireshark», y hay una tarjeta de **Información experta** (lo que Wireshark marca como anómalo, agrupado por mensaje). La lista está limitada a los primeros `PACKET_LIST_MAX` (1000) paquetes: los filtros solo ven esas filas, porque la captura se descarta tras el análisis.
- **Tabla de consultas DNS** con el desenlace de cada consulta (OK / lenta / sin respuesta / SERVFAIL / NXDOMAIN) y su latencia.
- **Tabla de peticiones HTTP** (método, host+URI y código de respuesta emparejado por stream, o "Sin respuesta").
- **Propiedades de la captura** (primer/último paquete, tamaño medio, tasas) al estilo *Capture File Properties* de Wireshark.
- **Tiempos de respuesta de servicio (SRT)**: latencia mín/media/máx por protocolo (DNS, handshake TCP, HTTP).
- **Sesiones TLS**: versión, cipher, SNI y alerta por stream. Todo esto también aparece en el informe PDF.
- Lista de problemas con badges de severidad (Crítico/Aviso/Info).
- Drill-down: clic en un issue con conversación asociada o en un top talker abre el detalle de la conversación TCP (bytes por sentido, retransmisiones, MSS, RTT de handshake, eventos window 0 e issues relacionados), con un **diagrama de flujo** (ladder diagram estilo Wireshark) del intercambio de paquetes entre los dos extremos.
- Las marcas de evidencia del informe (`[[pkt: N]]`, `[[filter: …]]`) se muestran como botones: «Ver paquetes» aplica el filtro en la lista local y un número de paquete salta a su fila; si el filtro usa campos que la lista no conoce, se ofrece solo copiarlo para Wireshark.
- **Cobertura OSI explícita**: una matriz explica las señales detectables y las limitaciones de cada capa, incluida la imposibilidad de inferir estado físico de capa 1 únicamente desde un pcap.
- Aviso visible cuando un límite de memoria recorta secciones del análisis.
- **Modo claro/oscuro e idioma (ES/EN)** con toggles en la barra de configuración (arriba a la derecha); la preferencia se guarda en el navegador. En inglés, el diagnóstico y las consultas de IA también responden en inglés. Nota: el texto de los problemas autodetectados lo generan los detectores del backend y por ahora se muestra siempre en español.
- **Recuperación de errores de UI**: un error inesperado de render muestra un aviso recargable en vez de dejar la página en blanco.

### Capa IA (Fase 3)

La interfaz usa la investigación interactiva (sección siguiente). Siguen disponibles dos endpoints más simples que envían a la Anthropic API **solo el resumen JSON del análisis** (recortado a un máximo de issues/conversaciones), **nunca la captura**. El resumen sí puede incluir IPs, nombres de host, DNS y el nombre del archivo. No actives la IA externa sin autorización para compartir esos metadatos; la captura puede contener información sensible.

- `POST /diagnose` — diagnóstico narrativo: *qué está pasando, causa probable y siguiente paso recomendado* (ya no se usa desde la interfaz; lo sustituye la investigación).
- `POST /query` — traduce una pregunta en lenguaje natural ("conexiones fallidas hacia el servidor de correo") a un **display filter de Wireshark**, con explicación y la lista de conversaciones/issues relacionadas que existen en los datos analizados. Tampoco se usa desde la interfaz desde la 1.3.0; se mantiene para integraciones.

**Configurar la capa IA** — dos opciones:

1. **IA real**: copia `backend/.env.example` a `backend/.env`, pega tu clave en `ANTHROPIC_API_KEY` y reinicia el backend (el `.env` se carga automáticamente y está en `.gitignore`). Con Docker Compose basta un `.env` en la raíz del proyecto con la misma variable.
2. **Modo demo** (`LLM_DEMO=1` en el `.env`): respuestas simuladas generadas desde el propio análisis, sin llamar a la API — sin coste ni credenciales. El diagnóstico y las explicaciones se marcan como "(modo demo)".

Sin credenciales ni modo demo, `GET /health` lo indica (`ai.available: false`) y los endpoints devuelven `503` con instrucciones; el resto de la aplicación funciona con normalidad. Variables: `LLM_MODEL` (por defecto `claude-opus-5-5`), `LLM_MAX_TOKENS` (4096), `LLM_TIMEOUT_S` (120), `LLM_DEMO`. Los strings procedentes de la captura se tratan como datos no confiables también en los prompts.

### Investigación con IA (sesiones)

Tras analizar una captura, el backend la conserva **cifrada en disco local** durante
`SESSION_TTL_MINUTES` (60) de inactividad para que la IA pueda investigarla de verdad: en
vez de leer un resumen, el modelo dispone de seis herramientas que el backend ejecuta sobre
el pcap con tshark (`capture_overview`, `filter_packets` con filtros reales de Wireshark,
`stream_detail` con RTT/huecos/retransmisiones por flujo, `statistics` sobre `tshark -z`,
`follow_stream` y `protocol_reference`). Al abrir la captura la IA hace una investigación
automática y entrega un informe con evidencia (`[[pkt: N]]`, `[[filter: …]]`); después se
pueden hacer preguntas de seguimiento por `POST /sessions/{id}/chat` (SSE).

- **Filtros sobre toda la captura**: `POST /sessions/{id}/packets` con
  `{"filter": "<display filter>", "limit": 1000, "offset": 0}` aplica un filtro real de
  Wireshark con tshark a la captura conservada y devuelve filas con la misma forma que
  `packet_list`. La lista del análisis solo contiene los primeros `PACKET_LIST_MAX` (1000)
  paquetes; con esto la interfaz abre la evidencia de cualquier paquete («Buscar en toda la
  captura», Intro en el filtro y los botones «Ver paquetes»). Solo cabeceras y metadatos.
  Límites: `PACKET_QUERY_WORKERS` (2) búsquedas simultáneas (429), `PACKET_QUERY_TIMEOUT_S`
  (60, 504), filtro validado por tshark (422).
- La clave de cifrado vive solo en memoria: al reiniciar, los archivos huérfanos quedan
  ilegibles y se borran. `DELETE /sessions/{id}` borra la captura al momento; también lo hace
  «Analizar otra captura» en la interfaz.
- **Contenido de los paquetes**: por defecto la IA solo ve cabeceras y metadatos. El
  interruptor por sesión (`PATCH /sessions/{id}` con `content_allowed: true`) habilita
  `follow_stream` y los campos de payload, con credenciales enmascaradas. Lo que devuelven las
  herramientas viaja a la API de Anthropic; el pcap nunca.
- **Topes duros**: `AGENT_MAX_TOOL_CALLS` (25) y `AGENT_MAX_MODEL_CALLS` (20) por pregunta,
  `AGENT_TASK_BUDGET_TOKENS` (60 000) por pregunta, `SESSION_MAX_TOKENS` (2 M) por sesión,
  `LLM_MAX_CALLS_PER_DAY` / `_GLOBAL` (cuentan preguntas), `AGENT_WORKERS` (2) investigaciones
  simultáneas, `TOOL_TIMEOUT_S` (30) y `TOOL_MAX_ROWS` (200) por herramienta. Otras:
  `SESSIONS_ENABLED`, `SESSION_DIR`, `MAX_SESSIONS` (20), `MAX_SESSION_BYTES` (2 GiB),
  `TOOL_MAX_OUTPUT_BYTES`, `AGENT_EFFORT` (`high`), `AGENT_COMPACT_TOKENS`.
- En modo cola compartida (Supabase) el análisis corre en otro proceso y **no** se crean
  sesiones (`session: null`); la investigación interactiva es una función del self-hosted.
- Sin clave (`LLM_DEMO=1`) el informe inicial es texto determinista con la evidencia de los
  detectores y el chat indica cómo activar la IA.
- Coste: lo paga la clave del propietario. Estimación con `claude-opus-5-5` (4 $/M entrada,
  20 $/M salida, caché 0,20 $/M): investigación inicial 0,20-0,80 €, pregunta de seguimiento
  0,05-0,25 €. Pendiente de confirmar con mediciones reales; el evento `usage` del chat
  devuelve los tokens exactos de cada pregunta.

### Informe PDF y capturas grandes (Fase 4)

- `POST /report` — genera un **informe PDF en español** (resumen, problemas con severidad, diagnóstico IA si se generó, protocolos, top talkers, conversaciones, túneles) listo para entregar a un cliente. En la UI: botón "⇩ Exportar informe" de la cabecera.
- `POST /analyze/async` + `GET /jobs/{id}` — análisis en segundo plano para capturas grandes; la UI lo usa automáticamente para archivos de más de 20 MB. En modo `token`, se ejecuta en un pool local; en modo Supabase, el estado y el worker se comparten mediante Postgres/Storage.

### Autenticación, cuotas y límites (modo `token`)

En modo Supabase, la UI usa Supabase Auth y la API verifica los JWT contra las claves públicas del proyecto. La membresía activa determina el tenant; se usa una cuota deslizante compartida y los trabajos se consultan por tenant. La clave service-role nunca se envía al navegador. Los detalles de despliegue están en «Modo SaaS multi-tenant con Supabase».

Todos los endpoints excepto `GET /health` requieren `Authorization: Bearer <token>`. Configura `API_TOKENS` con uno o varios tokens de alta entropía separados por comas; no los guardes en el repositorio. La interfaz los envía en las peticiones y los conserva únicamente en `sessionStorage` de la pestaña. Los trabajos asíncronos solo son visibles para el token que los creó.

Cuotas predeterminadas por token: 30 solicitudes/minuto para operaciones de análisis, IA e informes (las consultas de estado del trabajo no consumen esa cuota) y hasta 2 análisis concurrentes. La cola global admite hasta 4 trabajos en espera, con hasta 1 GiB combinado de capturas pendientes, y rechaza nuevas solicitudes con `429` cuando se llena. Se conservan como máximo 20 resultados asíncronos (`MAX_RETAINED_JOBS`). `MAX_UPLOAD_MB` limita la subida comprimida y `MAX_DECOMPRESSED_MB` limita el tamaño expandido de archivos gzip.

El motor aplica límites por sección (`MAX_CONVERSATIONS`, `MAX_TRACKED_TALKERS`, `MAX_TIME_SERIES_BUCKETS`, `MAX_DNS_TRANSACTIONS`, `MAX_HTTP_REQUESTS`, `MAX_TLS_SESSIONS`, `MAX_TLS_ALERTS`, `MAX_FRAGMENT_GROUPS`, `MAX_DHCP_TRANSACTIONS`, `MAX_ARP_CLAIMS`, `MAX_ARP_STORM_SENDERS`, `MAX_ARP_STORM_TARGETS` y `MAX_ISSUES`). Si alcanza uno, `meta.truncated_sections` lo identifica y el dashboard avisa que esos resultados son parciales. Estos topes de memoria siguen configurados por proceso; Supabase comparte identidad, cuotas de API, acceso a trabajos, almacenamiento temporal y cola de análisis entre réplicas.

## Uso

```bash
curl -s -H "Authorization: Bearer $API_TOKENS" \
  -F "file=@captura.pcap" http://127.0.0.1:8000/analyze | jq .
```

### Respuesta (resumen del esquema)

```jsonc
{
  "file":     { "name": "captura.pcap", "size_bytes": 1570 },
  "summary":  { "packets": 20, "bytes": 1570, "duration_seconds": 5.0,
                "conversations": 6, "avg_packets_per_second": 4.0, ... },
  "protocols": [ { "protocol": "tcp", "packets": 12, "bytes": 900,
                   "packet_pct": 60.0, "bytes_pct": 57.3 }, ... ],
  "time_series": [ { "t": 0, "packets": 8, "bytes": 830, "retransmissions": 2 }, ... ],
  "conversations": {
    "tcp": [ { "stream_id": 0, "src": "10.0.0.1", "src_port": 34567,
               "dst": "10.0.0.2", "dst_port": 80, "packets": 8, "bytes": 830,
               "retransmissions": 2, "retransmission_pct": 25.0,
               "zero_window_events": 1, ... } ],
    "udp": [ ... ],
    "top_talkers": [ { "address": "10.0.0.1", "bytes_sent": 1006,
                       "bytes_received": 480, "bytes_total": 1486, ... } ]
  },
  "tunnels": [ { "type": "esp", "peer_a": "10.0.0.1", "peer_b": "10.0.0.6",
                 "packets": 4, "packets_a_to_b": 4, "packets_b_to_a": 0,
                 "bytes": 328, "bytes_a_to_b": 328, "bytes_b_to_a": 0,
                 "duration_s": 3.0, "max_idle_s": 1.0, "handshakes": 0 } ],
  "issues": [
    { "id": "tcp-syn-rst-1", "type": "tcp_syn_rst", "severity": "critical",
      "title": "SYN respondido con RST inmediato",
      "detail": "...", "conversation": "10.0.0.1:34568 <-> 10.0.0.3:8443",
      "evidence": { "syn_to_rst_ms": 5.0, "dst_port": 8443 } }
  ],
  "meta": { "engine_version": "0.1.0", "tshark_version": "TShark ... 4.6.6",
            "analysis_duration_ms": 150 }
}
```

`time_series` es dispersa (solo segundos con tráfico); `t` es el offset en segundos desde el inicio de la captura. Las conversaciones TCP incluyen además `mss_client`, `mss_server` y `handshake_rtt_ms`. `tunnels` identifica pasivamente tráfico VPN/túnel: ESP, IKE/ISAKMP, WireGuard, OpenVPN, GRE, L2TP y Teredo, con bytes por sentido, duración, el mayor tiempo sin tráfico y los handshakes completados (inicio de IKE, WireGuard y OpenVPN).

### Detectores (`issues`)

| Tipo | Detección | Severidad |
|---|---|---|
| `tcp_syn_rst` | SYN respondido con RST sin SYN-ACK en < 1 s → firewall / puerto cerrado | `critical` |
| `tcp_retransmissions` | % de retransmisiones por conversación (`tcp.analysis.retransmission` + fast/spurious) | `critical` > 2 %, `warning` > 1 % |
| `dns_unanswered` | No se observó respuesta DNS dentro del intervalo capturado; puede ser un límite de captura | `warning` |
| `dns_slow` | Respuesta DNS con latencia > 500 ms | `warning` |
| `tcp_zero_window` | ≥ 3 anuncios de ventana TCP 0; evidencia de presión de recepción, no prueba por sí sola saturación sostenida | `warning` |
| `tls_handshake_failure` | Alerta TLS `handshake_failure` (código 40) | `warning` |
| `tls_alert` | Otras alertas TLS fatales (bad_certificate, unknown_ca, …) | `warning` |
| `ip_duplicate` | Una IP aparece como origen ARP desde ≥ 2 MACs; también puede ser proxy ARP o segmentos distintos | `warning` |
| `arp_storm` | ≥ `ARP_STORM_RATE_PER_S` (20) peticiones ARP por segundo durante ≥ `ARP_STORM_MIN_SECONDS` (3) segundos; indica quién pregunta y cuántas direcciones distintas | `warning` |
| `port_scan` | Un origen prueba ≥ `SCAN_MIN_PORTS` (20) puertos de un equipo o un puerto en ≥ `SCAN_MIN_HOSTS` (20) equipos y como mucho el `SCAN_MAX_ANSWERED_PCT` (50 %) responde con SYN-ACK | `warning` |
| `cleartext_credentials` | Inicio de sesión sin cifrar (FTP `PASS`, POP3 `PASS`, IMAP `LOGIN`, SMTP `AUTH`, HTTP Basic). Solo informa del protocolo, el servidor y el número de logins: nunca guarda ni muestra usuario o contraseña | `warning` |
| `insecure_protocol` | Telnet, SMBv1 sobre TCP o SNMP v1/v2c en uso (los anuncios NetBIOS por UDP 138 no cuentan) | `warning` |
| `arp_spoofing` | Una MAC reclama ≥ `ARP_SPOOF_MIN_IPS` (2) IPs y otra MAC también reclama alguna de ellas (envenenamiento ARP; también puede ser VRRP/HSRP) | `critical` |
| `ip_fragment_overlap` | Fragmentos IP que se solapan con datos distintos (`ip.fragment.overlap.conflict`): teardrop, evasión de IDS o pila rota | `critical` |
| `ike_no_response` | ≥ 2 mensajes IKE sin respuesta observada; una captura parcial o asimétrica puede ocultarla | `warning` |
| `ike_handshake_incomplete` | IKE bidireccional pero sin tráfico ESP posterior entre esos peers | `warning` |
| `esp_one_way` | ESP en un solo sentido (≥ `ESP_ONE_WAY_MIN`, 3 paquetes) → túnel roto | `warning` |
| `tunnel_one_way` | WireGuard, OpenVPN, GRE, L2TP o Teredo en un solo sentido (≥ 3 paquetes) | `warning` |
| `tunnel_handshake_no_response` | ≥ `TUNNEL_HANDSHAKE_NO_RESPONSE_MIN` (2) inicios de handshake WireGuard/OpenVPN sin respuesta: puerto filtrado, peer caído o clave desconocida | `warning` |
| `tunnel_renegotiation` | ≥ `TUNNEL_RENEGOTIATION_MIN` (4) handshakes completados en un túnel, uno cada menos de `TUNNEL_RENEGOTIATION_MAX_INTERVAL_S` (60 s) de media: el túnel se cae y vuelve | `warning` |
| `ip_fragments_incomplete` | Se vio fragmento inicial sin fragmento final; alerta de visibilidad incompleta, no prueba pérdida | `warning` |
| `ip_fragmentation_high` | > 5 % de los paquetes son fragmentos IP | `warning` |
| `icmp_frag_needed` | ICMP Fragmentation Needed / ICMPv6 Packet Too Big (MTU del camino) | `warning` |
| `pmtud_blackhole` | ≥ 3 retransmisiones de segmentos tamaño-MSS sin ningún ICMP frag-needed → PMTUD roto | `warning` |
| `mss_low` | MSS negociado < 1300 bytes (overhead de túnel/VPN en el camino) | `info` |
| `tcp_slow_handshake` | SYN → SYN-ACK > 500 ms (latencia alta o servidor saturado) | `warning` |
| `dns_servfail` | Respuestas SERVFAIL de un servidor DNS | `warning` |
| `dns_nxdomain` | Ráfaga de ≥ 3 NXDOMAIN hacia un mismo cliente (sufijo mal configurado / DGA) | `warning` |
| `tcp_dup_acks` | ≥ 5 ACK duplicados en una conversación (`tcp.analysis.duplicate_ack`); señal de pérdida o reordenamiento | `warning` |
| `tcp_out_of_order` | ≥ 5 segmentos fuera de orden; `warning` si ≥ 5 % de los paquetes (balanceo asimétrico / multipath) | `info` / `warning` |
| `tcp_lost_segments` | «Previous segment not captured»; `warning` si hay ACK duplicados o retransmisiones (pérdida confirmada), `info` si puede ser límite de la captura | `info` / `warning` |
| `tcp_window_full` | ≥ 3 veces el emisor llenó la ventana del receptor (`tcp.analysis.window_full`) | `warning` |
| `tcp_resets` | RST **después** de un handshake completo, agregados; `warning` si afecta a ≥ 10 conversaciones | `info` / `warning` |
| `icmp_unreachable` | ICMP/ICMPv6 destino inalcanzable por reportador y código (puerto, host, red, prohibido por administración) | `warning` |
| `icmp_ttl_exceeded` | ≥ 5 «TTL exceeded» (bucle de enrutamiento) o reensamblado agotado | `warning` |
| `http_server_errors` | Respuestas HTTP 5xx por servidor; `critical` si son ≥ 50 % de ≥ 5 respuestas | `warning` / `critical` |
| `http_client_errors` | ≥ 5 respuestas HTTP 4xx por servidor (401 y 407 no cuentan: son el reto de autenticación) | `info` / `warning` |
| `http_slow` | Respuestas HTTP que tardan > 1 s desde la petición (`http.time`) | `warning` |
| `dhcp_nak` | El servidor DHCP rechaza la petición (NAK) | `warning` |
| `dhcp_declined` | El cliente rechaza la IP ofrecida (DECLINE): dirección ya en uso | `warning` |
| `dhcp_no_response` | DISCOVER o REQUEST sin OFFER, ACK ni NAK | `warning` |
| `tls_legacy_version` | El servidor negocia SSL 3.0, TLS 1.0 o TLS 1.1 (versión del ServerHello), por servidor | `warning` |

### Calidad de la captura (`capture_quality`)

Antes de leer los problemas hay que saber cuánto fiarse de la captura. El resultado incluye un
bloque `capture_quality` con un veredicto (`good`, `fair`, `poor`) y notas sobre los límites de
la propia captura, que la interfaz muestra encima de los hallazgos y que también reciben el
agente de IA y el PDF:

| Nota | Qué detecta | Efecto |
|---|---|---|
| `duplicate_frames` | Tramas idénticas a otra vista hace menos de 1 ms (port mirror que copia entrada y salida, captura en varias interfaces) | Se dejan fuera del análisis: no cuentan como retransmisiones ni ACK duplicados. Siguen en los totales y en la lista, atenuadas |
| `one_way` | Conversaciones TCP donde un lado confirma datos que no están en la captura | Si son mayoría, los avisos de tipo «sin respuesta» (`dns_unanswered`, `ike_no_response`, `esp_one_way`, `tunnel_one_way`, `tunnel_handshake_no_response`, `dhcp_no_response`) bajan a `info` con una advertencia |
| `truncated_frames` | Tramas recortadas por el límite de bytes por paquete (snaplen) | Aviso: HTTP, TLS o DNS pueden salir incompletos |
| `midstream` | Conexiones ya abiertas al empezar la captura | Aviso: sin MSS, escalado de ventana ni tiempo de establecimiento |
| `malformed_packets` | Paquetes con campos ilegibles | Se omiten y se cuentan; el análisis continúa |

Umbrales: `DUP_FRAME_WINDOW_S`, `QUALITY_DUP_WARN_PCT`, `QUALITY_ONE_WAY_WARN_PCT`,
`QUALITY_ONE_WAY_INFO_PCT`, `QUALITY_MIDSTREAM_INFO_PCT`.

Umbrales configurables por entorno (`app/config.py`, nada hardcodeado): `RETRANS_WARN_PCT`, `RETRANS_CRIT_PCT`, `RETRANS_MIN_PACKETS`, `SYN_RST_MAX_DELAY_S`, `DNS_SLOW_THRESHOLD_S`, `DNS_NXDOMAIN_MIN`, `TCP_HANDSHAKE_SLOW_S`, `TCP_ZERO_WINDOW_MIN_EVENTS`, `MSS_LOW_THRESHOLD`, `PMTUD_MIN_FULLSIZE_RETRANS`, `FRAG_HIGH_PCT`, `ESP_ONE_WAY_MIN`, `IKE_NO_RESPONSE_MIN`, `TCP_DUP_ACK_MIN`, `TCP_OUT_OF_ORDER_MIN`, `TCP_LOST_SEGMENT_MIN`, `TCP_WINDOW_FULL_MIN`, `TCP_RESET_MIN_CONVS`, `ICMP_UNREACHABLE_MIN`, `ICMP_TTL_EXCEEDED_MIN`. Otras variables: `API_TOKENS`, `API_MAX_REQUESTS_PER_MINUTE`, `API_MAX_JOBS_PER_TOKEN`, `MAX_QUEUED_JOBS`, `MAX_UPLOAD_MB`, `MAX_DECOMPRESSED_MB`, `TSHARK_TIMEOUT_S`, `TSHARK_PATH`, `CORS_ORIGINS`, `TOP_TALKERS_LIMIT`.

### Qué diagnostica por capa OSI

| Capa | Alcance real del análisis |
|---|---|
| 1 · Física | No inferible solo desde un pcap: no hay señal, cable, óptica ni contadores del puerto. |
| 2 · Enlace | Visibilidad ARP; anuncios desde varias MAC son una pista, no prueba de conflicto sin VLAN/topología. |
| 3 · Red | IPv4, fragmentación, ICMP y avisos de MTU observados. No reconstruye necesariamente todas las rutas ni cubre todos los casos IPv6. |
| 4 · Transporte | Cobertura principal: handshakes/RST/retransmisiones/ventana TCP y conversaciones TCP/UDP visibles. |
| 5 · Sesión | Señales derivadas de transporte; no existe diagnóstico OSI independiente para esta capa. |
| 6 · Presentación | Metadatos y alertas TLS visibles; el contenido cifrado no se interpreta sin claves. |
| 7 · Aplicación | Subconjuntos de DNS, DHCP y HTTP; no se inspeccionan todas las aplicaciones ni sus estados internos. |

Toda conclusión está limitada al punto, interfaz, intervalo y contenido que realmente capturó el archivo. La ausencia de una respuesta no prueba que el servidor no respondiera si quedó fuera de la captura.

### Errores

| Código | Causa |
|---|---|
| `400` | El archivo no es un pcap/pcapng (magic number) o está vacío |
| `401` | Falta el token Bearer o no es válido |
| `413` | Supera `MAX_UPLOAD_MB` o `MAX_DECOMPRESSED_MB` |
| `429` | Cuota por token o capacidad de la cola alcanzada |
| `422` | tshark no pudo procesar el archivo |
| `503` | `API_TOKENS` no está configurado o tshark no está instalado |
| `504` | El análisis excedió `TSHARK_TIMEOUT_S` |

## Tests

```bash
cd backend
.venv/bin/python -m pytest tests/ -v
```

- `test_detectors.py`: un test unitario por detector sobre estados sintéticos (no requiere tshark).
- `test_analyze.py`: integración del endpoint contra `tests/fixtures/sample.pcap`, regenerado de forma determinista en cada ejecución por [pcap_builder.py](backend/tests/pcap_builder.py) (paquetes crafteados a mano, sin scapy). El fixture contiene deliberadamente: retransmisiones TCP (25 % de un stream), un SYN→RST inmediato, un zero window, un handshake TLS que termina en `handshake_failure`, consultas DNS rápida / lenta (700 ms) / sin respuesta, un stream con MSS 1240 y agujero negro PMTUD, un handshake de 600 ms, un ICMP Fragmentation Needed, un datagrama fragmentado completo y otro incompleto, ESP unidireccional, IKE sin respuesta e IKE sin ESP posterior, un SERVFAIL, tres NXDOMAIN y una IP duplicada anunciada por dos MACs. Estos tests se saltan automáticamente si tshark no está instalado.

- `test_capture_quality.py`: robustez ante capturas malformadas y calidad de la captura
  (tráfico sano duplicado por un mirror, captura unidireccional, snaplen, conexiones ya abiertas).
- `test_packet_query.py`: filtros reales sobre toda la captura (`/sessions/{id}/packets`).
- `test_detectors_l7.py`: detectores de HTTP, DHCP y TLS obsoleto.

Seguridad: nunca se loguean payloads, el archivo subido se borra tras el análisis (o, con sesiones de investigación, se conserva cifrado con una clave que solo vive en memoria y se borra por inactividad), hay límite de tamaño de subida y los strings extraídos de la captura (p. ej. nombres DNS) se sanean antes de incluirse en la respuesta.

## Roadmap

- **Fase 1:** backend de análisis con tshark ✔
- **Fase 2:** frontend React + Recharts según `docs/mockup.png` ✔
- **Fase 3:** capa IA — diagnóstico narrativo y lenguaje natural → display filter ✔
- **Fase 4:** Docker Compose (on-premise), informe PDF exportable y cola async para capturas grandes ✔

Ideas post-MVP: multiusuario/planes (freemium B2B), descifrado TLS con claves del usuario, persistencia opcional de análisis, workers externos (Redis/RQ) si la cola en proceso se queda corta.

## Licencia

Código fuente: https://github.com/sebaandrada-cell/PcapAnalyzer

PcapAnalyzer es software libre bajo la [licencia Apache 2.0](LICENSE): puedes usarlo,
modificarlo y redistribuirlo, también en tu empresa, conservando el aviso de
copyright y el archivo [NOTICE](NOTICE). tshark/Wireshark (GPL) se ejecuta como un
programa aparte y no se distribuye con PcapAnalyzer.
