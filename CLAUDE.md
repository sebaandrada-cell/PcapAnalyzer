# PcapAnalyzer

Analizador web de archivos .pcap/.pcapng con dashboard y troubleshooting asistido por IA.
Producto SaaS orientado a MSPs, sysadmins generalistas y NOC de primer nivel.
El objetivo comercial es un freemium B2B; la privacidad es un pilar (opción de
procesamiento local/on-premise como diferenciador frente a competidores cloud-only).

## Stack y decisiones de arquitectura

- **Backend**: Python 3.12 + FastAPI.
- **Parsing de pcaps**: `tshark` vía `subprocess` con salida JSON (`-T json` / `-T ek`).
  NO usar pyshark para el análisis principal (demasiado lento en capturas grandes).
  Verificar la presencia de tshark al arrancar y fallar con mensaje claro si no está.
- **Frontend**: React + Recharts (se añadirá en Fase 2; ver SPEC.md).
- **Capa IA**: Anthropic API (Fase 3). El LLM recibe un resumen JSON estructurado
  de la captura, nunca el pcap crudo.
- **Sin base de datos en Fase 1**: el análisis es stateless (subes pcap → JSON).

## Convenciones

- Código y comentarios en inglés; documentación de usuario en español.
- Type hints obligatorios; validación con Pydantic en todos los endpoints.
- Tests con pytest; cada detector de problemas tiene su test con un pcap sintético
  o fixture JSON (no versionar pcaps grandes en el repo; usar `tests/fixtures/`).
- Los detectores de problemas viven en `app/detectors/`, un módulo por patrón,
  todos implementando la misma interfaz (entrada: datos parseados; salida: lista
  de `Issue` con `severity`, `title`, `detail`, `evidence`).
- Umbrales de detección configurables en `app/config.py`, nunca hardcodeados.

## Motor de detección (Fase 1)

Patrones que el motor debe detectar, con severidad:

1. **SYN → RST inmediato** (crítico): patrón de bloqueo por firewall.
2. **Retransmisiones TCP > 2%** por conversación (crítico).
3. **DNS sin respuesta o con latencia > 500 ms** (aviso).
4. **TCP window size = 0** sostenido (aviso): receptor saturado.
5. **TLS handshake_failure / alertas fatales** (aviso).

## Seguridad

- Los pcaps pueden contener credenciales y datos sensibles: nunca loguear
  payloads, borrar el archivo subido tras el análisis, límite de tamaño de subida.
- Sanitizar cualquier string del pcap antes de renderizarlo (nombres de host,
  queries DNS) — son datos no confiables.

## Delegación al subagente haiku-auxiliar

- Antes de explorar archivos o resumir logs, considera delegar a `haiku-auxiliar`
  (subagente de solo lectura: Read, Glob, Grep).
- Reserva al agente principal las decisiones complejas, la seguridad, la
  arquitectura y los cambios de código.
- Si la tarea es trivial o delegar añade trabajo innecesario, resuélvela
  directamente.
- No afirmes que hubo delegación si no aparece en la ejecución.
