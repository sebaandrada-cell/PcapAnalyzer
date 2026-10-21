# SPEC — PcapAnalyzer

## Problema

Wireshark es potente pero hostil: los display filters tienen curva de aprendizaje
alta, no existe una vista "dashboard" del estado de una captura, y el diagnóstico
depende por completo de la experiencia de quien mira. MSPs, sysadmins generalistas
y NOCs de primer nivel reciben capturas que no saben interpretar con rapidez.

## Producto

Aplicación web: subes un .pcap/.pcapng y obtienes (a) un dashboard visual,
(b) una lista de problemas detectados automáticamente con severidad, y
(c) un diagnóstico en lenguaje natural generado por IA, además de consultas
en lenguaje natural que se traducen a display filters.

## No-objetivos (v1)

- Captura de tráfico en vivo (solo análisis de archivos).
- Soporte multiusuario/equipos, facturación y planes (post-MVP).
- Descifrado TLS con claves aportadas por el usuario (considerar en v2).
- App de escritorio (la variante on-premise será el mismo backend en Docker).

## Fases

### Fase 1 — Backend de análisis (empezar aquí)

Endpoint `POST /analyze` que recibe un pcap y devuelve JSON con:

1. Resumen: nº paquetes, duración, bytes totales, nº conversaciones.
2. Distribución de protocolos (% por bytes y por paquetes).
3. Conversaciones TCP/UDP: endpoints, puertos, bytes, paquetes, retransmisiones;
   top talkers ordenados por volumen.
4. Serie temporal: paquetes/segundo y retransmisiones/segundo (para el gráfico).
5. Array `issues[]` generado por los detectores descritos en CLAUDE.md.

Criterios de aceptación:
- Analiza un pcap de 50 MB en < 30 s en un portátil normal.
- Cada detector tiene test unitario con fixture.
- README con instrucciones de instalación (incluida la de tshark).

### Fase 2 — Frontend dashboard

React + Recharts replicando el mockup de referencia (captura adjunta en
`docs/mockup.png` si existe). Vistas en orden de prioridad:

1. Cabecera con metadatos del archivo + barra de consulta en lenguaje natural
   (en esta fase la barra puede quedar deshabilitada o mock).
2. Tarjetas de métricas: paquetes, duración, conversaciones, problemas.
3. Distribución de protocolos (barras horizontales) + top talkers (lista).
4. Gráfico temporal de tráfico con serie de retransmisiones superpuesta.
5. Lista de problemas con badges de severidad.
6. Vista de detalle de una conversación TCP concreta (drill-down desde
   top talkers o desde un issue).

### Fase 3 — Capa IA

1. **Diagnóstico**: endpoint que envía el JSON resumido (nunca el pcap) a la
   Anthropic API y devuelve un diagnóstico narrativo: qué pasa, causa probable,
   siguiente paso recomendado. Prompt con contexto de networking senior.
2. **Consulta en lenguaje natural → display filter**: el usuario escribe
   "conexiones fallidas hacia el servidor de correo" y el sistema devuelve el
   filtro Wireshark equivalente y lo aplica sobre los datos ya parseados.

### Fase 4 — Empaquetado

- Docker Compose (backend + frontend) para la variante on-premise.
- Informe PDF exportable (para que MSPs lo entreguen a sus clientes).
- Límites de tamaño y colas para capturas grandes (procesado async).

## Datos de prueba

Generar pcaps de prueba desde el lab GNS3: capturar tráfico normal y luego
provocar fallos a propósito (bloquear un puerto en el firewall para generar
RSTs, simular pérdida de paquetes para retransmisiones, apuntar a un DNS
inexistente). Guardar como fixtures pequeños y anonimizados.

## Primer prompt sugerido para Claude Code

> Lee CLAUDE.md y SPEC.md. Implementa la Fase 1 completa: proyecto FastAPI
> con el endpoint /analyze, los cinco detectores como módulos independientes,
> tests con fixtures y README. Antes de escribir código, verifica si tshark
> está instalado en este sistema y proponme el plan de estructura del proyecto
> para que lo apruebe.
