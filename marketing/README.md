# Material gráfico

Capturas del producto real (modo self-hosted, captura de ejemplo, sin datos reales).
No forman parte del paquete de venta (`export-ignore`).

| Archivo | Qué muestra | Uso sugerido |
|---|---|---|
| `01-panel-es-claro.jpg` | Panel principal: métricas, protocolos, top talkers, túneles VPN | Portada de Gumroad, LinkedIn |
| `02-problemas-detectados-es.jpg` | Lista de problemas con severidad y explicación | LinkedIn, artículo técnico |
| `03-diagrama-de-flujo-es.jpg` | Conversación SYN→RST en 5 ms con su diagrama de flujo | Artículo técnico, Reddit |
| `04-diagnostico-modo-demo-es.jpg` | Diagnóstico asistido **en modo demo** (texto sin IA, así lo dice la imagen) | Solo con la aclaración «modo demo»; no presentarlo como IA real |
| `05-panel-en-oscuro.jpg` | Panel principal en inglés y tema oscuro | Reddit, Indie Hackers, Product Hunt |

Regenerar: levantar el backend con `AUTH_MODE=token LLM_DEMO=1`, el frontend con `npm run dev`,
cargar «Probar con la captura de ejemplo» y capturar.
