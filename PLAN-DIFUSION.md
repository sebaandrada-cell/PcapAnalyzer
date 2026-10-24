# Plan de difusión — PcapAnalyzer (v2 · 24-oct-2026)

**Producto:** PcapAnalyzer 1.2.0 · descarga self-hosted · 5 € pago único
**Compra:** https://sebaandrada6.gumroad.com/l/hspgx
**Landing (ES/EN, pública):** https://claude.ai/artifact/NAX5Yw8wfuP86odEKtS7uv
**Público:** sysadmins, MSPs y NOC de primer nivel. Gente que ya usa Wireshark y no
quiere perder media hora leyendo paquetes.

---

## 1. Estado: qué está listo y qué no

| | |
|---|---|
| Paquete 1.2.0 en Gumroad (18 detectores, filtros estilo Wireshark), sin secretos ni datos internos | ✔ (`scripts/build-release.sh`) |
| Paquete 1.1.1 (arregla el inglés del modo demo) incluido en el 1.2.0 | ✔ |
| `docker compose` probado de punta a punta (19 comprobaciones) | ✔ en CI (`scripts/verify-bundle.sh`) |
| Landing bilingüe con el comando correcto (`./start.sh`) | ✔ versión 7 |
| Ficha de Gumroad alineada con el producto | ✔ |
| **Demo sin pagar ni registrarse** (https://pcap-analyzer-seven.vercel.app/#demo) | ✔ en producción, sin llamadas al backend |
| 5 capturas del producto real (`marketing/`) | ✔ |
| Vídeo/GIF de 20–30 s | ☐ lo graba el dueño con Kap (guion en §5) |
| Huella de la descarga real = paquete local | ☐ la comprueba el dueño (`shasum -a 256`) |
| **Compra de prueba completa** (pago → email → descarga → arranque) | ☐ sin hacer |
| Reglas de cada comunidad leídas | ☐ sin hacer |

**La compra de prueba es lo más importante antes de anunciar nada.** Crea un cupón de
descuento alto en Gumroad, cómprate el producto y comprueba que llega el email, que la
descarga funciona y que `./start.sh` arranca desde esa descarga. Si algo falla delante
del primer cliente real, no se recupera.

## 2. Correcciones respecto al plan anterior

- **Hacker News (Show HN) no encaja tal cual.** Las reglas oficiales piden que se pueda
  probar «ideally without barriers such as signups», dejan fuera las páginas de
  aterrizaje («Don't post landing pages») y prohíben pedir votos o comentarios a amigos.
  Un producto de pago con landing se arriesga a que lo marquen como fuera de tema. Solo
  tiene sentido enlazando a la demo sin registro (§3), no a la landing ni a Gumroad.
- **Reddit: las reglas NO están verificadas.** Reddit bloquea la lectura automática, así
  que el plan anterior se equivocó al dar por hecho que r/sysadmin tiene un día de
  autopromoción. **Lee la barra lateral y las reglas de cada subreddit antes de publicar**
  y, si prohíben vender, no publiques ahí.
- **Los textos prometían de más.** El diagnóstico con IA real necesita la clave del
  comprador (sin clave hay modo demo) y el comando de arranque ya no es
  `docker compose up` sino `./start.sh`. Los textos de §6 están corregidos.
- Pedir a conocidos que comenten sirve en LinkedIn, **no** en Hacker News.

## 3. Cómo se prueba sin pagar: demo web sin registro (hecha)

**https://pcap-analyzer-seven.vercel.app/#demo** — el panel real con el análisis de la
captura de ejemplo, sin cuenta y sin backend (son datos generados por el propio motor,
`scripts/make-demo-data.py`). Lo que **sí** puede hacer el visitante: recorrer métricas,
tablas, lista de problemas, abrir una conversación con su diagrama de flujo, cambiar
idioma y tema, y pulsar «Generar diagnóstico». Lo que **no**: subir capturas propias, la
consulta en lenguaje natural y el informe PDF (eso es la versión completa).

Dilo claro al enlazarla: el diagnóstico de la demo es **texto generado sin IA** (así lo
indica la propia página). No la presentes como IA real.

Opcional: publicar `sample.pcap` como descarga libre dentro de un artículo técnico, para
que el lector la abra en Wireshark y compare con lo que detecta la herramienta.

## 4. Calendario (hoy es sábado 24)

| Cuándo | Qué |
|---|---|
| **Sáb 24 – lun 26** | Preparación: compra de prueba, huella de la descarga, grabar el vídeo con Kap, leer reglas de cada canal, decidir si se sube el 1.1.1. (La demo y las capturas ya están.) |
| **Mar 27** · 8:30–10:00 | **LinkedIn** (post en español + vídeo). Responder cada comentario el mismo día. |
| **Mié 28** | **Indie Hackers** (post en inglés sobre cómo se construyó y qué problema resuelve). |
| **Jue 29** | **Reddit**: un único subreddit, el que sus reglas permitan; participa en comentarios, no solo publiques. |
| **Lun 2 nov** | Revisar métricas (§7) y decidir qué ajustar. |
| **Mar 3 nov** · ~15:00 UTC | **Show HN** enlazando a la **demo** (§3), no a la landing ni a Gumroad. Estar 3 horas disponible para responder. |

Mejor un canal bien trabajado cada día que cinco a la vez con prisas.
**Product Hunt** es una opción de segunda ola: está pensado para lanzamientos de producto
(verifica sus condiciones para productos de pago) y conviene prepararlo con una semana.

## 5. Material visual (lo que más convierte)

1. **3 capturas reales:** dashboard con problemas detectados, diagrama de flujo de una
   conversación, diagnóstico asistido. Servirán también de portada en Gumroad.
2. **Un vídeo/GIF de 20–30 s** con este guion:
   1. «Probar con la captura de ejemplo» → aparece el dashboard (18 problemas).
   2. Clic en «SYN respondido con RST inmediato» → se abre la conversación.
   3. Diagrama de flujo de esa conversación.
   4. «Generar diagnóstico» → qué pasa, causa probable, siguiente paso.
   5. «Exportar informe» (PDF).
   Para LinkedIn y X sube **MP4**; para Reddit y la landing, GIF.
3. Usa siempre la captura de ejemplo: nunca datos reales de nadie.

## 6. Textos

Sin emojis de viñeta: en una comunidad técnica restan credibilidad.

### LinkedIn (español)

> **Versión definitiva en castellano y en inglés: `marketing/linkedin.md`** (con gancho
> técnico, enlace a la demo y primer comentario). El texto de abajo es el borrador anterior.

```
He lanzado una herramienta que llevaba tiempo queriendo construir: PcapAnalyzer.

Analiza capturas de red (.pcap / .pcapng) y te da el primer diagnóstico en segundos:
qué falla, por qué y cuál es el siguiente paso. Está pensada para MSPs, sysadmins y NOC
de primer nivel que no quieren pasar media hora leyendo Wireshark paquete a paquete.

Qué hace:
- Detecta 18 tipos de problema: bloqueos de firewall (SYN→RST), retransmisiones y ACK
  duplicados, pérdida y reordenamiento, ventana cero o llena, PMTUD, fragmentación,
  errores ICMP, DNS sin respuesta o lento, fallos TLS, túneles VPN e IPs duplicadas.
- Diagnóstico con IA: qué pasa, causa probable y siguiente paso. Usa tu propia clave de
  Anthropic; sin clave hay un modo demo.
- Escribes la consulta en lenguaje natural y la traduce a un filtro de Wireshark.
- Informe PDF, interfaz en español e inglés, modo claro y oscuro.

Lo importante: se ejecuta en tu propia máquina con Docker (./start.sh). Las capturas,
que suelen llevar datos sensibles, no salen de tu equipo. Solo si activas la IA real se
envía un resumen en JSON, nunca el pcap.

Pago único de 5 €, self-hosted, sin suscripción.
https://sebaandrada6.gumroad.com/l/hspgx

Puedes verla funcionando sin registrarte (con una captura de ejemplo):
https://pcap-analyzer-seven.vercel.app/#demo

Si haces troubleshooting de redes, me interesa saber qué echas en falta.
```

### Post en inglés (Indie Hackers / Reddit si las reglas lo permiten)

```
I built a self-hosted pcap analyzer that gives you a first diagnosis in seconds

I kept scrolling through Wireshark packet by packet for routine troubleshooting, so I
built PcapAnalyzer: drop in a .pcap/.pcapng (gzip too) and it tells you what is wrong,
why, and what to check next.

- 18 detectors: firewall blocks (SYN→RST), retransmissions, duplicate ACKs, loss and
  reordering, zero/full window, PMTUD black holes, IP fragmentation, ICMP errors,
  unanswered/slow DNS, TLS handshake failures, VPN tunnel problems, duplicate IPs.
- AI diagnosis (what's happening / probable cause / next step). You bring your own
  Anthropic key; without one it runs a demo mode with simulated output.
- Natural-language query → Wireshark display filter.
- Wireshark-style views, PDF report, EN/ES UI, light/dark.

It runs on your machine (docker compose, one script). Captures are analyzed and
discarded; only if you enable the real AI is a JSON summary (never the raw pcap) sent
to the model.

One-time €5, personal license, self-hosted: https://sebaandrada6.gumroad.com/l/hspgx
You can see it working with a sample capture, no sign-up: https://pcap-analyzer-seven.vercel.app/#demo
(the demo's diagnosis text is generated without AI, and says so)

Happy to discuss the detection engine, how it parses captures (tshark, streaming), or
what you would add.
```

### Show HN (enlazando a la demo, §3)

Título: `Show HN: PcapAnalyzer – self-hosted pcap analyzer with a first-pass diagnosis`
(sin «€5» en el título; el precio va en el primer comentario, no en el titular).
Enlazar a la **demo**, no a la landing ni a Gumroad. Primer comentario: qué problema
resuelve, decisiones técnicas (tshark en streaming, no pyshark; la IA solo recibe un
JSON resumido), limitaciones honestas y que es de pago.

### Artículo técnico (dev.to / LinkedIn / blog) — para posicionarte, no para vender

*«Cómo reconocer un firewall que bloquea en un pcap: el patrón SYN→RST en 5 ms»*, con el
ejemplo real de la captura de muestra. Enseña a verlo a mano en Wireshark
(`tcp.flags.syn==1`, `tcp.flags.reset==1`) y, al final, una mención discreta a la
herramienta. Enlaza la captura de ejemplo como descarga libre (§3-C).

## 7. Qué se mide

**Ventas, no visitas.** Gumroad muestra visitas a la ficha y de dónde llegan, así que
mira qué canal trae visitas **y** ventas.
Regla práctica (mía, no un dato): si tras unas 200 visitas a la ficha no hay ninguna
compra, el problema es la oferta o el mensaje, no la difusión: toca revisar portada,
primera frase y precio, no publicar más.
Objetivo realista del primer mes: **unas 5–10 ventas**. Un producto de nicho, sin
audiencia previa y a 5 € arranca despacio; con 1–2 ya se valida que alguien paga.

## 8. Antes de publicar cada día

- [ ] Compra de prueba hecha y descarga verificada.
- [ ] Leídas las reglas del canal de ese día.
- [ ] El enlace que compartes es el correcto y abre bien en el móvil.
- [ ] Hay un medio de soporte visible (email de contacto en la ficha de Gumroad).
- [ ] Tienes 2–3 horas libres para contestar sin retrasos.
