# Plan de difusión — PcapAnalyzer (5 €)

**Enlace único que repartes en todo:** https://sebaandrada6.gumroad.com/l/hspgx
**Público objetivo:** sysadmins, MSPs, técnicos de NOC/soporte de redes. Gente que
ya usa Wireshark y odia perder media hora leyendo paquetes.

---

## Paso 0 — Antes de publicar nada (1 hora)

1. **Hacer pública la landing.** Hoy es privada. Abrirla en claude.ai y darle a
   compartir, o repartir directamente el enlace de Gumroad (ese ya es público).
2. **Grabar un GIF de 20–30 s**: subir un pcap → aparecen los problemas → clic en
   un diagnóstico. Un GIF vende 10× más que texto; es lo que engancha en Reddit,
   X y LinkedIn.
3. Tener a mano **1 captura de pantalla** del dashboard con problemas detectados.

## Semana 1 — Lanzamiento (donde está el público)

| Día | Canal | Qué hacer |
|---|---|---|
| Lun | **Hacker News (Show HN)** | Título: `Show HN: PcapAnalyzer – self-hosted pcap analyzer with AI diagnosis (€5)`. Publicar martes–jueves ~15:00 UTC. Responder TODOS los comentarios. Mejor tiro de alcance técnico. |
| Mar | **Reddit** (con cuidado) | r/networking **prohíbe autopromo** → NO vender ahí directo. Mejor: **r/msp**, r/sysadmin (mirar su día de self-promo), r/homelab. Usar el texto en inglés + el GIF. |
| Mié | **LinkedIn** | Post en español + GIF. Etiquetar #Networking #Sysadmin #MSP. Pedir a conocidos del sector que comenten (el algoritmo premia comentarios tempranos). |
| Jue | **Comunidades Discord/Slack** | Discord de r/homelab, de NetworkChuck, grupos de MSP. No spamear: participar y mencionarlo donde encaje. |
| Vie | **Indie Hackers** | Post de lanzamiento "built a €5 tool for network troubleshooting". Comunidad receptiva a makers. |

## Semana 2 — Seguimiento y contenido

- **Responder feedback** y ajustar la landing con lo que digan (las objeciones
  reales son oro).
- **Escribir 1 artículo/hilo técnico útil** (no venta):
  *"Cómo detectar un firewall que bloquea con SYN→RST en un pcap"*. Al final,
  mención discreta a la herramienta. Esto es SEO + autoridad; publicar en
  dev.to / LinkedIn / Medium.
- **X/Twitter:** hilo corto con el GIF mostrando un caso real que detecta.

## La métrica que se mira (y solo esa)

**Ventas, no visitas.** Gumroad muestra vistas y conversiones.
Objetivo realista primer mes: **5–10 ventas**.
- Muchas vistas y 0 ventas → problema de precio/mensaje.
- Pocas vistas → problema de difusión (publicar más).

## Expectativa honesta

Producto de nicho, sin audiencia, a 5 €: las primeras ventas cuestan. HN e Indie
Hackers pueden dar un pico de 1 día; lo sostenible es el contenido técnico útil
que posiciona. No desanimarse si la primera semana son 1–2 ventas: eso ya valida
que alguien paga.

---

## Textos listos para copiar

### LinkedIn (español)

```
He lanzado una herramienta que llevaba tiempo queriendo construir: PcapAnalyzer.

Es un analizador de capturas de red (.pcap / .pcapng) que te da el diagnóstico
en segundos: qué falla, por qué y cuál es el siguiente paso. Pensado para MSPs,
sysadmins y NOC de primer nivel que no quieren pasarse media hora leyendo
Wireshark paquete a paquete.

Qué hace:
🔎 Detecta 11 problemas automáticamente: bloqueos de firewall (SYN→RST),
   retransmisiones TCP, ventana cero, PMTUD, fragmentación, DNS sin respuesta,
   fallos TLS, túneles VPN e IPs duplicadas.
🤖 Diagnóstico con IA: te explica qué pasa, la causa probable y qué hacer.
💬 Escribes en lenguaje natural y te lo traduce a un filtro de Wireshark.
📄 Informe PDF exportable, interfaz en español e inglés, modo claro/oscuro.

Y lo más importante: se ejecuta en TU propia máquina. Tus capturas —que suelen
llevar datos sensibles— nunca salen de tu equipo. Arranca con un comando
(docker compose up) y listo.

Es de pago único, 5 €, self-hosted. Sin suscripciones, sin subir nada a la nube.

👉 https://sebaandrada6.gumroad.com/l/hspgx

Si trabajas con redes y te toca hacer troubleshooting, me encantaría que le eches
un vistazo y me digas qué te parece.

#Networking #Sysadmin #DevOps #Wireshark #MSP #Troubleshooting
```

### Reddit / Hacker News / foros técnicos (inglés)

```
I built a self-hosted pcap analyzer that gives you a diagnosis in seconds

I got tired of scrolling through Wireshark packet-by-packet for routine
troubleshooting, so I built PcapAnalyzer: you drop in a .pcap/.pcapng and it
tells you what's wrong, why, and what to check next.

What it does:
- Auto-detects 11 issues: firewall blocks (SYN→RST), TCP retransmissions,
  zero window, PMTUD black holes, IP fragmentation, unanswered/slow DNS, TLS
  handshake failures, VPN tunnel problems, duplicate IPs.
- AI-assisted diagnosis (what's happening / probable cause / next step).
- Natural-language → Wireshark filter translation.
- Wireshark-style views: packet list, HTTP/DNS/TLS tables, per-conversation
  flow diagrams. Exportable PDF report. EN/ES UI, light/dark.

Key point: it runs entirely on your own machine (docker compose up). Your
captures never leave your box. For the AI part you plug in your own Anthropic
API key, or use the built-in demo mode with no key and no cost.

It's a one-time €5, self-hosted download.

Link: https://sebaandrada6.gumroad.com/l/hspgx

Happy to answer questions about the detection engine or how it parses captures.
```

### Hacker News — título Show HN

```
Show HN: PcapAnalyzer – self-hosted pcap analyzer with AI diagnosis (€5)
```

---

## Aviso sobre Reddit

r/networking **prohíbe la autopromoción**: un post de venta directo se borra y
puede costar un ban. Alternativas más seguras: r/msp, r/sysadmin (revisar reglas
y día de self-promo), r/homelab. En Reddit funciona mejor participar, responder
dudas reales de troubleshooting, y mencionar la herramienta solo cuando encaje.
El texto de venta directo encaja mejor en Show HN, Indie Hackers o foros de MSP.
