# Publicación de LinkedIn — castellano e inglés

Texto plano, sin emojis de viñeta. Las dos primeras líneas son lo único que se ve antes de
«ver más»: por eso empiezan con el gancho técnico y no con «lanzamiento».

**Imagen o vídeo recomendados:** `03-diagrama-de-flujo-es.jpg` (el SYN y el RST a 5 ms) para la
versión en castellano; `05-panel-en-oscuro.jpg` para la inglesa. Mejor aún, el vídeo de 20–30 s
en MP4 subido directamente a LinkedIn.

---

## Castellano

```
Un firewall que rechaza una conexión (o un puerto cerrado) deja una firma muy concreta en una captura de red: un SYN y, 5 milisegundos después, un RST. Sin SYN-ACK en medio.

Verlo en Wireshark es cuestión de saber qué buscar. Encontrarlo entre decenas de miles de paquetes, con el cliente esperando, es otra historia.

Por eso he hecho PcapAnalyzer: subes un .pcap o .pcapng (también .gz) y te dice qué falla, por qué y qué mirar después.

Lo que hace:
- Detecta 11 tipos de problema: bloqueos de firewall (SYN→RST), retransmisiones TCP, ventana cero, PMTUD, fragmentación, DNS sin respuesta o lento, fallos TLS, túneles VPN e IPs duplicadas.
- Diagnóstico en lenguaje claro: qué pasa, causa probable y siguiente paso. Con tu propia clave de Anthropic; sin clave funciona en modo demo, con texto generado sin IA.
- Consultas en lenguaje natural que se traducen a un filtro de Wireshark.
- Informe en PDF, interfaz en español e inglés, tema claro y oscuro.

Se ejecuta en tu máquina con Docker, con un solo comando (./start.sh). Las capturas, que suelen llevar credenciales y datos de clientes, no salen de tu equipo. Solo si activas la IA se envía un resumen en JSON, nunca el pcap.

Pago único de 5 €, sin suscripción.

Demo sin registro, con una captura de ejemplo:
https://pcap-analyzer-seven.vercel.app/#demo

Descarga:
https://sebaandrada6.gumroad.com/l/hspgx

Si haces troubleshooting de redes, me interesa saber qué detector echas en falta.

#redes #sysadmin #wireshark #troubleshooting #MSP
```

## English

```
A firewall that rejects a connection (or a closed port) leaves a very specific signature in a packet capture: a SYN and, 5 milliseconds later, a RST. No SYN-ACK in between.

Spotting it in Wireshark is a matter of knowing what to look for. Finding it among tens of thousands of packets, with the customer waiting, is another story.

That is why I built PcapAnalyzer: you upload a .pcap or .pcapng (gzip works too) and it tells you what is failing, why, and what to check next.

What it does:
- Detects 11 kinds of problem: firewall blocks (SYN→RST), TCP retransmissions, zero window, PMTUD black holes, IP fragmentation, unanswered or slow DNS, TLS failures, VPN tunnel issues and duplicate IPs.
- A plain-language diagnosis: what is happening, the likely cause and the next step. It uses your own Anthropic key; without one it runs in a demo mode with text generated without AI.
- Natural-language questions that turn into a Wireshark display filter.
- PDF report, Spanish and English interface, light and dark theme.

It runs on your own machine with Docker, with a single command (./start.sh). Captures, which often hold credentials and customer data, do not leave your computer. Only if you turn on the AI is a JSON summary sent, never the pcap.

One-time €5, no subscription.

Demo with a sample capture, no sign-up:
https://pcap-analyzer-seven.vercel.app/#demo

Download:
https://sebaandrada6.gumroad.com/l/hspgx

If you troubleshoot networks, I would like to know which detector you are missing.

#networking #sysadmin #wireshark #troubleshooting #MSP
```

---

## Primer comentario (opcional)

Si prefieres no poner los enlaces en el cuerpo del post, déjalos en el primer comentario.
Hay quien lo hace porque se dice que LinkedIn reduce el alcance de los posts con enlaces
externos; no está comprobado, pruébalo con el primero y mira las impresiones.

```
Demo sin registro: https://pcap-analyzer-seven.vercel.app/#demo
Descarga (5 €): https://sebaandrada6.gumroad.com/l/hspgx
```
