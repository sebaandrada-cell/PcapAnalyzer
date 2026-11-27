# PcapAnalyzer

*English version: [README.md](README.md) · Versión en español: [README.es.md](README.es.md).*

Ağ arızasını saatler değil saniyeler içinde bulun. Bir `.pcap` / `.pcapng` yakalamasını (gzip dahil) yükleyin; PcapAnalyzer size neyin başarısız olduğunu, nedenini ve sonraki adımda neyi kontrol etmeniz gerektiğini söylesin.
Kendi makinenizde çalışır, böylece yakalamalar ağınızdan dışarı çıkmaz.

**Ücretsiz ve açık kaynak (Apache 2.0). Durum: beta.**

- Hiçbir şey kurmadan deneyin: <https://pcap-analyzer-seven.vercel.app/#demo>
- İndirin: <https://sebaandrada6.gumroad.com/l/hspgx> (ücretsiz) veya bu depoyu klonlayın.

## Ne yapar

- Her yakalamada çalışan, her biri önem derecesi ve bir sonraki adım önerisi içeren **27 algılayıcı**:
  - TCP: güvenlik duvarı engellemeleri (SYN→RST), yeniden iletimler (retransmissions), yinelenen ACK'ler, paket kaybı ve sırasız paketler (reordering), sıfır ve dolu pencereler, el sıkışma sonrası sıfırlamalar, yavaş el sıkışmalar.
  - Yol (Path): PMTUD kara delikleri, düşük MSS, IP parçalanması, ICMP hataları, yönlendirme döngüleri.
  - Ad ve adres servisleri: yanıtlanmayan veya yavaş DNS, SERVFAIL, NXDOMAIN patlamaları, DHCP NAK / DECLINE / yanıtsız, yinelenen IP'ler, ARP fırtınaları.
  - Uygulamalar: HTTP 4xx / 5xx ve yavaş yanıtlar, TLS uyarıları, SSL 3.0 / TLS 1.0 / 1.1.
  - Tüneller: tek yönlü kalan, el sıkışmaya hiç yanıt vermeyen veya sürekli yeniden müzakere eden IPsec (IKE ve ESP), WireGuard, OpenVPN, GRE, L2TP ve Teredo.
  - Güvenlik: port taramaları ve tarama süpürmeleri (sweeps), düz metin oturum açmalar (FTP, POP3, IMAP, SMTP AUTH, HTTP Basic; kimlik bilgileri asla saklanmaz veya gösterilmez), Telnet / SMBv1 / SNMP v1-v2c, ARP sahteciliği (spoofing), örtüşen IP parçaları.
- **Önce yakalama kalitesi.** Yakalamanın kendisinin sonucu sınırladığı durumlarda uyarır: mirror port nedeniyle yinelenen çerçeveler, yalnızca tek yönde görülen trafik, kesilmiş (truncated) paketler, yakalama başladığında zaten açık olan bağlantılar.
- **Wireshark tarzı görünümler:** tüm yakalama üzerinde gerçek Wireshark görüntüleme filtreleriyle paket listesi, renklendirme, CSV dışa aktarma, uzman bilgisi (expert info), HTTP / DNS / DHCP / TLS tabloları, yanıt süreleri ve her konuşma için akış diyagramı.
- **Yapay zeka incelemesi (isteğe bağlı):** bir yapay zeka, araçlarla (gerçek filtreler, akış ayrıntısı, istatistikler) yakalamayı inceler ve her iddianın arkasındaki paketleri kaynak gösterir. Ardından takip soruları sorabilirsiniz. Kendi Anthropic API anahtarınızı kullanır; anahtar olmadan demo modu, analizden üretilen metinle tam akışı ücretsiz olarak çalıştırır.
- **PDF raporu**, İspanyolca ve İngilizce arayüz, açık ve koyu tema.

## Hızlı başlangıç

Docker Compose ile birlikte **Docker** gereklidir. Windows'ta betiği Git Bash veya WSL üzerinden çalıştırın.

```bash
git clone https://github.com/sebaandrada-cell/PcapAnalyzer.git
cd PcapAnalyzer
./start.sh
```

Betik rastgele bir erişim belirteci (token) oluşturur (bir kez gösterilir, `.env` dosyasında saklanır) ve uygulamayı başlatır. Derleme tamamlandığında <http://localhost:8080> adresini açın, belirteci sağ üstteki "API token" alanına yapıştırın ve bir yakalama yükleyin veya "Try the sample capture" seçeneğine tıklayın.

Uygulama yalnızca `127.0.0.1` üzerinde dinler. Kimlik doğrulamalı bir ters proxy olmadan ağa açmayın: API, yapay zeka hesabınızı kullanabilir.
Ayrıntılar, yapay zeka kurulumu ve sorun giderme için [QUICKSTART.md](QUICKSTART.md) dosyasına bakın.

### Docker olmadan

Python 3.9+, Node 20+ ve **tshark** (Wireshark ile birlikte kurulur) gereklidir.

```bash
cd backend
python3 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
export API_TOKENS="$(openssl rand -hex 32)"
.venv/bin/uvicorn app.main:app --reload
```

```bash
cd frontend
npm install
npm run dev
```

<http://localhost:5173> adresini açın ve aynı belirteci yapıştırın. `tshark` `PATH` üzerinde değilse `TSHARK_PATH` değişkenini ikili dosyanın yoluna ayarlayın.

## Gizlilik

- Yakalama kendi makinenizde analiz edilir. Yapay zeka incelemesi sürerken şifreli olarak saklanır (60 dakika hareketsizlik veya "Delete capture now" düğmesine basana kadar) ve ardından silinir.
- Yapay zeka isteğe bağlıdır ve kendi Anthropic API anahtarınızı kullanır. Yalnızca araçlarının döndürdüğü verileri görür, `.pcap` dosyasını asla görmez. "allow packet content" kapalıyken (varsayılan) bu veriler paket meta verileridir: IP'ler, MAC'ler, portlar, DNS adları, TLS SNI ve HTTP host ile yol (path). URL sorgu dizeleri ve FTP, POP3, IMAP, SMTP ile Telnet oturum açma komutları gizlenir. Hiçbir şey anonimleştirilmez: IP adresleri ve ana bilgisayar adları olduğu gibi gönderilir.
- Kendi barındırdığınız sürümde telemetri ve hesap yoktur.

## Testler

```bash
cd backend && .venv/bin/python -m pytest -q    # tshark gerektirir
cd frontend && npm test
```

## Geri bildirim

PcapAnalyzer beta aşamasındadır. Sentetik test verileri ve herkese açık örnek yakalamalarla test edilmiştir; en faydalı geri bildirim, bir sorunu kaçırdığı veya gerçek olmayan bir sorunu bildirdiği bir yakalamadır. Lütfen <https://github.com/sebaandrada-cell/PcapAnalyzer/issues> adresinden bir issue açın ve durumu açıklayın.
**Gerçek kimlik bilgileri veya müşteri verileri içeren yakalamaları eklemeyin**; önce anonimleştirin veya deseni açıklayın.

Teknik referans (JSON şeması, algılayıcı eşikleri, sınırlar, API hataları) İspanyolca olarak [README.es.md](README.es.md) dosyasında yer almaktadır.

## Lisans

[Apache License 2.0](LICENSE). Üçüncü taraf yazılımlar için [NOTICE](NOTICE) dosyasına bakın: tshark / Wireshark (GPL) ayrı bir program olarak çalışır ve PcapAnalyzer ile birlikte dağıtılmaz.
