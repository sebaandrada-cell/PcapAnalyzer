# PcapAnalyzer backend: FastAPI + tshark (CLAUDE.md targets Python 3.12).
FROM python:3.12-slim

# tshark comes from the wireshark-common package family; non-interactive
# install skips the dumpcap privileges prompt (not needed: we only read files).
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends tshark \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /srv/pcapanalyzer

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

# Run as an unprivileged user; captures are read from uploads, never the wire.
RUN useradd --system --no-create-home analyzer \
    && mkdir -p /tmp/pcapanalyzer \
    && chown analyzer /tmp/pcapanalyzer
USER analyzer
ENV TMPDIR=/tmp/pcapanalyzer

# Bind to $PORT when the platform provides one (Render/Fly/Cloud Run set it),
# falling back to 8000 for local docker-compose. Shell form so $PORT expands.
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD python -c "import os,urllib.request; urllib.request.urlopen('http://127.0.0.1:'+os.environ.get('PORT','8000')+'/health', timeout=4)"

CMD uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}
