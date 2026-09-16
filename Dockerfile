# ReconScan - one-command deploy (Phase 2)
#
# Built on Kali because that is where the scanning tools live and are kept
# current. The image ships nmap, masscan, nuclei, nikto, whatweb and gobuster
# plus the standard wordlists, so a scan you set up in the UI can actually run.
#
#   docker compose up --build        -> https://localhost:8000 (LAN mode, login)
#
# Raw-packet scans (SYN, OS detection, UDP, masscan) need NET_RAW and NET_ADMIN;
# docker-compose.yml grants exactly those two rather than running privileged.
FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Tools first: this layer is large and changes rarely, so it stays cached while
# you iterate on the application code below.
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap \
        masscan \
        nikto \
        whatweb \
        gobuster \
        nuclei \
        dirb \
        wordlists \
        ca-certificates \
        openssl \
        python3 \
        python3-pip \
        python3-venv \
    && rm -rf /var/lib/apt/lists/*

# Kali ships some wordlists gzipped; unpack the big one so gobuster can read it.
RUN if [ -f /usr/share/wordlists/rockyou.txt.gz ]; then \
        gunzip -f /usr/share/wordlists/rockyou.txt.gz || true; \
    fi

# A virtualenv keeps our Python dependencies away from the system interpreter,
# which Debian/Kali now protect (PEP 668).
ENV VIRTUAL_ENV=/opt/venv
RUN python3 -m venv "$VIRTUAL_ENV"
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

WORKDIR /app
COPY app/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir --upgrade pip && pip install --no-cache-dir -r requirements.txt

COPY app/ /app/

# Projects, scans, findings and the LAN certificate live here. Mount a volume
# over it (docker-compose.yml does) so your work survives a rebuild.
ENV RECONSCAN_DATA_DIR=/data \
    RECONSCAN_HOST=0.0.0.0 \
    RECONSCAN_PORT=8000 \
    RECONSCAN_DEMO=0
RUN mkdir -p /data
VOLUME ["/data"]

EXPOSE 8000

# No HEALTHCHECK against /api/meta over HTTPS with a self-signed certificate -
# it would need --insecure and only tell us uvicorn is listening, which the
# container's own exit status already covers.
CMD ["python", "-m", "reconscan"]
