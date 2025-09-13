# firewall-agent Dockerfile
# - Python base image with iptables tools
# - Runs an HTTPS API (to be implemented) and manages host iptables via CAP_NET_ADMIN

FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       iptables iproute2 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY firewall-agent/requirements.txt /app/requirements.txt
RUN pip install -r /app/requirements.txt

COPY firewall-agent/ /app/

# API port (configurable via FIREWALL_API_PORT)
EXPOSE 8443

# For now, run placeholder server; later this will run FastAPI/uvicorn
ENTRYPOINT ["python", "-u", "app.py"]

