"""
firewall-agent: HTTPS API entrypoint (FastAPI)

Endpoints:
  - POST /enable  -> Apply baseline rules, then allow configured services
  - POST /disable -> Flush DOCKER-USER chain (failsafe)
  - GET  /status  -> Report iptables state and container summaries

TLS:
  - Uses self-signed cert by default (generated if missing)
  - Configure with FIREWALL_TLS_CERT and FIREWALL_TLS_KEY

Configuration (env vars):
  - FIREWALL_ALLOWED_SERVICES  (default: "traefik,jellyfin,gluetun")
  - FIREWALL_RESTRICT_LABEL    (default: "firewall.restrict")
  - FIREWALL_API_HOST          (default: "0.0.0.0")
  - FIREWALL_API_PORT          (default: 8443)
  - FIREWALL_TLS_CERT          (default: "/app/certs/server.crt")
  - FIREWALL_TLS_KEY           (default: "/app/certs/server.key")
  - FIREWALL_TLS_AUTO          (default: "true")
"""

from __future__ import annotations

import json
import logging
import os
import pathlib
from typing import Dict, List

from fastapi import FastAPI
from fastapi.responses import JSONResponse
import uvicorn

from iptables import reset_rules, allow_container, allow_service, disable as fw_disable, status as fw_status
import docker_client

logging.basicConfig(
    level=os.environ.get("FIREWALL_LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("firewall-agent.api")


def _parse_allowed_services() -> List[str]:
    raw = os.environ.get("FIREWALL_ALLOWED_SERVICES", "traefik,jellyfin,gluetun")
    parts = [s.strip() for s in raw.split(",") if s.strip()]
    # Deduplicate preserving order
    seen = set()
    out: List[str] = []
    for s in parts:
        if s not in seen:
            seen.add(s)
            out.append(s)
    return out


def _restrict_label() -> str:
    return os.environ.get("FIREWALL_RESTRICT_LABEL", "firewall.restrict")


def _tls_paths() -> tuple[str, str]:
    cert_path = os.environ.get("FIREWALL_TLS_CERT", "/app/certs/server.crt")
    key_path = os.environ.get("FIREWALL_TLS_KEY", "/app/certs/server.key")
    return cert_path, key_path


def _should_auto_tls() -> bool:
    return os.environ.get("FIREWALL_TLS_AUTO", "true").lower() in ("1", "true", "yes", "on")


def _ensure_self_signed_cert() -> tuple[str, str]:
    cert_path, key_path = _tls_paths()
    cert_file = pathlib.Path(cert_path)
    key_file = pathlib.Path(key_path)
    if cert_file.exists() and key_file.exists():
        return cert_path, key_path

    if not _should_auto_tls():
        raise RuntimeError("TLS cert/key missing and FIREWALL_TLS_AUTO disabled")

    log.info("Generating self-signed TLS cert at %s", cert_file.parent)
    cert_file.parent.mkdir(parents=True, exist_ok=True)

    # Generate self-signed cert using cryptography
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    import datetime

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"firewall-agent"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"firewall-agent.local"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(u"localhost")]), critical=False)
        .sign(key, hashes.SHA256())
    )

    with open(key_file, "wb") as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    with open(cert_file, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    return cert_path, key_path


app = FastAPI(title="firewall-agent")


def _apply_allowed_services(services: List[str]) -> Dict[str, List[str]]:
    allowed_ips: List[str] = []
    for svc in services:
        try:
            # Prefer docker_client to resolve IPs, then allow explicitly
            ips = docker_client.resolve_service_ips(svc)
            if not ips:
                # Fallback to iptables helper that self-resolves
                log.info("No IPs resolved via docker_client for %s; trying iptables helper", svc)
                res = allow_service(svc)
                ips = res.get("ips", []) if isinstance(res, dict) else []
            for ip in ips:
                allow_container(ip)
                allowed_ips.append(ip)
        except Exception as e:
            log.warning("Failed to allow service %s: %s", svc, e)
    # Deduplicate
    allowed_ips = sorted(set(allowed_ips))
    return {"services": services, "ips": allowed_ips}


@app.post("/enable")
def enable() -> JSONResponse:
    services = _parse_allowed_services()
    base = reset_rules()
    allowed = _apply_allowed_services(services)

    restrict_label = _restrict_label()
    restricted = docker_client.list_restricted_containers(restrict_label)

    log.info("Enabled firewall. Allowed services=%s, ips=%s", services, allowed["ips"])
    return JSONResponse({
        "ok": True,
        "baseline": {"enabled": base.get("enabled"), "rule_count": base.get("rule_count")},
        "allowed": allowed,
        "restricted_containers": [c.get("name") for c in restricted],
    })


@app.post("/disable")
def disable() -> JSONResponse:
    s = fw_disable()
    return JSONResponse({"ok": True, "status": s})


@app.get("/status")
def status() -> JSONResponse:
    s = fw_status()
    services = _parse_allowed_services()
    restrict_label = _restrict_label()
    restricted = docker_client.list_restricted_containers(restrict_label)

    # Provide a light summary of containers with service matches
    allowed_map: Dict[str, List[str]] = {}
    for svc in services:
        allowed_map[svc] = docker_client.resolve_service_ips(svc)

    return JSONResponse({
        "ok": True,
        "iptables": {k: s[k] for k in ("chain", "enabled", "rule_count", "allow_ips")},
        "allowed_services": allowed_map,
        "restricted_containers": [c.get("name") for c in restricted],
    })


@app.get("/topology")
def topology() -> JSONResponse:
    """Return a graph-friendly topology summary for UI visualization.

    Includes:
      - nodes: containers (with service, labels), networks, and a WAN node
      - edges: container->network, container->WAN (allowed or blocked)
      - per-container flags: allowed_wan, restricted
    """
    restrict_label = _restrict_label()
    containers = docker_client.list_containers()
    s = fw_status()
    allowed_ips = set(s.get("allow_ips") or [])
    services = _parse_allowed_services()

    # Build service->IPs map using docker client
    svc_ip_map = {svc: docker_client.resolve_service_ips(svc) for svc in services}
    svc_ip_set = {svc: set(ips) for svc, ips in svc_ip_map.items()}

    networks = set()
    nodes = []
    edges = []

    for item in containers:
        name = item.get("name")
        ips = item.get("ips") or []
        svc = item.get("service")
        labels = item.get("labels") or {}
        nets = item.get("networks") or {}
        for n in nets.keys():
            networks.add(n)

        is_restricted = str(labels.get(restrict_label, "")).strip().lower() in ("1", "true", "yes", "on", "enable", "enabled")

        # Determine WAN allowance: if any IP is explicitly allowed or part of an allowed service's IPs
        allowed_wan = any(ip in allowed_ips for ip in ips)
        if not allowed_wan and svc in svc_ip_set:
            allowed_wan = any(ip in svc_ip_set[svc] for ip in ips) or (svc in services)

        nodes.append({
            "type": "container",
            "id": name,
            "label": name,
            "service": svc,
            "ips": ips,
            "restricted": is_restricted,
            "allowed_wan": bool(allowed_wan),
        })

        # Edges to networks
        for net_name, ip in nets.items():
            edges.append({
                "from": name,
                "to": f"net:{net_name}",
                "type": "link",
            })

        # Edge to WAN (allowed/blocked)
        edges.append({
            "from": name,
            "to": "wan",
            "type": "wan",
            "allowed": bool(allowed_wan),
        })

    # Add network nodes
    for n in sorted(networks):
        nodes.append({
            "type": "network",
            "id": f"net:{n}",
            "label": n,
        })

    # Add WAN node
    nodes.append({"type": "wan", "id": "wan", "label": "WAN"})

    return JSONResponse({
        "ok": True,
        "nodes": nodes,
        "edges": edges,
        "allowed_services": services,
        "service_ips": svc_ip_map,
    })


def main() -> None:
    host = os.environ.get("FIREWALL_API_HOST", "0.0.0.0")
    port = int(os.environ.get("FIREWALL_API_PORT", "8443"))
    cert_path, key_path = _ensure_self_signed_cert()
    log.info("Starting firewall-agent API on %s:%s", host, port)
    uvicorn.run(
        "app:app",
        host=host,
        port=port,
        reload=False,
        ssl_certfile=cert_path,
        ssl_keyfile=key_path,
    )


if __name__ == "__main__":
    main()
