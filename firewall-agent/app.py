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
  - FIREWALL_API_PORT          (default: 9444)
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

from fastapi import FastAPI, Depends, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import uvicorn

from iptables import reset_rules, allow_container, allow_service, disable as fw_disable, status as fw_status
import docker_client

logging.basicConfig(
    level=os.environ.get("FIREWALL_LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("firewall-agent.api")

# In‑memory runtime config (overrides env when set via API)
CURRENT_ALLOWED_SERVICES: List[str] | None = None
CURRENT_RESTRICT_LABEL: str | None = None
API_TOKEN = os.environ.get("FIREWALL_API_TOKEN")


def _parse_allowed_services() -> List[str]:
    raw_env = os.environ.get("FIREWALL_ALLOWED_SERVICES", "traefik,jellyfin,gluetun")
    raw = ",".join(CURRENT_ALLOWED_SERVICES) if CURRENT_ALLOWED_SERVICES is not None else raw_env
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
    return CURRENT_RESTRICT_LABEL or os.environ.get("FIREWALL_RESTRICT_LABEL", "firewall.restrict")


def require_auth(authorization: str | None = Header(None)) -> None:
    if not API_TOKEN:
        return
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    token = authorization.split(" ", 1)[1]
    if token != API_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid token")


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


from contextlib import asynccontextmanager

_watch_thread: threading.Thread | None = None
_watch_running = False


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


@app.post("/enable", dependencies=[Depends(require_auth)])
def enable() -> JSONResponse:
    services = _parse_allowed_services()
    # Discover internal Docker network subnets to allow container↔container traffic precisely
    internal_subnets = docker_client.list_network_subnets(only_in_use=True)
    base = reset_rules(private_cidrs=internal_subnets)
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


@app.post("/disable", dependencies=[Depends(require_auth)])
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


# Optional: background Docker events watcher to auto-apply policy
import threading
import time


def _apply_current_policy() -> None:
    try:
        services = _parse_allowed_services()
        internal_subnets = docker_client.list_network_subnets(only_in_use=True)
        reset_rules(private_cidrs=internal_subnets)
        _apply_allowed_services(services)
        log.info("Policy reapplied: subnets=%s services=%s", internal_subnets, services)
    except Exception as e:
        log.warning("Failed to apply policy: %s", e)


def _watch_events_loop():
    global _watch_running
    _watch_running = True
    try:
        cli = docker_client._docker_client()  # type: ignore[attr-defined]
        events = cli.api.events(decode=True)  # type: ignore[attr-defined]
        last_apply = 0.0
        debounce = float(os.environ.get("FIREWALL_APPLY_DEBOUNCE_SECONDS", "3"))
        for ev in events:
            if not _watch_running:
                break
            if not isinstance(ev, dict):
                continue
            typ = ev.get("Type")
            act = ev.get("Action")
            if typ in ("container", "network") and act in ("start", "die", "connect", "disconnect", "update"):
                now = time.time()
                if now - last_apply >= debounce:
                    _apply_current_policy()
                    last_apply = now
    except Exception as e:
        log.warning("Docker events watcher stopped: %s", e)
    finally:
        _watch_running = False

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    if os.environ.get("FIREWALL_AUTO_ENABLE_ON_START", "true").lower() in ("1", "true", "yes", "on"):
        _apply_current_policy()
    if os.environ.get("FIREWALL_WATCH_DOCKER", "true").lower() in ("1", "true", "yes", "on"):
        global _watch_thread
        if _watch_thread is None or not _watch_thread.is_alive():
            _watch_thread = threading.Thread(target=_watch_events_loop, name="fw-docker-watch", daemon=True)
            _watch_thread.start()
    try:
        yield
    finally:
        # Shutdown
        global _watch_running
        _watch_running = False


app = FastAPI(title="firewall-agent", lifespan=lifespan)

# Allow UI (browser) to call API from another origin. Lock down via env if needed later.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


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


@app.get("/containers")
def containers() -> JSONResponse:
    restrict_label = _restrict_label()
    all_containers = docker_client.list_containers()
    restricted = docker_client.list_restricted_containers(restrict_label)
    restricted_names = {c.get("name") for c in restricted}
    return JSONResponse({
        "ok": True,
        "count": len(all_containers),
        "restricted": sorted(n for n in restricted_names if n),
        "items": all_containers,
    })


@app.post("/policy/reload", dependencies=[Depends(require_auth)])
def policy_reload() -> JSONResponse:
    _apply_current_policy()
    return JSONResponse({"ok": True})


@app.post("/allow/service", dependencies=[Depends(require_auth)])
def allow_service_api(body: Dict[str, str]) -> JSONResponse:
    name = (body or {}).get("name")
    if not name:
        raise HTTPException(status_code=400, detail="Missing 'name'")
    res = allow_service(name)
    return JSONResponse({"ok": True, "result": res})


@app.post("/allow/ip", dependencies=[Depends(require_auth)])
def allow_ip_api(body: Dict[str, str]) -> JSONResponse:
    ip = (body or {}).get("ip")
    if not ip:
        raise HTTPException(status_code=400, detail="Missing 'ip'")
    res = allow_container(ip)
    return JSONResponse({"ok": True, "result": res})


@app.get("/config")
def get_config() -> JSONResponse:
    return JSONResponse({
        "ok": True,
        "allowed_services": _parse_allowed_services(),
        "restrict_label": _restrict_label(),
        "watch_docker": os.environ.get("FIREWALL_WATCH_DOCKER", "true"),
        "auto_enable": os.environ.get("FIREWALL_AUTO_ENABLE_ON_START", "true"),
        "port": int(os.environ.get("FIREWALL_API_PORT", "9444")),
        "token_configured": bool(API_TOKEN),
    })


@app.patch("/config", dependencies=[Depends(require_auth)])
def patch_config(body: Dict[str, object]) -> JSONResponse:
    global CURRENT_ALLOWED_SERVICES, CURRENT_RESTRICT_LABEL
    changed: Dict[str, object] = {}
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="Invalid body")
    if "allowed_services" in body:
        val = body.get("allowed_services")
        if isinstance(val, list) and all(isinstance(s, str) for s in val):
            CURRENT_ALLOWED_SERVICES = [s.strip() for s in val if s and isinstance(s, str)]
            changed["allowed_services"] = CURRENT_ALLOWED_SERVICES
        else:
            raise HTTPException(status_code=400, detail="allowed_services must be a list of strings")
    if "restrict_label" in body:
        val2 = body.get("restrict_label")
        if isinstance(val2, str) and val2:
            CURRENT_RESTRICT_LABEL = val2
            changed["restrict_label"] = CURRENT_RESTRICT_LABEL
        else:
            raise HTTPException(status_code=400, detail="restrict_label must be a non-empty string")

    # Optionally re-apply policy
    if body.get("reapply") in (True, "true", 1, "1"):
        _apply_current_policy()

    return JSONResponse({"ok": True, "changed": changed})


def main() -> None:
    host = os.environ.get("FIREWALL_API_HOST", "0.0.0.0")
    port = int(os.environ.get("FIREWALL_API_PORT", "9444"))
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
