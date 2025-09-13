"""
docker_client.py - Docker API helpers for firewall-agent

Responsibilities:
 - Connect to the Docker Engine via /var/run/docker.sock (docker SDK)
 - List running containers with metadata (name, labels, IPs, service)
 - Resolve service containers and their IPs by service name
 - Filter containers by a restriction label (e.g., firewall.restrict=true)

Notes:
 - Matching strategy for services prefers the Swarm label
   'com.docker.swarm.service.name'. Also matches if the container name contains
   the requested service name or if the Swarm label endswith "_<service>"
   (useful when stacks prefix the service with the stack name).
 - IPv6 is not handled yet; returned IPs are IPv4 only.
"""

from __future__ import annotations

import json
import logging
from typing import Dict, List, Optional

log = logging.getLogger("firewall-agent.docker")


_DOCKER_CLIENT = None


def _docker_client():
    global _DOCKER_CLIENT
    if _DOCKER_CLIENT is not None:
        return _DOCKER_CLIENT
    try:
        import docker  # type: ignore
    except Exception as e:  # pragma: no cover - best-effort path
        raise RuntimeError(
            "docker SDK not available. Install 'docker' and mount /var/run/docker.sock"
        ) from e
    _DOCKER_CLIENT = docker.from_env()
    return _DOCKER_CLIENT


def _container_network_ips(container) -> Dict[str, str]:
    nets = {}
    try:
        networks = container.attrs.get("NetworkSettings", {}).get("Networks", {})
        for net_name, net in networks.items():
            ip = net.get("IPAddress")
            if ip:
                nets[net_name] = ip
    except Exception:
        pass
    return nets


def _service_label(container) -> Optional[str]:
    try:
        labels = container.labels or {}
        return labels.get("com.docker.swarm.service.name")
    except Exception:
        return None


def _is_truthy(value: Optional[str]) -> bool:
    if value is None:
        return False
    return str(value).strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
        "enable",
        "enabled",
    }


def list_containers() -> List[Dict]:
    """Return a list of running containers and metadata.

    Each item contains: id, name, labels, service, ips (list), networks (map)
    """
    cli = _docker_client()
    result: List[Dict] = []
    for c in cli.containers.list(all=False):
        try:
            c.reload()
        except Exception:
            pass
        nets = _container_network_ips(c)
        labels = c.labels or {}
        item = {
            "id": getattr(c, "id", None),
            "name": getattr(c, "name", None),
            "labels": labels,
            "service": _service_label(c),
            "ips": list(nets.values()),
            "networks": nets,
        }
        result.append(item)
    return result


def resolve_service_ips(service_name: str) -> List[str]:
    """Return IPv4 addresses for containers of a given service.

    Matching precedence:
      1) com.docker.swarm.service.name == service_name
      2) com.docker.swarm.service.name endswith _<service_name>
      3) container.name contains service_name
    """
    cli = _docker_client()
    ips: List[str] = []

    for c in cli.containers.list(all=False):
        try:
            c.reload()
        except Exception:
            pass
        svc = _service_label(c)
        name = getattr(c, "name", "") or ""
        if svc == service_name or (
            isinstance(svc, str) and svc.endswith(f"_{service_name}")
        ) or (service_name in name):
            nets = _container_network_ips(c)
            ips.extend(ip for ip in nets.values() if ip)

    # Deduplicate, stable order
    seen = set()
    out: List[str] = []
    for ip in ips:
        if ip not in seen:
            seen.add(ip)
            out.append(ip)
    return out


def list_restricted_containers(restrict_label: str) -> List[Dict]:
    """Return containers having the restrict_label set to a truthy value."""
    res: List[Dict] = []
    for item in list_containers():
        val = (item.get("labels") or {}).get(restrict_label)
        if _is_truthy(val):
            res.append(item)
    return res


if __name__ == "__main__":
    # Minimal CLI for debugging
    import argparse

    parser = argparse.ArgumentParser(description="Docker helpers for firewall-agent")
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("list", help="List running containers and metadata")

    p1 = sub.add_parser("resolve-service", help="Resolve service IPs")
    p1.add_argument("name")

    p2 = sub.add_parser("restricted", help="List containers with restrict label truthy")
    p2.add_argument("label")

    args = parser.parse_args()

    if args.cmd == "list":
        print(json.dumps(list_containers(), indent=2))
    elif args.cmd == "resolve-service":
        print(json.dumps(resolve_service_ips(args.name), indent=2))
    elif args.cmd == "restricted":
        print(json.dumps(list_restricted_containers(args.label), indent=2))
    else:
        parser.print_help()
        exit(2)
