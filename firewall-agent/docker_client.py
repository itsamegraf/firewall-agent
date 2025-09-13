"""
docker_client.py - Docker API helpers for firewall-agent (skeleton)

Responsibilities (to be implemented next):
 - Connect to the Docker Engine via /var/run/docker.sock (docker-py)
 - List running containers with metadata (names, labels, IPs)
 - Resolve service containers and their IPs by service name
 - Filter containers by a restriction label (e.g., firewall.restrict=true)

This module will be used by app.py to determine which containers should be
allowed to bypass WAN restrictions and which should be restricted.
"""

from __future__ import annotations

from typing import Dict, List


def list_containers() -> List[Dict]:
    """Return a list of containers with minimal metadata.

    Placeholder: to be implemented using docker SDK.
    """
    return []


def resolve_service_ips(service_name: str) -> List[str]:
    """Return a list of IPv4 addresses for containers of a given service.

    Placeholder: to be implemented using docker SDK.
    """
    return []


def list_restricted_containers(restrict_label: str) -> List[Dict]:
    """Return containers that have the restrict_label set to a truthy value.

    Placeholder: to be implemented using docker SDK.
    """
    return []

