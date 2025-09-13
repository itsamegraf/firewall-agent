"""
iptables.py - DOCKER-USER chain manager for firewall-agent

Responsibilities:
 - Idempotently manage the DOCKER-USER chain for container egress filtering
 - Provide simple operations:
     reset_rules()   -> flush and add baseline rules incl. default DROP
     allow_container(ip) -> allow a specific container source IP to egress (WAN)
     allow_service(service_name) -> resolve service containers via Docker SDK and allow their IPs
     status()        -> report current chain state and rules

Notes:
 - Uses RETURN (allow) and a final DROP in DOCKER-USER to filter container traffic.
 - Allows internal/private networks by default (RFC1918/LL/mcast), then drops everything else.
 - Designed to be re-run safely. Re-applying reset_rules() is idempotent.
 - Requires CAP_NET_ADMIN and host network namespace access.

CLI (for debugging):
   python firewall-agent/iptables.py reset
   python firewall-agent/iptables.py allow-ip 10.0.0.12
   python firewall-agent/iptables.py allow-service gluetun
   python firewall-agent/iptables.py status
   python firewall-agent/iptables.py disable
"""

from __future__ import annotations

import ipaddress
import logging
import os
import shlex
import shutil
import subprocess
import sys
from typing import Dict, List, Optional


# ----- Configuration -----
DOCKER_USER_CHAIN = "DOCKER-USER"
COMMENT_PREFIX = "firewall-agent"

# Conservative defaults for "internal" destinations allowed for container ↔ container comms.
PRIVATE_CIDRS = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",  # link-local
    "224.0.0.0/4",     # multicast
    "255.255.255.255/32",  # broadcast
]


logging.basicConfig(
    level=os.environ.get("FIREWALL_LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("firewall-agent.iptables")


class IptablesError(RuntimeError):
    pass


def _which(binary: str) -> str:
    path = shutil.which(binary)
    if path:
        return path
    # Common fallback locations in minimal images
    fallbacks = [f"/usr/sbin/{binary}", f"/sbin/{binary}"]
    for fb in fallbacks:
        if os.path.exists(fb):
            return fb
    raise IptablesError(f"Required binary not found: {binary}")


IPTABLES = _which("iptables")
IPTABLES_SAVE = _which("iptables-save")


def _run(cmd: List[str], check: bool = False) -> subprocess.CompletedProcess:
    """Run a command, return the CompletedProcess. Raises if check=True and rc!=0."""
    log.debug("$ %s", " ".join(shlex.quote(c) for c in cmd))
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if check and proc.returncode != 0:
        raise IptablesError(f"Command failed ({proc.returncode}): {' '.join(cmd)}\n{proc.stderr}")
    return proc


def _iptables(args: List[str], check: bool = False) -> subprocess.CompletedProcess:
    return _run([IPTABLES] + args, check=check)


def _iptables_save() -> str:
    proc = _run([IPTABLES_SAVE, "-t", "filter"], check=True)
    return proc.stdout


def _ensure_chain_and_hook() -> None:
    """Ensure DOCKER-USER exists and FORWARD jumps to it once. Safe/idempotent."""
    # Ensure chain exists
    proc = _iptables(["-S", DOCKER_USER_CHAIN])
    if proc.returncode != 0:
        log.info("Creating chain %s", DOCKER_USER_CHAIN)
        _iptables(["-N", DOCKER_USER_CHAIN], check=True)

    # Ensure FORWARD -> DOCKER-USER hook exists once
    exists = _iptables(["-C", "FORWARD", "-j", DOCKER_USER_CHAIN]).returncode == 0
    if not exists:
        log.info("Hooking FORWARD -> %s", DOCKER_USER_CHAIN)
        _iptables(["-I", "FORWARD", "1", "-j", DOCKER_USER_CHAIN, "-m", "comment", "--comment", f"{COMMENT_PREFIX}:hook"], check=True)


def reset_rules() -> Dict[str, object]:
    """Flush and set baseline rules with default DROP at end.

    Baseline rules:
      - RETURN established/related
      - RETURN for internal/private destinations
      - DROP everything else (WAN egress blocked unless explicitly allowed)
    """
    _ensure_chain_and_hook()

    log.info("Flushing %s", DOCKER_USER_CHAIN)
    _iptables(["-F", DOCKER_USER_CHAIN], check=True)

    # 1) Allow established/related
    _iptables([
        "-A", DOCKER_USER_CHAIN,
        "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED",
        "-j", "RETURN",
        "-m", "comment", "--comment", f"{COMMENT_PREFIX}:established",
    ], check=True)

    # 2) Allow internal/private destinations (RFC1918 etc.)
    for cidr in PRIVATE_CIDRS:
        _iptables([
            "-A", DOCKER_USER_CHAIN,
            "-d", cidr,
            "-j", "RETURN",
            "-m", "comment", "--comment", f"{COMMENT_PREFIX}:allow-internal:{cidr}",
        ], check=True)

    # 3) Final default DROP
    _iptables([
        "-A", DOCKER_USER_CHAIN,
        "-j", "DROP",
        "-m", "comment", "--comment", f"{COMMENT_PREFIX}:default-drop",
    ], check=True)

    s = status()
    log.info("Baseline applied: %s", {k: s[k] for k in ("enabled", "rule_count")})
    return s


def _rule_exists_allow_src(ip: str) -> bool:
    """Return True if a RETURN rule for the given source IP exists in DOCKER-USER.

    Uses iptables-save text parsing to ignore comments while matching semantics.
    """
    ip_obj = ipaddress.ip_address(ip)
    cidr = f"{ip_obj}/32" if ip_obj.version == 4 else f"{ip_obj}/128"
    text = _iptables_save()
    needle1 = f"-A {DOCKER_USER_CHAIN} -s {cidr} "
    needle2 = " -j RETURN"
    for line in text.splitlines():
        if line.startswith(f"-A {DOCKER_USER_CHAIN}") and (f" -s {cidr} " in line) and (needle2 in line):
            return True
    return False


def allow_container(ip: str) -> Dict[str, object]:
    """Allow a specific container source IP to egress to WAN.

    Idempotent: does nothing if the rule already exists.
    """
    try:
        ipaddress.ip_address(ip)
    except ValueError as e:
        raise IptablesError(f"Invalid IP address: {ip}") from e

    _ensure_chain_and_hook()

    if _rule_exists_allow_src(ip):
        log.info("Allow rule already present for %s", ip)
        return {"allowed": False, "ip": ip, "reason": "exists"}

    log.info("Allowing container IP to egress: %s", ip)
    # Insert at top to take precedence
    _iptables([
        "-I", DOCKER_USER_CHAIN, "1",
        "-s", ip,
        "-j", "RETURN",
        "-m", "comment", "--comment", f"{COMMENT_PREFIX}:allow-ip:{ip}",
    ], check=True)
    return {"allowed": True, "ip": ip}


def _docker_client():
    """Return docker-py client if available, else raise informative error."""
    try:
        import docker  # type: ignore
    except Exception as e:  # pragma: no cover - best-effort path
        raise IptablesError(
            "docker SDK not available. Install 'docker' package and mount /var/run/docker.sock"
        ) from e
    try:
        return docker.from_env()
    except Exception as e:
        raise IptablesError("Failed to connect to Docker via /var/run/docker.sock") from e


def _container_ips(container) -> List[str]:
    ips: List[str] = []
    try:
        networks = container.attrs.get("NetworkSettings", {}).get("Networks", {})
        for net in networks.values():
            ip = net.get("IPAddress")
            if ip:
                ips.append(ip)
    except Exception:
        pass
    return ips


def allow_service(service_name: str) -> Dict[str, object]:
    """Resolve a Swarm/Compose service by name and allow all its container IPs.

    Matching strategy:
      - Prefer Swarm label 'com.docker.swarm.service.name' == service_name
      - Fallback: container name contains service_name as substring
    """
    cli = _docker_client()
    containers = cli.containers.list(all=False)
    matched = []
    ips_added: List[str] = []

    for c in containers:
        try:
            c.reload()
        except Exception:
            pass
        labels = (c.labels or {})
        swarm_name = labels.get("com.docker.swarm.service.name")
        name_matches = service_name in (c.name or "")
        if swarm_name == service_name or name_matches:
            matched.append(c)

    for c in matched:
        for ip in _container_ips(c):
            res = allow_container(ip)
            if res.get("allowed"):
                ips_added.append(ip)

    return {
        "service": service_name,
        "containers": [getattr(c, "name", None) for c in matched],
        "ips": ips_added,
    }


def disable() -> Dict[str, object]:
    """Failsafe: flush DOCKER-USER (removes our DROP) so traffic is not blocked."""
    _ensure_chain_and_hook()
    _iptables(["-F", DOCKER_USER_CHAIN], check=True)
    s = status()
    log.warning("Firewall disabled (chain flushed)")
    return s


def status() -> Dict[str, object]:
    """Return current chain status and summary."""
    s_out = _iptables(["-S", DOCKER_USER_CHAIN]).stdout
    enabled = f"--comment {COMMENT_PREFIX}:default-drop" in s_out or f"{COMMENT_PREFIX}:default-drop" in s_out

    # Gather allowlisted IPs from iptables-save, looking for RETURN rules with our comment
    saved = _iptables_save()
    allow_ips: List[str] = []
    rules_total = 0
    for line in saved.splitlines():
        if not line.startswith(f"-A {DOCKER_USER_CHAIN}"):
            continue
        rules_total += 1
        if " -j RETURN" in line and f"--comment \"{COMMENT_PREFIX}:allow-ip:" in line:
            # Extract IP: look for "-s X/32"
            parts = line.split()
            if "-s" in parts:
                try:
                    ip_cidr = parts[parts.index("-s") + 1]
                    ip = ip_cidr.split("/")[0]
                    allow_ips.append(ip)
                except Exception:
                    pass

    return {
        "chain": DOCKER_USER_CHAIN,
        "enabled": enabled,
        "rule_count": rules_total,
        "allow_ips": sorted(set(allow_ips)),
        "raw": s_out,
    }


def _usage() -> None:
    print(
        "Usage: iptables.py [reset|disable|status|allow-ip <ip>|allow-service <name>]",
        file=sys.stderr,
    )


if __name__ == "__main__":
    if len(sys.argv) < 2:
        _usage()
        sys.exit(1)

    action = sys.argv[1]
    try:
        if action == "reset":
            out = reset_rules()
            print(out)
        elif action == "disable":
            out = disable()
            print(out)
        elif action == "status":
            out = status()
            print(out)
        elif action == "allow-ip" and len(sys.argv) >= 3:
            out = allow_container(sys.argv[2])
            print(out)
        elif action == "allow-service" and len(sys.argv) >= 3:
            out = allow_service(sys.argv[2])
            print(out)
        else:
            _usage()
            sys.exit(2)
    except Exception as e:  # pragma: no cover
        log.error("Error: %s", e)
        sys.exit(1)
