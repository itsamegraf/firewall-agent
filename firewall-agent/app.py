"""
firewall-agent: HTTPS API entrypoint (FastAPI/Flask to be added).

Purpose:
 - Expose endpoints:
     POST /enable  -> apply firewall rules
     POST /disable -> flush/failsafe
     GET  /status  -> report current rules and agent state
 - Protect with TLS (self-signed cert initially)
 - Integrate with docker_client.py to discover containers and labels
 - Use iptables.py to enforce DOCKER-USER chain rules

This file will be implemented after the iptables core utilities are ready.
"""

if __name__ == "__main__":
    # Placeholder run loop; the FastAPI/Flask app will be added next.
    print("firewall-agent API server placeholder. Coming soon.")

