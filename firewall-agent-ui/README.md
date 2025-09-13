# firewall-agent-ui

React + Next.js UI to visualize Docker Swarm containers, networks, and WAN accessibility computed by firewall-agent.

Features
- Live topology fetched from `GET /topology`
- Interactive network graph using Cytoscape.js
- Colors:
  - WAN: blue
  - Networks: slate
  - Allowed containers: green
  - Restricted containers: red
  - Others: amber
  - WAN edges: green (allowed) / red (blocked)

Dev
```
npm install
NEXT_PUBLIC_FIREWALL_API_URL=https://localhost:8443 npm run dev
```

Prod build
```
npm run build
npm start
```

Docker
```
docker build -t firewall-agent-ui -f firewall-agent-ui/Dockerfile .
docker run -e NEXT_PUBLIC_FIREWALL_API_URL=https://api-host:8443 -p 8080:3000 firewall-agent-ui
```

