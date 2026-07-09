# Install

### Prerequisites

- Docker 24+
- Docker Compose v2 (`docker compose`, not the legacy `docker-compose`)
- One free public DNS name if you want Caddy to provision Let's Encrypt
  certificates automatically (otherwise the stack falls back to a
  self-signed certificate).

### 60-second launch

```bash
curl -fsSL https://raw.githubusercontent.com/ssnrshnn/NACo/main/install.sh | bash
```

That's it. The installer clones the repo and runs `quickstart.sh`, which
checks prerequisites, generates `.env` with strong secrets plus the EAP
certificates, pulls the prebuilt image from GHCR (building locally only as
a fallback), starts the stack, and prints the generated admin password.
Everything lives in **one** `docker-compose.yml` at the repository root.

Prefer explicit steps?

```bash
git clone https://github.com/ssnrshnn/NACo.git
cd NACo
./quickstart.sh          # or continue fully by hand:
```

```bash
cp .env.example .env     # fill in the REQUIRED values
docker compose up -d
docker compose logs -f naco
```

Then open:

- Admin UI:  `https://<your-host>/`  (default login `admin` /
  `${NACO_ADMIN_PASSWORD}` — **change at first login**)
- REST API:  `https://<your-host>/api/v1/docs`
- Portal:     `http://<your-host>/portal` (captive portals must be HTTP)
- Metrics:   `https://<your-host>/api/v1/metrics`

### Optional features (same file, compose profiles)

```bash
# FreeRADIUS 802.1X (EAP-TLS / EAP-TTLS / PEAP) is ON by default — skip it with:
./quickstart.sh --no-eap

# Add Prometheus + Grafana + Loki + Promtail
./quickstart.sh --obs

# Profiles are pinned in .env:  COMPOSE_PROFILES=eap,obs
```

---
