# AI-Powered Network Intrusion Detection & Threat Intelligence Platform

A real-time working platform that captures network traffic, aggregates it into flows,
classifies known attacks with a Random Forest model, flags unknown/zero-day anomalies
with an Isolation Forest, explains every prediction with SHAP, and pushes live results
to a Next.js dashboard over WebSockets.

## Architecture

```
Live packets (Scapy) ──▶ Flow Tracker ──▶ Feature Extraction ──▶ ML Pipeline
                                                                   │
                              ┌────────────────────────────────────┤
                              ▼                                    ▼
                     Random Forest (known attacks)        Isolation Forest (anomalies)
                              │                                    │
                              └─────────────────┬──────────────────┘
                                                 ▼
                                     SHAP Explainability
                                                 ▼
                                    Threat Intelligence Engine
                                                 ▼
                              PostgreSQL  ◀──▶  Alert Engine
                                                 ▼
                          FastAPI REST + WebSocket ──▶ Next.js Dashboard
```

Also accepts traffic via `POST /api/predict` (single flow) and `POST /api/upload-pcap`
(offline `.pcap`/`.pcapng` replay through the same pipeline) — useful since live
capture only sees whatever traffic actually crosses your NIC while it's running.

## Important: about the ML models

There is no bundled real-world attack dataset. `backend/app/ml/dataset.py` generates a
synthetic, labeled flow-feature dataset whose statistical shape mirrors documented
attack behavior (port scans = many tiny high-SYN flows, DDoS = huge packets/sec with
tiny average size, brute force = many short bursts to one port, normal = everyday
traffic). This is enough to make the full pipeline trainable and demonstrable end to
end. Before relying on this for anything beyond a demo/project, retrain on a real
labeled capture (e.g. CICIDS2017, NSL-KDD, or your own labeled pcaps) by swapping
`generate_dataset()` for a loader over real data — `train.py` doesn't otherwise need to
change.

### Known limitations, found while validating against real captured traffic

Running live capture against genuine loopback traffic (not just synthetic test payloads)
surfaced real calibration issues, since fixed or documented rather than papered over:

- **Flow fragmentation on TCP teardown** — the flow tracker used to start a *new*
  flow for any stray packet with no matching open flow, so the tail end of a
  connection's close sequence (an ACK arriving just after the flow completed on
  FIN) produced a bogus 1-2-packet "flow" that looked identical to a port scan.
  Fixed in [`app/capture/flow_tracker.py`](backend/app/capture/flow_tracker.py):
  a non-SYN TCP packet with no open flow is now dropped instead of starting one.
- **Training data didn't model fast local traffic** — the original synthetic
  "normal" class was shaped like WAN/LAN sessions (hundreds of ms to seconds,
  ~500-byte packets). A real sub-millisecond loopback request/response has
  packets/sec in the thousands purely from being fast, which looked identical to
  an attack. Fixed by adding a `normal_fast` sub-population to
  [`app/ml/dataset.py`](backend/app/ml/dataset.py) modeling clean quick
  handshake-to-close flows (the actual discriminator is the SYN/ACK/FIN shape,
  not raw rate).
- **A NIDS monitoring its own control-plane traffic** — when capture, backend,
  and frontend all share one loopback interface, the dashboard's own long-lived
  WebSocket connection to the backend is itself traffic on that interface, and
  its high packet count got misclassified as `ddos`. Fixed by excluding the
  backend's own port (`CAPTURE_EXCLUDE_PORTS`, default `[8000]`) from capture.
- **Still open**: rapid repeated connections to one port (application-layer
  brute forcing) get flagged as `unknown_anomaly` rather than the specific
  `brute_force` label. Each individual flow's packet shape is indistinguishable
  from a single legitimate fast request — telling them apart really needs a
  session/rate feature (connections-per-source-per-minute), not just per-flow
  features. The anomaly detector still catches it; the label is just less
  specific. Worth fixing before relying on the attack-type label alone.

## Prerequisites

- Python 3.12 (Homebrew: `brew install python@3.12` — newer Python builds may lack
  wheels for scikit-learn/shap/scapy)
- Node.js 20+
- Docker Desktop (for Postgres, or run the whole stack via `docker compose`)
- macOS/Linux root privileges only if you want **live** packet capture

## Quick start (local, no Docker for the app code)

### 1. Start Postgres

```bash
docker compose up -d postgres
```

### 2. Backend

```bash
cd backend
/opt/homebrew/bin/python3.12 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt -r requirements-extra.txt
cp .env.example .env

# Train the ML models (writes backend/app/ml/models/*.joblib)
python -m app.ml.train

# Seed the default admin user (admin@nids-platform.io / ChangeMe123!)
python -m app.seed

# Run the API (no sudo needed — CAPTURE_ENABLED=false by default)
uvicorn app.main:app --reload --port 8000
```

Visit `http://localhost:8000/api/health` to confirm `models_trained: true`.

Interactive API docs: `http://localhost:8000/docs`

### 3. Frontend

```bash
cd frontend
npm install
cp .env.local.example .env.local
npm run dev
```

Visit `http://localhost:3000`, log in with `admin@nids-platform.io` / `ChangeMe123!`.

### 4. Generate traffic to see detections

The dashboard starts empty until flows are analyzed. Three ways to feed it:

**A. Manual prediction (fastest way to see it work):**
```bash
curl -X POST http://localhost:8000/api/predict \
  -H "Authorization: Bearer <token from /api/login>" \
  -H "Content-Type: application/json" \
  -d '{"duration":0.05,"total_packets":40,"total_bytes":3200,"avg_packet_size":80,
       "syn_count":40,"ack_count":0,"fin_count":0,"packets_per_sec":800,
       "bytes_per_sec":64000,"source_ip":"10.0.0.5","destination_ip":"10.0.0.1"}'
```
This shape (many SYNs, tiny packets, no ACKs) should classify as `port_scan`.

**B. Upload a pcap:** capture some traffic with Wireshark/tcpdump (or use a sample
`.pcap`) and `POST` it as multipart form data to `/api/upload-pcap`.

**C. Live capture (fully real-time, no manual API calls):**

Raw packet capture needs BPF/raw-socket access, which is root-only by default.
Two ways to get it:

- *One-off*: `sudo .venv/bin/uvicorn app.main:app --port 8000` (re-enter your
  password every time you restart).
- *Permanent* (recommended — same fix Wireshark's installer applies): run
  `sudo bash scripts/setup-live-capture-macos.sh` once, log out and back in,
  then run uvicorn normally, no `sudo` needed ever again. See
  [scripts/setup-live-capture-macos.sh](scripts/setup-live-capture-macos.sh)
  for exactly what it does (creates an `access_bpf` group + LaunchDaemon).

Either way, in `backend/.env` set `CAPTURE_ENABLED=true`. For a self-contained,
fully-authorized demo that doesn't touch your real network traffic, set
`CAPTURE_INTERFACE=lo0` (loopback) and run the bundled local traffic generator
in another terminal:

```bash
cd backend && source .venv/bin/activate
python -m app.demo_traffic
```

This starts a local HTTP server on `127.0.0.1:8765` and continuously drives real
localhost traffic against it — ordinary request bursts most of the time, with
periodic port-scan-shaped and brute-force-shaped bursts mixed in. Since the
backend is sniffing `lo0`, every one of those is a genuine captured packet
flowing through flow aggregation → ML classification → SHAP → threat intel →
DB → WebSocket → dashboard, with zero manual `/predict` calls.

To point capture at your real network interface instead of loopback, set
`CAPTURE_INTERFACE` to it (macOS: `ifconfig -l` to list, usually `en0`; Linux:
`ip link`) — only do this against traffic you're authorized to monitor.

## Running everything via Docker Compose

```bash
docker compose up --build
```
This builds and starts Postgres, the backend (models are trained at image build time,
admin user seeded on container start), and the frontend, all wired together. Live
capture inside a container needs host networking + `NET_RAW`/`NET_ADMIN` — see the
commented-out block in `docker-compose.yml`.

## Deployment

Two supported paths — nothing deploys automatically, these configs just make the
platforms' own import/deploy flows work once you connect your own accounts.

**Option A — everything on Vercel as one project** (`vercel.json` at the repo root):
Vercel builds the Next.js frontend and the FastAPI backend as two services in one
project, routed by path (`/api/*` → backend, everything else → frontend). This is
what `vercel.json`'s `entrypoint: "app.main:app"` and the `/api/(.*)` rewrite are
for. Two things to set up yourself in the Vercel dashboard:
- Backend service env vars: `DATABASE_URL` (an external Postgres — Vercel doesn't
  bundle one; Vercel Postgres/Neon/Supabase all work), `JWT_SECRET`,
  `CORS_ORIGINS`, `CAPTURE_ENABLED=false` (Vercel's sandbox has no NIC — live
  capture can never run there, by design, not a bug).
- Frontend env vars: `NEXT_PUBLIC_API_URL=/api`, `NEXT_PUBLIC_WS_URL=wss://<your-domain>/api/ws`
  (relative, same domain — the rewrite handles routing to the backend service).

Vercel's Python functions cap out at 500MB, so this path installs only
`backend/requirements.txt` — **not** `requirements-extra.txt` (`shap` and its
LLVM/numba dependency chain alone blow past that limit, and `scapy` is dead weight
with no NIC to sniff). Predictions still work; explanations fall back from true
SHAP values to the RandomForest's built-in `feature_importances_`
(see [predictor.py](backend/app/ml/predictor.py)), and `/api/upload-pcap` returns a
clear "not installed" error instead of working.

**Option B — split, full-featured** (`frontend/vercel.json` + `render.yaml`):
Frontend on Vercel as its own project, backend on Render as a Dockerized service
(`render.yaml` provisions a free Postgres instance alongside it). Render's Docker
build installs `requirements-extra.txt` too, so SHAP explanations and
`/api/upload-pcap` both work fully — only live capture stays unavailable (no raw
socket access on Render either, same as any managed container host). Set
`NEXT_PUBLIC_API_URL` / `NEXT_PUBLIC_WS_URL` on the frontend to the Render backend's
URL.

## Project layout

```
backend/
  app/
    capture/        Scapy live sniffer + flow aggregation
    ml/              synthetic dataset, training script, RF + Isolation Forest, SHAP
    threat_intel/    severity/risk-score/recommendation mapping
    alerts/          alert persistence + threshold logic
    websocket/       broadcast manager for live dashboard push
    routers/         REST endpoints (auth, traffic, attacks, dashboard, alerts, reports, predict, upload, ws)
    pipeline.py      shared flow -> prediction -> persistence -> alert -> broadcast logic
    models.py        SQLAlchemy models (User, Traffic, Attack, Alert)
    seed.py          creates the default admin user
    demo_traffic.py  generates real localhost traffic (+ attack-shaped bursts) for live-capture demos
scripts/
  setup-live-capture-macos.sh  one-time sudo fix for root-free packet capture on macOS
frontend/
  app/               Next.js App Router pages (login, dashboard)
  components/        stat cards, charts (Recharts), attack table, alert panel
  lib/                API client, auth storage, WebSocket hook
```

## Security notes for real use

This ships with sane defaults for local development, not production:
- Change `JWT_SECRET` and the seeded admin password before any real deployment.
- Live capture requires root — do not run the whole API process as root in
  production; instead grant `CAP_NET_RAW`/`CAP_NET_ADMIN` to a dedicated capture
  process, or run capture in its own least-privileged container.
- Rate limiting and audit logging described in the original spec are not yet wired
  up — add `slowapi` (or a reverse-proxy rate limiter) and an audit log table before
  exposing this beyond a local demo.
