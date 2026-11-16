# Installing HuntCompiler on one machine

HuntCompiler runs on the user's or the business's own machine as one Docker Compose stack (D-67). It reads public
threat intelligence from the Internet and serves signed hunting packs; it never connects into your internal network.
The Vietnamese summary is in `README.vi.md`, section 16.

## 1. Choose the machine

Use a dedicated machine or virtual machine, not a workstation used for daily work. HuntCompiler processes text written
by attackers (exploit code, phishing pages, leak posts). It never runs that text, but keeping it away from your own
files and browser sessions limits the damage of any bug.

**Measured on 2026-11-15** (default settings, one tenant, all collectors without API keys, reference datasets loaded):

| Container | Memory, steady | Memory, peak | CPU, peak |
|---|---|---|---|
| worker (4 task processes) | 650 MiB | 690 MiB | 79 % of one core (dataset sync) |
| beat | 80 MiB | 80 MiB | < 1 % |
| api | 64 MiB | 64 MiB | 22 % |
| certstream watcher | 63 MiB | 64 MiB | 1 % |
| PostgreSQL | 37 MiB | 38 MiB | 9 % |
| Redis | 5 MiB | 6 MiB | 2 % |
| **Total** | **about 0.9 GiB** | | |

Most of the worker's memory is the MISP warninglists used by the whitelist (about 300 MiB). The worker loads them
once and its four task processes share them (D-75); before that change the worker needed about 1.5 GiB. The optional
Caddy uses about 15 MiB; the Telegram bot and backup containers add roughly 50 to 100 MiB each.

Disk: the application image is 0.54 GB, the PostgreSQL and Redis images 0.48 GB together, and the data starts at about
50 MB. Raw events are kept 90 days (`HC_RETENTION_RAW_EVENT_DAYS`) and the `backup` profile keeps 14 daily dumps.

| | Minimum | Recommended |
|---|---|---|
| CPU | 2 cores | 4 cores |
| Memory | 4 GB | 8 GB |
| Free disk | 20 GB | 40 GB (with backups) |
| Software | Docker Engine with Compose v2 | the same |

## 2. Install

```bash
git clone <your copy of the repository> huntcompiler && cd huntcompiler
cp .env.example .env
```

Fill in `.env`:

| Setting | How |
|---|---|
| `POSTGRES_PASSWORD`, `REDIS_PASSWORD` | long random strings |
| `HC_MASTER_ENCRYPTION_KEYS` | `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` (or any Fernet key) |
| `HC_TENANT_<NAME>_HMAC_SECRET`, `HC_TENANT_<NAME>_API_TOKEN` | random strings of at least 32 characters; the names are the ones in your manifest |
| `HC_GITHUB_TOKEN` | recommended: a fine-grained personal access token with read-only access to public repositories and no other permission. Without it, KEV alerts still ship, but PoC and Nuclei details are often missing (D-54, D-71) |

Describe your organisation in `config/tenant_manifest.yaml`: public domains, login portals, public IP ranges and the
products you run (`tech_stack_tags`). Public facts only; internal addresses are rejected.

```bash
docker compose up -d --build
docker compose run --rm api python -m scripts.load_manifest config/tenant_manifest.yaml
curl -s http://127.0.0.1:8000/readyz          # {"postgres":"ok","redis":"ok"}
```

Collectors run on a schedule. To fill the reference datasets and check KEV right away:

```bash
docker compose exec worker celery -A app.worker.celery_app:celery_app call collectors.reference_sync
docker compose exec worker celery -A app.worker.celery_app:celery_app call collectors.edge_exploit_sweep
```

Optional sources and features, each off until configured:
- URLScan (`HC_URLSCAN_API_KEY`), MalwareBazaar (`HC_ABUSECH_AUTH_KEY`).
- HIBP and Telegram CTI: read the usage rules in D-73 first (public channels only, a separate research account, only
  domains you own and have verified).
- Telegram digest and command bot: `TELEGRAM.md` §8.
- AI rule drafting with Gemini: off by default; needs your own paid key and a daily budget (D-68).

## 3. Let consumers reach the API

The API listens on `127.0.0.1:8000` only. Pick one of three set-ups:

**Consumer on the same machine.** Point it at `http://127.0.0.1:8000`. The reference consumer accepts plain HTTP for
`localhost` and loopback addresses only (D-72); everything else needs HTTPS.

**Consumers elsewhere in your LAN (no public name).** Caddy issues the certificate from its own local CA:

```bash
# in .env: HC_TLS_MODE=internal and HC_PUBLIC_HOSTNAME=<the LAN name or IP consumers use>, e.g. huntcompiler.lan
docker compose --profile edge up -d caddy
docker compose cp caddy:/data/caddy/pki/authorities/local/root.crt ./huntcompiler-root.crt
```

Copy `huntcompiler-root.crt` to each consumer machine and set `HC_KIT_CA_BUNDLE` to its path (or add it to that
machine's trust store). The root stays valid for years; Caddy renews the server certificate on its own. To test from
Windows with the built-in curl, add `--ssl-no-revoke`: the local CA publishes no revocation list, which Windows checks
by default (the chain and the name are still verified). Allow ports
443 (and 80, which only redirects) from the LAN in the host firewall; do not forward them from the Internet.

**Consumers on the Internet.** Leave `HC_TLS_MODE=public`, set `HC_PUBLIC_HOSTNAME` to a DNS name that points to this
machine, open ports 80 and 443, and start the same `edge` profile. Caddy obtains a Let's Encrypt certificate.

In every case only `/api/v1/*` and `/healthz` are reachable through Caddy.

## 4. Update

```bash
git pull
docker compose up -d --build          # the migrate service applies database migrations before the API starts
docker compose run --rm api python -m scripts.load_manifest config/tenant_manifest.yaml   # if the manifest changed
```

Read `DECISIONS.md` for changes in behaviour before updating a production installation.

## 5. Back up

```bash
docker compose --profile backup up -d backup
```

One `pg_dump` a day, the newest 14 kept in the `pg_backups` volume. Restore steps are in `README.md` ("Backups"). The
dumps live on the same machine: copy them elsewhere for disaster recovery (D-60).

## 6. Uninstall

```bash
docker compose --profile edge --profile backup --profile certstream --profile telegram down -v   # deletes all data
docker image rm outsight-huntcompiler:dev
```

`down -v` removes the database, the backups and Caddy's certificates. Take a last backup first if you may need the
data again. Then delete the project folder and revoke the tokens you created for it (GitHub, Telegram, HIBP, Gemini).
