# SIEM Lab — Elastic Stack (ELK) Deployment with TLS & Log Ingestion

**TL;DR:** A hardened, TLS-secured Elastic Stack SIEM lab — built, encrypted end-to-end, connected to a live log source, and debugged from scratch. Includes real issues hit along the way and how they were diagnosed and fixed (see [Troubleshooting Notes](#-troubleshooting-notes-real-issues-encountered)).

A SIEM (Security Information and Event Management) system is what security teams use to collect logs from across an organization's servers and devices, then search, monitor, and alert on that data to catch suspicious activity. This repo documents a self-hosted, security-hardened Elastic Stack (Elasticsearch, Logstash, Kibana) deployed via Docker Compose, with end-to-end TLS encryption and a live log ingestion pipeline from a real Linux host using Filebeat.

This project was built as a hands-on cybersecurity lab to practice the same architecture used in real-world SIEM deployments — from infrastructure setup, to security hardening, to actual log analysis.

---

## 📋 Table of Contents

- [Architecture](#-architecture)
- [Prerequisites](#-prerequisites)
- [Project Structure](#-project-structure)
- [Part 1: Base Deployment](#part-1-base-deployment)
- [Part 2: Security Hardening (TLS)](#part-2-security-hardening-tls)
- [Part 3: Log Ingestion Pipeline](#part-3-log-ingestion-pipeline)
- [Verification](#-verification)
- [Troubleshooting Notes](#-troubleshooting-notes-real-issues-encountered)
- [Lessons Learned](#-lessons-learned)
- [Roadmap](#-roadmap)
- [Screenshots](#-screenshots)

---

## 🏗 Architecture

```
┌─────────────────┐     ┌──────────────┐     ┌───────────────┐     ┌─────────┐
│  Filebeat        │────▶│  Logstash    │────▶│ Elasticsearch │◀────│ Kibana  │
│  (host service)  │     │  (Docker)    │     │  (Docker)     │     │ (Docker)│
│  reads:          │     │  port 5044   │     │  port 9200    │     │port 5601│
│  /var/log/syslog │     │  Beats input │     │  HTTPS only   │     │  HTTPS  │
│  /var/log/auth.log│    │  → HTTPS out │     │  auth enabled │     │         │
└─────────────────┘     └──────────────┘     └───────────────┘     └─────────┘
```

All inter-service traffic (Logstash→Elasticsearch, Kibana→Elasticsearch) and all browser-facing traffic (Kibana) is encrypted via a self-signed CA generated specifically for this lab.

**Stack versions:** Elasticsearch 8.12.0 · Kibana 8.12.0 · Logstash 8.12.0 · Filebeat 8.12.0

---

## ✅ Prerequisites

- A Linux host or VM (this project used Ubuntu 22.04 on VMware Workstation)
- Docker & Docker Compose installed
- At least 4GB RAM allocated to the host/VM
- Basic command-line familiarity

---

## 📁 Project Structure

```
elk-stack/
├── docker-compose.yml
├── elasticsearch/
│   └── certs/              # CA + service certificates (generated, not committed)
│       ├── ca.crt
│       ├── http.crt / http.key
│       └── kibana.crt / kibana.key
├── logstash/
│   └── pipeline/
│       └── logstash.conf   # Beats input → Elasticsearch output
└── kibana/
```

> ⚠️ **Never commit the `certs/` folder or real passwords to a public repository.** This README uses lab-only placeholder credentials for illustration.

---

## Part 1: Base Deployment

The stack is defined in a single `docker-compose.yml` with three services: `elasticsearch`, `logstash`, and `kibana`, all sharing a Docker bridge network (`elk-net`).

Key base configuration:
- Single-node Elasticsearch (`discovery.type=single-node`) — appropriate for a lab, not production
- `xpack.security.enabled=true` from the start — authentication is on by default in modern Elastic Stack versions
- A named Docker volume (`es_data`) persists Elasticsearch's data across restarts

```bash
docker compose up -d
docker ps   # confirm all three containers are Up
```

📸 *[Screenshot: `docker ps` showing all three containers running]*
<img width="1269" height="525" alt="Logstash-Elasticsearch-Kibana" src="https://github.com/user-attachments/assets/d65eac04-f3e2-416d-a6eb-02edb2c22400" />


📸 *[Screenshot: initial Kibana login page over plain HTTP]*
<img width="1279" height="737" alt="HTTP login page" src="https://github.com/user-attachments/assets/cd9bb3d5-6625-4f5d-ac21-4a1c87967156" />

---

## Part 2: Security Hardening (TLS)

By default, this stack only had authentication enabled — traffic itself was still unencrypted. The following hardening was applied in stages.

### 2.1 Verifying Security Enforcement

```bash
curl http://localhost:9200/_cluster/health
# → 401 security_exception: missing authentication credentials
```

📸 *[Screenshot: 401 response confirming security is enforced]*
<img width="1273" height="779" alt="Docker Compose Health check" src="https://github.com/user-attachments/assets/e5855ae3-0621-471b-ab72-e42327bd16c9" />


### 2.2 Generating a Certificate Authority and Certificates

Using Elasticsearch's built-in `certutil` tool, run from inside the running container:

```bash
# Generate a CA
docker exec elasticsearch bin/elasticsearch-certutil ca --pem --out /tmp/ca.zip
docker exec elasticsearch unzip /tmp/ca.zip -d /tmp/ca-unzipped

# Issue a certificate for Elasticsearch's HTTP layer
docker exec elasticsearch bin/elasticsearch-certutil cert \
  --ca-cert /tmp/ca-unzipped/ca/ca.crt --ca-key /tmp/ca-unzipped/ca/ca.key \
  --pem --out /tmp/http.zip \
  --name elasticsearch --dns elasticsearch --dns localhost --ip 127.0.0.1

# Issue a certificate for Kibana's own web server
docker exec elasticsearch bin/elasticsearch-certutil cert \
  --ca-cert /tmp/ca-unzipped/ca/ca.crt --ca-key /tmp/ca-unzipped/ca/ca.key \
  --pem --out /tmp/kibana-http.zip \
  --name kibana --dns kibana --dns localhost --ip 127.0.0.1
```

Certificates are then copied out of the container onto the host (`docker cp`) into `elasticsearch/certs/`, so they persist and can be mounted into every service — container `/tmp` storage does **not** survive a container recreate.

📸 *[Screenshot: certificate files listed in `elasticsearch/certs/`]*
<img width="1265" height="772" alt="Creating CA HTTPS Certificates" src="https://github.com/user-attachments/assets/5402b230-53a9-42b0-a650-ce77725f5e81" />


### 2.3 Enabling HTTPS on Elasticsearch

Added to the `elasticsearch` service environment:
```yaml
- xpack.security.http.ssl.enabled=true
- xpack.security.http.ssl.key=certs/http.key
- xpack.security.http.ssl.certificate=certs/http.crt
- xpack.security.http.ssl.certificate_authorities=certs/ca.crt
```
With the certs folder mounted as a volume into `/usr/share/elasticsearch/config/certs`.

### 2.4 Enabling HTTPS on Kibana (both legs)

Two separate things had to be configured — easy to miss one:

**Kibana → Elasticsearch** (Kibana as a client):
```yaml
- ELASTICSEARCH_HOSTS=https://elasticsearch:9200
- ELASTICSEARCH_SSL_CERTIFICATEAUTHORITIES=/usr/share/kibana/config/certs/ca.crt
```

**Browser → Kibana** (Kibana's own web server):
```yaml
- SERVER_SSL_ENABLED=true
- SERVER_SSL_CERTIFICATE=/usr/share/kibana/config/certs/kibana.crt
- SERVER_SSL_KEY=/usr/share/kibana/config/certs/kibana.key
```

📸 *[Screenshot: Kibana loading over HTTPS with self-signed cert warning]*
<img width="1260" height="722" alt="Kibana HTTPS warning" src="https://github.com/user-attachments/assets/527e6442-04ec-472d-826d-8410df411be0" />


📸 *[Screenshot: successful Kibana login over HTTPS]*
<img width="1267" height="737" alt="Kibana Homepage" src="https://github.com/user-attachments/assets/efa20311-576c-4666-bd4e-cb8695bb88de" />

---

## Part 3: Log Ingestion Pipeline

With the stack secured, the next step was ingesting real data — this server's own system logs — via Filebeat.

### 3.1 Filebeat (installed on the host, not in Docker)

`/etc/filebeat/filebeat.yml`:
```yaml
filebeat.inputs:
  - type: filestream
    enabled: true
    paths:
      - /var/log/syslog
      - /var/log/auth.log

output.logstash:
  hosts: ["localhost:5044"]
```

```bash
sudo systemctl enable filebeat --now
sudo systemctl status filebeat   # should show active (running)
```

### 3.2 Logstash Pipeline

`logstash/pipeline/logstash.conf`, mounted into the `logstash` container:
```
input {
  beats {
    port => 5044
  }
}

output {
  elasticsearch {
    hosts => ["elasticsearch:9200"]
    ssl_enabled => true
    ssl_certificate_authorities => ["/usr/share/logstash/certs/ca.crt"]
    user => "elastic"
    password => "......"
    index => "filebeat-lab-%{+YYYY.MM.dd}"
  }
}
```

### 3.3 Creating the Kibana Data View

In **Stack Management → Data Views**, a data view was created for `filebeat-lab-*` with `@timestamp` as the time field, exposing 61 auto-detected fields from the ingested documents.

📸 *[Screenshot: Data View creation screen showing matched index]*
<img width="635" height="381" alt="Filebeat Dataview" src="https://github.com/user-attachments/assets/4ee04da0-092a-4d37-b7a3-a182fb945f79" />



---

## ✅ Verification

```bash
curl -k -u elastic:<mypassword> https://myhostip:9200/_cat/indices?v
```
Confirms the `filebeat-lab-*` index exists with a non-zero document count.

📸 *[Screenshot: Kibana Discover showing 500 hits of real log data]*
<img width="1259" height="484" alt="file beat confirmed" src="https://github.com/user-attachments/assets/c51988c8-2a49-4230-967f-2ca03b3dd92f" />

---

## 🐛 Troubleshooting Notes (real issues encountered)

| Issue | Root Cause | Fix |
|---|---|---|
| `password empty` error during cert generation | Passed `--pass ""` explicitly | Omit the flag entirely rather than passing an empty string |
| Lost CA private key after a restart | `/tmp` inside a container doesn't persist across recreate | Regenerated CA + reissued all certs, copied to a mounted host folder |
| Kibana loaded over `http://` but not `https://` | Kibana's own server-side TLS is separate from its TLS connection to Elasticsearch | Configured `SERVER_SSL_*` settings in addition to `ELASTICSEARCH_SSL_*` |
| Wrong Filebeat version downloaded (9.x vs 8.x) | Elastic's download page defaults to latest release | Used the version-specific archive page instead |
| No internet access on lab VM | Intentionally isolated lab network | Downloaded packages on a host machine with internet, transferred via `scp` |
| Logstash kept connecting via `http://` despite `https://` in config | A stray, incorrectly indented line in `docker-compose.yml` silently broke the `environment:` block | Validated with `docker compose config`, fixed the YAML, explicitly set `ssl_enabled => true` |

---

## 🎓 Lessons Learned

- **A single YAML indentation error can silently break a config section without an obvious error message** — always validate with `docker compose config` after edits.
- **Container `/tmp` is ephemeral.** Anything needed long-term must be copied to a mounted volume.
- **A plugin silently accepting a setting doesn't guarantee it's using it correctly** — when behavior doesn't match configuration, enable debug logging and read what the process actually resolved at startup.
- **Match component major versions** — a newer Beat (9.x) is not guaranteed to work against an older Elasticsearch cluster (8.x).
- **Kibana's browser-facing TLS and its outbound TLS to Elasticsearch are two separate settings** — enabling one does not enable the other.

---

## 🗺 Roadmap

- [x] Base Elastic Stack deployment via Docker Compose
- [x] Enable authentication and verify enforcement
- [x] Generate CA and certificates
- [x] Enable HTTPS on Elasticsearch
- [x] Enable HTTPS on Kibana (both client and server-side)
- [x] Install and configure Filebeat on the host
- [x] Build a Logstash pipeline to receive and forward Beats data
- [x] Confirm real log data flowing end-to-end into Kibana
- [ ] Create named, least-privilege users and roles (scoped to `filebeat-lab-*`)
- [ ] Set up Index Lifecycle Management (ILM) for automatic rollover/cleanup
- [ ] Build dashboards for log volume, top event types, and auth activity
- [ ] Learn to identify suspicious authentication activity (brute-force patterns, privilege escalation)
- [ ] Set up snapshot-based backups

---

## 📸 Screenshots

> Add screenshots to a `/screenshots` folder in this repo and reference them below.

| Description | Screenshot |
|---|---|
| Docker containers running | `![docker ps](screenshots/docker-ps.png)` |
| Security enforcement (401 response) | `![401 response](screenshots/security-401.png)` |
| Generated certificates | `![certs folder](screenshots/certs-folder.png)` |
| Kibana over HTTPS | `![kibana https](screenshots/kibana-https.png)` |
| Successful login | `![kibana login](screenshots/kibana-login.png)` |
| Data view creation | `![data view](screenshots/data-view.png)` |
| Discover with real log data | `![discover hits](screenshots/discover-hits.png)` |

---

## 🔐 Security Disclaimer

This is a personal lab environment. Passwords, certificates, and configurations shown here are for demonstration only and should never be reused in a production environment. Always use strong, unique credentials and properly issued (non-self-signed) certificates outside of a lab context.
