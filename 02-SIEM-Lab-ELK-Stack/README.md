# SIEM Lab: Elastic Stack (ELK) with TLS and Log Ingestion

Part of the [AD-Attack-Defense-Lab](../) repo.

This is where I built the SIEM itself: a self-hosted Elastic Stack (Elasticsearch, Logstash, Kibana) in Docker Compose, encrypted end to end with TLS, taking in real logs from a Linux host through Filebeat. I built it from scratch and debugged it as I went, and the problems I hit are written up in [Troubleshooting](#troubleshooting) below, because fixing them taught me more than the happy path did.

A SIEM is what security teams use to pull logs from across an organization's servers and devices, then search, monitor and alert on them to catch suspicious activity. I wanted hands-on practice with the same architecture a real deployment uses: stand it up, harden it, then actually analyze log data.

## Architecture

```
┌─────────────────┐     ┌──────────────┐     ┌───────────────┐     ┌─────────┐
│  Filebeat        │────▶│  Logstash    │────▶│ Elasticsearch │◀────│ Kibana  │
│  (host service)  │     │  (Docker)    │     │  (Docker)     │     │ (Docker)│
│  reads:          │     │  port 5044   │     │  port 9200    │     │port 5601│
│  /var/log/syslog │     │  Beats input │     │  HTTPS only   │     │  HTTPS  │
│  /var/log/auth.log│    │  → HTTPS out │     │  auth enabled │     │         │
└─────────────────┘     └──────────────┘     └───────────────┘     └─────────┘
```

Every leg of traffic, Logstash to Elasticsearch, Kibana to Elasticsearch, and browser to Kibana, is encrypted with a self-signed CA I generated for this lab. All components are Elasticsearch, Kibana, Logstash and Filebeat 8.12.0.

I ran it on Ubuntu 22.04 (VMware Workstation) with Docker and Docker Compose, 4 GB RAM allocated.

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

I never commit the `certs/` folder or real passwords. The credentials shown below are lab-only placeholders.

## Part 1: Base deployment

The stack is one `docker-compose.yml` with three services, `elasticsearch`, `logstash` and `kibana`, on a shared Docker bridge network (`elk-net`). Elasticsearch runs single-node (`discovery.type=single-node`), which is fine for a lab but not production. I had `xpack.security.enabled=true` from the start, since authentication is on by default in modern Elastic, and a named volume (`es_data`) keeps Elasticsearch's data across restarts.

```bash
docker compose up -d
docker ps   # confirm all three containers are Up
```

All three containers running:

<img width="1269" height="525" alt="Logstash-Elasticsearch-Kibana" src="https://github.com/user-attachments/assets/d65eac04-f3e2-416d-a6eb-02edb2c22400" />

The initial Kibana login over plain HTTP, before I added TLS:

<img width="1279" height="737" alt="HTTP login page" src="https://github.com/user-attachments/assets/cd9bb3d5-6625-4f5d-ac21-4a1c87967156" />

## Part 2: TLS hardening

Out of the box the stack had authentication but no encryption; the traffic itself was still plaintext. I hardened it in stages.

**Confirm security is actually enforced.**

```bash
curl http://localhost:9200/_cluster/health
# → 401 security_exception: missing authentication credentials
```

The 401 confirming security is on:

<img width="1273" height="779" alt="Docker Compose Health check" src="https://github.com/user-attachments/assets/e5855ae3-0621-471b-ab72-e42327bd16c9" />

**Generate a CA and certificates** with Elasticsearch's built-in `certutil`, run from inside the container:

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

I then copied the certs out of the container onto the host with `docker cp` into `elasticsearch/certs/`, so they persist and can be mounted into every service. Container `/tmp` does not survive a recreate, which I learned the hard way (see Troubleshooting).

The generated certificate files:

<img width="1265" height="772" alt="Creating CA HTTPS Certificates" src="https://github.com/user-attachments/assets/5402b230-53a9-42b0-a650-ce77725f5e81" />

**Enable HTTPS on Elasticsearch** by adding to its environment, with the certs folder mounted into `/usr/share/elasticsearch/config/certs`:

```yaml
- xpack.security.http.ssl.enabled=true
- xpack.security.http.ssl.key=certs/http.key
- xpack.security.http.ssl.certificate=certs/http.crt
- xpack.security.http.ssl.certificate_authorities=certs/ca.crt
```

**Enable HTTPS on Kibana, both legs.** This is two separate things and it's easy to miss one.

Kibana talking to Elasticsearch (Kibana as a client):

```yaml
- ELASTICSEARCH_HOSTS=https://elasticsearch:9200
- ELASTICSEARCH_SSL_CERTIFICATEAUTHORITIES=/usr/share/kibana/config/certs/ca.crt
```

The browser talking to Kibana (Kibana's own web server):

```yaml
- SERVER_SSL_ENABLED=true
- SERVER_SSL_CERTIFICATE=/usr/share/kibana/config/certs/kibana.crt
- SERVER_SSL_KEY=/usr/share/kibana/config/certs/kibana.key
```

Kibana over HTTPS with the self-signed cert warning:

<img width="1260" height="722" alt="Kibana HTTPS warning" src="https://github.com/user-attachments/assets/527e6442-04ec-472d-826d-8410df411be0" />

And logged in over HTTPS:

<img width="1267" height="737" alt="Kibana Homepage" src="https://github.com/user-attachments/assets/efa20311-576c-4666-bd4e-cb8695bb88de" />

## Part 3: Log ingestion

With the stack secured, I ingested the server's own system logs through Filebeat.

**Filebeat on the host** (not in Docker), `/etc/filebeat/filebeat.yml`:

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

**The Logstash pipeline**, `logstash/pipeline/logstash.conf`, mounted into the container:

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

**The Kibana data view.** In Stack Management → Data Views I created one for `filebeat-lab-*` with `@timestamp` as the time field, which exposed 61 auto-detected fields from the ingested documents.

<img width="635" height="381" alt="Filebeat Dataview" src="https://github.com/user-attachments/assets/4ee04da0-092a-4d37-b7a3-a182fb945f79" />

## Verifying end to end

```bash
curl -k -u elastic:<mypassword> https://myhostip:9200/_cat/indices?v
```

This confirmed the `filebeat-lab-*` index exists with a non-zero document count. In Discover, 500 hits of real log data:

<img width="1259" height="484" alt="file beat confirmed" src="https://github.com/user-attachments/assets/c51988c8-2a49-4230-967f-2ca03b3dd92f" />

## Troubleshooting

| Issue | Cause | Fix |
|---|---|---|
| `password empty` error during cert generation | I passed `--pass ""` explicitly | Omit the flag entirely rather than passing an empty string |
| Lost the CA private key after a restart | `/tmp` inside a container doesn't survive a recreate | Regenerated the CA, reissued all certs, copied them to a mounted host folder |
| Kibana loaded over `http://` but not `https://` | Kibana's own server-side TLS is separate from its TLS connection to Elasticsearch | Set `SERVER_SSL_*` in addition to `ELASTICSEARCH_SSL_*` |
| Wrong Filebeat version downloaded (9.x vs 8.x) | Elastic's download page defaults to the latest release | Used the version-specific archive page |
| No internet on the lab VM | The lab network is intentionally isolated | Downloaded packages on a machine with internet and transferred them with `scp` |
| Logstash kept connecting over `http://` despite `https://` in the config | A stray, badly indented line in `docker-compose.yml` silently broke the `environment:` block | Validated with `docker compose config`, fixed the YAML, set `ssl_enabled => true` explicitly |

The things I'd want to remember from this: a single YAML indentation error can break a config section with no obvious error, so validate with `docker compose config` after edits. Container `/tmp` is ephemeral; anything you need long-term goes in a mounted volume. A plugin accepting a setting without complaint doesn't mean it's using it, so when behavior doesn't match config, turn on debug logging and read what the process actually resolved at startup. Match component major versions; a 9.x Beat isn't guaranteed to work against an 8.x cluster. And Kibana's browser-facing TLS and its outbound TLS to Elasticsearch are two different settings.

## Status and next steps

Done: base deployment, authentication enforced, CA and certificates, HTTPS on Elasticsearch and both legs of Kibana, Filebeat on the host, the Logstash pipeline, and real log data flowing end to end into Kibana.

The rest of the hardening and analysis work continues in [Part 4](./Part-4-Continuation/): named least-privilege users and roles scoped to `filebeat-lab-*`, Index Lifecycle Management for rollover and cleanup, dashboards for log volume and auth activity, and snapshot-based backups.

---

This is a personal lab. The passwords, certificates and configs shown are for demonstration only and should never be reused in production. Outside a lab, use strong unique credentials and properly issued (non-self-signed) certificates.

[← Back to AD-Attack-Defense-Lab](../)
