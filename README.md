# GhostEye

> External reconnaissance for a domain's mail, identity, hosting, web stack, and exposure —
> from a single domain name, entirely out of public sources.

```
      ⠀⠀⠀⠀⣀⣤⣶⠾⠿⠿⠿⠿⢶⣦⣤⣀⡀
      ⠀⠀⣤⠾⠛⠉⠀⠀⠀⠀⠀⠀⠀⠀⠉⠙⠛⠻⠷⣶⣤⣤⣤⣀⣀⣀⣀⣀
      ⠀⠀⠀⠀⣠⡾⢛⣽⣿⣿⣏⠙⠛⠻⠷⣦⣤⣀⡀
      ⠀⠀⢠⣾⣋⡀⢸⣿⣿⣿⣿⠀⠀⢀⣀⣤⣽⡿⠿⠛⠿⠿⠷⠾⠿⠿⠛⠋
                        GHOSTEYE
```

GhostEye answers the first questions of an external engagement: who runs their mail and SSO,
where they are hosted, what software they expose, and where the soft edges are — without
sending a single packet to the target unless you ask it to. Where most tooling assumes
Microsoft 365, GhostEye tells you *which* mail and identity providers a domain actually uses,
and backs every call with the evidence it was drawn from.

It is passive by default. The active web, subdomain, and OSINT modules are opt-in flags, so
the same tool fits both a quiet mapping pass and a full external profile.

**Author:** black3dm0nd · [black3dm0nd.com](https://black3dm0nd.com) ·
[github.com/black3dm0nd](https://github.com/black3dm0nd)

---

## Capabilities

Given a domain, GhostEye reports, in logical order:

| Section | What you get |
|---------|--------------|
| **Domain Registration** | Registrar + IANA ID, created/expiry, DNSSEC, abuse contact, and whether WHOIS contact data is **exposed** vs privacy-protected (RDAP, with a port-43 WHOIS fallback for ccTLDs). |
| **Hosting** | Web root and primary MX resolved to `IP · Org · ASN · Country`, with cloud attribution (AWS/Azure/Google/Cloudflare/…). |
| **Services** | Open ports, service software/versions, and known CVEs for the web IP — **passively**, from Shodan InternetDB (no packets sent to the target). |
| **Identity** | Microsoft Entra / M365 tenant: cloud (Commercial/US-Gov/China), tenant GUID, `onmicrosoft` name, Managed vs **Federated** (+ the IdP URL), and **every domain in the tenant**. Shown only when a real tenant exists. |
| **Mail** | Mailbox host (M365, Google, Proofpoint-fronted, self-hosted, …) with confidence, inbound gateway, authorized senders, and an **email-spoofability** verdict (SPF + DMARC + DKIM). |
| **Technology Stack** | SaaS / vendor footprint from DNS verification tokens + NS + hosting (DNS provider, CDN/WAF, security vendors, ~60 SaaS apps). |
| **Website** *(`-w`)* | Technologies + **versions**, server/HTTP headers, **TLS certificate** (issuer/expiry/SANs), robots/sitemap, exposed **/.git**, **cloud-storage buckets**, exposed **JS source maps**, first-seen (Wayback), favicon. |
| **Social media** *(`-w`)* | LinkedIn / X / Facebook / etc. links found on the site. |
| **Subdomains** *(`-s`, `-C`)* | Live subdomains (probed + Certificate Transparency), each with IP and fingerprinted technologies, VPN/portal flags, and the likely **origin IP behind a CDN/WAF**. |
| **People & Email OSINT** *(`-O`)* | Emails/names scraped from the site, inferred **email format**, company LinkedIn, and ready-to-run Google dorks (documents, exposed files, logins). |

---

## Install

Requires **Python 3.10+** and a single dependency (`httpx`).

```bash
git clone https://github.com/black3dm0nd/ghosteye
cd ghosteye
python3 -m pip install -r requirements.txt
```

Optional: `pip install "httpx[socks]"` to route through a SOCKS `--proxy`.

---

## Usage

```bash
# Passive profile of a domain (default — nothing is sent to the target)
./ghosteye.py example.com

# Several domains, or a scope file
./ghosteye.py example.com acme.com
./ghosteye.py -f scope.txt

# Active website fingerprint (TLS, headers, buckets, source maps, …)
./ghosteye.py example.com -w

# Subdomains + per-host tech + origin behind the CDN/WAF
./ghosteye.py example.com -s

# Full external profile: web + subdomains + Certificate Transparency + people OSINT + evidence
./ghosteye.py example.com -a

# Reporting — format chosen by extension
./ghosteye.py -f scope.txt -o report.html      # styled HTML (summary + per-domain)
./ghosteye.py -f scope.txt -o out.csv           # spreadsheet
./ghosteye.py example.com -a -o out.json         # structured JSON / out.txt plain text

# Through a redirector / proxy
./ghosteye.py example.com -a --proxy socks5://127.0.0.1:9050
```

### Options

| Flag | Purpose |
|------|---------|
| `domain …` / `-f FILE` | target domain(s) / file of domains (one per line) |
| `-c N` | domains assessed in parallel (default 15) |
| `--resolver` | DoH resolvers (default `cloudflare,google`; `quad9` available) |
| `--proxy URL` | route all traffic through an HTTP/SOCKS proxy |
| `-o FILE` | write report — `.html` / `.csv` / `.json` / `.txt` |
| `--timeout S` | per-request timeout (default 8) |
| `-w, --web` | active website fingerprint |
| `-s, --subs` | subdomain discovery + tech profiling + origin unmasking |
| `-C, --ct` | add subdomains from Certificate Transparency (crt.sh) |
| `-O, --osint` | people & email OSINT |
| `-a, --all` | enable every active module + show scoring evidence |

Output is always shown in full — there is no verbose flag.
See **[INSTRUCTIONS.md](INSTRUCTIONS.md)** for a field-by-field walkthrough.

---

## Data sources

GhostEye draws on public services only. Nothing reaches the **target's own infrastructure**
unless an active flag is set — the final row below is the only target-touching traffic.

| Source | Used for | Flag | Touches target |
|--------|----------|------|----------------|
| Cloudflare / Google / Quad9 **DoH** | all DNS lookups (MX, SPF, DKIM, A, …) | default | No |
| `login.microsoftonline.com` / `.us` / `.partner.microsoftonline.cn` | Entra tenant + realm | default | No (Microsoft) |
| `autodiscover-s.outlook.com` / `.office365.us` / `.partner.outlook.cn` | tenant-domain enumeration | default | No (Microsoft) |
| `rdap.org` → registry/registrar RDAP | domain registration | default | No |
| `<tld>.whois-servers.net:43` | WHOIS fallback for ccTLDs | default | No |
| Team Cymru (`*.cymru.com` over DoH) | IP → ASN / org attribution | default | No |
| **Shodan InternetDB** (`internetdb.shodan.io`) | open ports / services / CVEs (pre-indexed) | default | No |
| `crt.sh` | Certificate Transparency subdomains | `-C` | No |
| `web.archive.org` (CDX) | site first-seen date | `-w` | No |
| `html.duckduckgo.com` | company LinkedIn lookup | `-O` | No |
| AWS S3 / Google Cloud Storage | cloud-bucket existence | `-w` | No (cloud provider) |
| **Target website + subdomains + static assets** | tech, TLS, headers, /.git, source maps | `-w` / `-s` | **Yes** |

No API keys are required for any source.

---

## Design notes

- **Passive by default.** Core profiling never contacts the target; active surface is gated
  behind `-w`, `-s`, and `-O` so a scan's blast radius is always explicit.
- **TLS verification stays on** for every HTTPS request (httpx default and
  `ssl.create_default_context`).
- **No code execution paths** — no `eval`/`exec`, no shell-outs. Network I/O is `httpx` plus a
  plain WHOIS TCP socket; fetched content is always handled as data.
- **No credentials** are sent or stored; GhostEye only reads public metadata.
- **Redirects are followed** during active checks by design — worth noting if a target can
  redirect into internal hosts.
- Async throughout: a default pass completes in a few seconds; heavier modules are bounded and
  concurrency-capped.

---

## Project layout

```
ghosteye/
├── ghosteye.py        # the recon tool
├── INSTRUCTIONS.md    # detailed, field-by-field guide
├── README.md
├── requirements.txt   # httpx
├── LICENSE            # MIT
└── .gitignore
```

## Legal

GhostEye is built for security professionals working within a defined engagement —
penetration tests, red-team operations, and assessment of assets you own or are contracted
to evaluate. The passive modules rely solely on third-party public data; the active modules
(`-w`, `-s`, `-O`) interact with the target and with external services.

Responsibility for operating within an authorized scope and in accordance with applicable
law rests entirely with the operator. The author accepts no liability for misuse or for any
damage arising from use of this tool.

---

## License

MIT © black3dm0nd
