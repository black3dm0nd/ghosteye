# GhostEye

> External reconnaissance for a domain's mail, identity, hosting, web stack, and exposure from public sources.

```
      ⠀⠀⠀⠀⣀⣤⣶⠾⠿⠿⠿⠿⢶⣦⣤⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
      ⠀⠀⣤⠾⠛⠉⠀⠀⠀⠀⠀⠀⠀⠀⠉⠙⠛⠻⠷⣶⣤⣤⣤⣀⣀⣀⣀⣀⠀⠀
      ⠀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠉⠉⠉⠉⠉⠀⠀
      ⠀⠀⠀⠀⣠⡾⢛⣽⣿⣿⣏⠙⠛⠻⠷⣦⣤⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⡀⠀⠀
      ⠀⠀⢠⣾⣋⡀⢸⣿⣿⣿⣿⠀⠀⢀⣀⣤⣽⡿⠿⠛⠿⠿⠷⠾⠿⠿⠛⠋⠀⠀
      ⠀⠀⠻⠛⠛⠻⣶⣽⣿⣿⣿⡶⠿⠛⠋⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
      ⠀⠀⠀⠀⠀⠀⣠⣿⡏⠻⣷⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣶⠶⢶⣤⠀⠀⠀
      ⠀⠀⠀⠀⠀⠀⢹⣯⠁⠀⠈⠛⢷⣤⡀⠀⠀⠀⠀⠀⠀⠀⠸⠧⠀⠀⢹⡇⠀⠀
      ⠀⠀⠀⠀⠀⠀⠈⣿⠀⠀⠀⠀⠀⠉⠻⠷⣦⣤⣤⣀⣀⣀⣀⣠⣤⡶⠟⠀⠀⠀
      ⠀⠀⠀⠀⠀⠀⠀⠛⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠉⠉⠉⠉⠉⠁⠀⠀⠀⠀⠀

      G H O S T E Y E
```

**Author:** black3dm0nd · [black3dm0nd.com](https://black3dm0nd.com/) · [github.com/black3dm0nd](https://github.com/black3dm0nd)

---

## Overview

GhostEye answers the first questions of an external engagement:

- Who runs the target's mail and SSO?
- Where is it hosted?
- What software and services are exposed?
- Where are the soft edges?

It is passive by default. Core profiling does not send traffic to the target unless you enable an active module. Where many tools assume Microsoft 365, GhostEye identifies which mail and identity providers a domain actually uses and backs every call with evidence.

Active web, subdomain, and OSINT modules are opt-in, so the same tool fits both a quiet mapping pass and a fuller external profile.

## Contents

- [Capabilities](#capabilities)
- [Install](#install)
- [Usage](#usage)
- [Options](#options)
- [Data Sources](#data-sources)
- [Design Notes](#design-notes)
- [Project Layout](#project-layout)
- [Legal](#legal)
- [License](#license)

---

## Capabilities

Given a domain, GhostEye reports the external profile in a logical order:

| Section | What you get |
| --- | --- |
| **Domain Registration** | Registrar and IANA ID, created/expiry dates, DNSSEC status, abuse contact, and whether WHOIS contact data is exposed or privacy-protected. Uses RDAP with port-43 WHOIS fallback for ccTLDs. |
| **Hosting** | Web root and primary MX resolved to `IP · Org · ASN · Country`, with cloud attribution for providers such as AWS, Azure, Google, and Cloudflare. |
| **Services** | Open ports, service software/versions, and known CVEs for the web IP, passively from Shodan InternetDB. No packets are sent to the target. |
| **Identity** | Microsoft Entra / M365 tenant details: cloud, tenant GUID, `onmicrosoft` name, Managed vs Federated, IdP URL, and every domain in the tenant. Shown only when a real tenant exists. |
| **Mail** | Mailbox host, inbound gateway, authorized senders, confidence score, and email-spoofability verdict from SPF, DMARC, and DKIM. |
| **Technology Stack** | SaaS and vendor footprint from DNS verification tokens, name servers, and hosting metadata, including DNS provider, CDN/WAF, security vendors, and SaaS apps. |
| **Website** `-w` | Technologies and versions, server/HTTP headers, TLS certificate, robots/sitemap, exposed `/.git`, cloud-storage buckets, JS source maps, first-seen date from Wayback, and favicon. |
| **Social Media** `-w` | LinkedIn, X, Facebook, and other social links found on the site. |
| **Subdomains** `-s`, `-C` | Live subdomains from probing and Certificate Transparency, each with IP, fingerprinted technologies, VPN/portal flags, and likely origin IP behind a CDN/WAF. |
| **People & Email OSINT** `-O` | Emails and names scraped from the site, inferred email format, company LinkedIn, and ready-to-run Google dorks for documents, exposed files, and login surfaces. |

---

## Install

GhostEye requires **Python 3.10+** and one required dependency: `httpx`.

```bash
git clone https://github.com/black3dm0nd/ghosteye
cd ghosteye
python3 -m pip install -r requirements.txt
```

To route through a SOCKS proxy, install the optional SOCKS extras:

```bash
python3 -m pip install "httpx[socks]"
```

---

## Usage

### Passive Profile

```bash
# Default mode: nothing is sent to the target.
./ghosteye.py example.com
```

### Multiple Domains

```bash
./ghosteye.py example.com acme.com
./ghosteye.py -f scope.txt
```

### Active Website Fingerprinting

```bash
# TLS, headers, buckets, source maps, and related web checks.
./ghosteye.py example.com -w
```

### Subdomains

```bash
# Subdomains, per-host technology, and origin checks behind CDN/WAF.
./ghosteye.py example.com -s
```

### Full External Profile

```bash
# Web, subdomains, Certificate Transparency, people OSINT, and evidence.
./ghosteye.py example.com -a
```

### Reports

```bash
# Report format is chosen by file extension.
./ghosteye.py -f scope.txt -o report.html
./ghosteye.py -f scope.txt -o out.csv
./ghosteye.py example.com -a -o out.json
./ghosteye.py example.com -a -o out.txt
```

### Proxy

```bash
./ghosteye.py example.com -a --proxy socks5://127.0.0.1:9050
```

---

## Options

| Flag | Purpose |
| --- | --- |
| `domain ...` / `-f FILE` | Target domain(s), or a file of domains with one domain per line. |
| `-c N` | Number of domains assessed in parallel. Default: `15`. |
| `--resolver` | DoH resolvers. Default: `cloudflare,google`; `quad9` is also available. |
| `--proxy URL` | Route all traffic through an HTTP or SOCKS proxy. |
| `-o FILE` | Write a report. Supported extensions: `.html`, `.csv`, `.json`, `.txt`. |
| `--timeout S` | Per-request timeout in seconds. Default: `8`. |
| `-w`, `--web` | Enable active website fingerprinting. |
| `-s`, `--subs` | Enable subdomain discovery, technology profiling, and origin unmasking. |
| `-C`, `--ct` | Add subdomains from Certificate Transparency via `crt.sh`. |
| `-O`, `--osint` | Enable people and email OSINT. |
| `-a`, `--all` | Enable every active module and show scoring evidence. |

Output is always shown in full; there is no verbose flag.

For a field-by-field walkthrough, see [INSTRUCTIONS.md](INSTRUCTIONS.md).

---

## Data Sources

GhostEye draws on public services only. Nothing reaches the target's own infrastructure unless an active flag is set. The target-touching checks are called out below.

| Source | Used for | Flag | Touches target |
| --- | --- | --- | --- |
| Cloudflare / Google / Quad9 DoH | DNS lookups such as MX, SPF, DKIM, and A records. | Default | No |
| `login.microsoftonline.com`, `.us`, `.partner.microsoftonline.cn` | Entra tenant and realm discovery. | Default | No; Microsoft only |
| `autodiscover-s.outlook.com`, `.office365.us`, `.partner.outlook.cn` | Tenant-domain enumeration. | Default | No; Microsoft only |
| `rdap.org` and registry/registrar RDAP | Domain registration. | Default | No |
| `<tld>.whois-servers.net:43` | WHOIS fallback for ccTLDs. | Default | No |
| Team Cymru `*.cymru.com` over DoH | IP to ASN and org attribution. | Default | No |
| Shodan InternetDB `internetdb.shodan.io` | Open ports, services, and CVEs from pre-indexed data. | Default | No |
| `crt.sh` | Certificate Transparency subdomains. | `-C` | No |
| `web.archive.org` CDX | Site first-seen date. | `-w` | No |
| `html.duckduckgo.com` | Company LinkedIn lookup. | `-O` | No |
| AWS S3 / Google Cloud Storage | Cloud-bucket existence checks. | `-w` | No; cloud provider only |
| Target website, subdomains, and static assets | Technology detection, TLS, headers, `/.git`, and source maps. | `-w`, `-s` | **Yes** |

No API keys are required for any source.

---

## Design Notes

- **Passive by default:** Core profiling never contacts the target. Active surface is gated behind `-w`, `-s`, and `-O` so scan scope stays explicit.
- **TLS verification stays on:** HTTPS requests use httpx defaults and `ssl.create_default_context`.
- **No code execution paths:** No `eval`, no `exec`, and no shell-outs. Network I/O uses `httpx` plus a plain WHOIS TCP socket; fetched content is handled as data.
- **No credentials:** GhostEye only reads public metadata and does not send or store credentials.
- **Redirects are followed:** Active checks follow redirects by design, which matters if a target redirects into internal hosts.
- **Async throughout:** Default passes complete quickly; heavier modules are bounded and concurrency-capped.

---

## Project Layout

```text
ghosteye/
├── ghosteye.py        # recon tool
├── INSTRUCTIONS.md    # detailed field-by-field guide
├── README.md
├── requirements.txt   # httpx
├── LICENSE            # MIT
└── .gitignore
```

---

## Legal

GhostEye is built for security professionals working within a defined engagement: penetration tests, red-team operations, and assessment of assets you own or are contracted to evaluate.

The passive modules rely on third-party public data. The active modules, including `-w`, `-s`, and `-O`, interact with the target and with external services.

Responsibility for operating within an authorized scope and in accordance with applicable law rests entirely with the operator. The author accepts no liability for misuse or for any damage arising from use of this tool.

---

## License

MIT © black3dm0nd
