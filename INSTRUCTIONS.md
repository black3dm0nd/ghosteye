# GhostEye — Instructions

Plain-language guide to what the tool does, the exact steps it runs, how to use it,
and how to read what it gives back.

---

## 1. What this tool does (in one paragraph)

`GhostEye` takes a domain name (e.g. `acme.com`) and tells you **which company hosts that
domain's email and which identity platform it uses for login** — Microsoft 365, Google
Workspace, Amazon SES/WorkMail, Proofpoint, Mimecast, Proton, Zoho, and ~18 others. It
figures this out purely from public information: it reads the domain's DNS records from
several public resolvers, matches those records against a database of provider
fingerprints, and then confirms the answer against the provider's own public lookup pages.
It separates the **receiving** side (the mailbox host, and any inbound security gateway in
front of it) from the **sending** side (every service authorized to send as the domain),
so you see how mail actually flows — not just one label. It also reports **where the
domain is registered** (registrar, dates, DNSSEC) and whether the registrant's contact
details are **leaked** or privacy-protected, grades the domain's **email spoofability**,
attributes the **hosting** (IP/ASN/cloud) of the site and mail, fingerprints the org's
**technology / SaaS stack** from public DNS, and expands the attack surface with
**Certificate Transparency** subdomains. It fills the gap in o365spray, which
assumes a target is Microsoft 365 and can't tell you *which* mail service a domain actually
runs.

It does **provider identification only**. It never guesses usernames, never tries
passwords, and never logs in. Every request hits either public DNS or a public,
unauthenticated metadata page using the domain name alone.

---

## 2. What this tool is useful for

`GhostEye` is useful whenever you need to know **what a domain's email and login
infrastructure actually is**, before doing anything else. It is the reconnaissance /
identification stage — the "know your target's mail and identity provider" step that
everything else builds on. Think of it as the fingerprinting front-end you run *before*
reaching for a phishing or spraying tool.

### On an authorized red-team / external assessment
- **Pick the right attack path.** Knowing it's Microsoft 365 vs. Google Workspace vs. a
  secure email gateway (Proofpoint / Mimecast / Barracuda) changes your phishing lures,
  your auth endpoints, and whether password-spray tooling like o365spray even applies.
  This is the step o365spray skips — it *assumes* Microsoft 365.
- **Spot federation pivots.** For Microsoft tenants it reports Managed vs. Federated and
  hands you the **IdP URL** (ADFS / Okta / Ping). A federated login is often a softer,
  separately-monitored entry point than Microsoft's own login.
- **Anchor further OSINT.** The extracted **Entra tenant GUID** feeds Azure/Entra
  enumeration, guest-access checks, and tenant-relationship mapping.
- **Phishing realism.** Knowing the exact mail provider lets you mimic the right login
  page and anticipate the right email-security gateway.

### At scale / scoping
- Feed it a whole in-scope domain list and get a **provider inventory in seconds** — which
  domains are M365, which are Google, which run a gateway, which are self-hosted.
- Catch **shadow IT / acquisitions**: a subsidiary domain on a different mail provider or a
  stray Entra tenant stands out immediately.

### Defensive / blue-team & audit uses
- **Attack-surface inventory** of your own estate: confirm every domain routes mail through
  the gateway you expect, and flag the ones that don't.
- **M&A / third-party due diligence:** fingerprint a target or vendor's mail + identity
  stack from the outside, non-intrusively.
- **Posture checks:** review SPF/DMARC/DKIM and detect unexpected senders in SPF includes.

### What it is *not* for
It does not find users, does not test credentials, and does not log in. It identifies the
mail and identity **provider** only — the fingerprinting that precedes any spraying or
phishing tool.

---

## 3. Exactly what it does, step by step

For **each domain** you give it, the tool runs this pipeline:

### Step 1 — Collect DNS intelligence (passive)
It asks public **DNS-over-HTTPS** resolvers (Cloudflare and Google by default; Quad9
optional) for the domain's records, and **merges** the answers so no single resolver's
view is trusted on its own. It looks up:

| Record | Why |
|--------|-----|
| `MX` | The mail exchangers — the single strongest signal for mail hosting |
| `TXT` (root) | Contains the `SPF` record (`v=spf1 …`) listing who may send mail |
| `TXT` `_dmarc` | The DMARC policy |
| `NS`, `SOA` | Who runs the domain's DNS |
| `autodiscover.<domain>` | Microsoft/Exchange client auto-config pointer |
| `enterpriseregistration.<domain>` / `enterpriseenrollment.<domain>` | Microsoft Intune/Entra device join pointers |
| `lyncdiscover.<domain>` / `sip.<domain>` | Microsoft Teams/Skype pointers |
| DKIM selectors (`selector1`, `selector2`, `google`, `amazonses`, `fm1-3`, `protonmail`, `zmail`, `k1`, `default`, …) | The mail-signing keys point at the provider's infrastructure |

All of these run **concurrently**, so the collection for a domain takes about a second.
It also **expands the SPF chain**: any `include:` / `redirect=` in the SPF record is
followed (up to two levels) so a domain that merely delegates its SPF (e.g.
`iana.org → redirect=icann.org`) is still classified by the provider referenced deeper in
the chain. This is the main reason fewer domains come back "Unknown".

### Step 2 — Score against the signature database
Each provider in the database has a set of weighted fingerprints — e.g. "an MX ending in
`mail.protection.outlook.com` is worth 45 points toward Microsoft 365", "an SPF containing
`include:_spf.google.com` is worth 35 toward Google Workspace". The tool checks every
collected record against every signature and adds up the points per provider. The same
record is never counted twice. Each provider also carries a **role** — `mailbox` (hosts
the inbox), `gateway` (an inbound filter in front of the mailbox), or `sender`
(outbound-only / transactional ESP). **Confidence** is the chosen mailbox host's share of
the points among *mailbox* candidates, so a security gateway sitting in front of the inbox
does not deflate it.

A lone domain-verification TXT record (like `MS=ms12345`) is treated as weak corroboration
only — it can **never** by itself decide the mail provider, because many domains carry one
without using that provider for mail.

### Step 3 — Active confirmation (public endpoints, opt-out with `--passive`)
To harden the result, it queries Microsoft's **public, unauthenticated** lookup pages using
the domain name only — no user, no password:

- **Tenant discovery across sovereign clouds.** It checks
  `.../<domain>/v2.0/.well-known/openid-configuration` on each Microsoft login cloud —
  Commercial (`login.microsoftonline.com`), **US Gov / GCC High / DoD**
  (`login.microsoftonline.us`), and China / 21Vianet
  (`login.partner.microsoftonline.cn`) — so a tenant in the Gov or China cloud is
  located, not missed. It reports **which cloud** and extracts the **tenant GUID**.
- **Auth posture.** `getuserrealm.srf?login=<domain>&xml=1` (on the matching cloud) reports
  **Managed** (login at Microsoft) or **Federated**, the federation brand, and the **IdP
  URL** (ADFS / Okta / Ping / etc.) — a direct pivot on an engagement.
- **Tenant domain enumeration.** The public `GetFederationInformation` SOAP endpoint
  returns **every domain registered in the tenant** plus the `<tenant>.onmicrosoft.com`
  name — instantly mapping an organisation's full M365 footprint (subsidiaries, brands,
  acquired domains) from a single input domain. Still unauthenticated, domain-only.

Important distinction the tool enforces: an Entra tenant existing means the org uses
**Microsoft for identity** — that is *not* the same as using Exchange Online for **mail**.
So the Microsoft tenant facts are reported on a separate **`identity`** line, and they only
raise the *mail* score when the MX actually points at Exchange Online. (That's why
`iana.org` reports "mail: Unknown/self-hosted" but still shows its Entra tenant.)

### Step 4 — Split the mail flow (receiving vs. sending)
From the scored evidence the tool separates the three roles so you see how mail actually
moves, not just one label:

- **Mailbox host (receiving).** Where the inbox lives. If the MX points at a **gateway**
  (Proofpoint, Mimecast, …), the tool still infers the real mailbox behind it from the
  other signals (autodiscover, DKIM selectors, the confirmed Entra tenant) and shows the
  path as `via gateway X -> mailbox Y`. If nothing reveals the mailbox behind a gateway it
  says `Unknown (behind X)`.
- **Sending services.** Everything authorized to send as the domain — read from the SPF
  `include:`/`redirect=` chain and DKIM signers, mapped to friendly names (Microsoft 365,
  Amazon SES, SendGrid, Mailchimp, Salesforce, …). Unmapped SPF sources are kept and shown
  with `-v`.

### Step 5 — Domain registration & contact-leak check (RDAP)
It queries public **RDAP** (the modern JSON successor to WHOIS, via the `rdap.org`
bootstrap) to report **where the domain is registered** and whether registrant data is
exposed:

- **Registrar** (name + IANA ID), **creation / expiry** dates, **DNSSEC** on/off, the
  **abuse** contact, and nameservers.
- **Contact-leak status** — it inspects the registrant / admin / tech / billing contacts
  and reports one of:
  - `LEAKED` → real PII is published (name, org, email, postal address, or phone), listed
    out. These are high-value OSINT: a registrant email is a phishing target and often a
    valid account/username; an org or address confirms attribution.
  - `privacy-protected / redacted` → the fields are behind a privacy service or GDPR
    redaction.
  - `contact details not published` → no contact object was returned at all.

RDAP is an active lookup (to `rdap.org`, not the target) and runs by default; for ccTLDs
without RDAP it falls back to a port-43 WHOIS query.

### Step 6 — Spoofability, hosting & subdomain discovery
Three more lenses on the target:

- **Spoofability** (always, even in `--passive`; computed from DNS). Grades the domain's
  resistance to email spoofing from its SPF qualifier (`-all` hardfail … `+all`/`?all`/
  absent = weak), DMARC policy (`p=reject/quarantine/none`, `pct`), and whether DKIM
  exists. Verdict is **SPOOFABLE** (weak/absent SPF or `p=none`), **partial** (e.g.
  `p=quarantine`), or **hardened** (`-all` + `p=reject`). A SPOOFABLE domain is a direct
  lead for a spoofed-sender phishing pretext.
- **Hosting / ASN attribution.** Resolves the web root and the primary MX to IPs and maps
  each to its **ASN, network name, country and cloud** (AWS / Microsoft/Azure / Google /
  Cloudflare / …) using Team Cymru's IP-to-ASN service over the same DoH resolvers — so you
  see where the site and the mail actually sit.
- **Technology fingerprint (passive).** Mines the collected TXT verification tokens, NS
  delegation and hosting cloud into the org's **SaaS / vendor stack** — e.g. Atlassian,
  DocuSign, Zoom, Okta, a HackerOne/Bugcrowd bug-bounty program, the DNS provider and any
  CDN/WAF. Entirely from public DNS; nothing touches the target.
- **Certificate Transparency (crt.sh) — opt-in with `--ct`.** Pulls subdomains and related
  names from issued TLS certificates. It is **off by default** because crt.sh is frequently
  overloaded and slow; enable it with `--ct` when you want the attack-surface expansion (the
  tool fast-fails and omits the line if crt.sh is unavailable).

### Step 7 — Report
It prints, per domain, the **mailbox host + confidence**, the **receiving** path (direct or
via a gateway), **hosting**, the **sending** services, the **spoofing** verdict, the
**identity** line (Entra tenant/cloud/auth/IdP + tenant domains), the **technology** stack,
the **registrar** line and **whois** leak status, **subdomains** from CT, and the evidence
lines. Results
**stream** — each domain appears the instant it finishes. After a multi-domain run it
prints a **summary** table: counts per mailbox host, inbound gateway and hosting cloud,
plus totals for spoofable domains, leaked WHOIS, and Entra tenants.

---

## 4. How to run it

### One-time setup
```bash
cd ~/externalpentesting/recon/ghosteye
python3 -m pip install -r requirements.txt     # installs httpx
chmod +x ghosteye.py                            # already done
```

### Basic use
```bash
# One domain
./ghosteye.py acme.com

# Several domains
./ghosteye.py acme.com example.org contoso.com

# A scope file (one domain per line; blank lines and # comments ignored)
./ghosteye.py -f scope.txt
```

### Common options
```bash
./ghosteye.py acme.com -v                 # -v = show full evidence + all candidates
./ghosteye.py -f scope.txt -c 20          # -c = run 20 domains in parallel (default 15)
./ghosteye.py acme.com --passive          # DNS only — do NOT touch provider endpoints
./ghosteye.py -f scope.txt -o report.html       # styled HTML report (or .csv/.json/.txt)
./ghosteye.py acme.com --timeout 5        # tighten per-request timeout (seconds)
./ghosteye.py acme.com --resolver cloudflare,google,quad9   # add Quad9 if its port is open
```

### All flags
| Flag | Meaning |
|------|---------|
| `domain …` | One or more domains (positional) |
| `-f, --file FILE` | Read domains from a file |
| `-c, --concurrency N` | Domains in parallel (default 15) |
| `--resolver LIST` | DoH resolvers: `cloudflare,google` (default); `quad9` also available |
| `--proxy URL` | Route all traffic through this HTTP/SOCKS proxy |
| `-o, --output FILE` | Write a report; format by extension — `.html` / `.csv` / `.json` / `.txt` |
| `--timeout S` | Per-request timeout in seconds (default 8) |

Everything is always shown fully (no verbose flag); `-a/--all` additionally runs every
active module and prints the scoring **evidence**.

**Active checks** (connect to the target and/or third parties):

| Flag | Description |
|------|-------------|
| `-w, --web` | Fetch the website and fingerprint it: tech + **versions**, headers, **TLS cert**, **robots/sitemap**, **/.git exposure**, **cloud-storage buckets**, exposed **JS source maps**, **first-seen (Wayback)**, favicon, social links |
| `-s, --subs` | Subdomain intelligence: resolve + **profile each subdomain's technologies**, flag VPN portals, and infer the **real origin IP behind a CDN/WAF** |
| `-C, --ct` | Add subdomains from Certificate Transparency logs (crt.sh) |
| `-O, --osint` | People & email OSINT: scrape employee emails/names, infer the **email format**, find the company on LinkedIn, and build Google dorks for documents & sensitive files |
| `-a, --all` | Enable all of the above (`-w -s -C -O`) + show evidence |

---

## 5. How to read the output

Output is grouped into labelled sections:

```
acme.com
  ──────────────────────────────────────────────────────────

  MAIL
  Mailbox host    Microsoft 365 / Exchange Online   (100% confidence)
  Inbound path    via Proofpoint (security gateway)
  MX records      mxa-00123.pphosted.com, mxb-00123.pphosted.com
  Auth. senders   Microsoft 365, Proofpoint, Amazon SES, SendGrid  (+1 unmapped, -v)
  Spoofing risk   partial  [SPF softfail (~all) · DMARC p=quarantine · DKIM yes]

  IDENTITY
  Platform        Entra ID · Commercial (Worldwide)
  Tenant ID       72f9…db47
  Default domain  acme.onmicrosoft.com
  Tenant brand    Acme
  Authentication  Federated → https://acme.okta.com/app/office365/.../sso/wsfed/passive?...
  Tenant domains  acme.com, acme.co.uk, acme-labs.com, ...  …(-v for all)

  HOSTING
  Web             203.0.113.10    Amazon.com, INC. (AWS) · AS16509 · US
  Mail            67.231.153.1    Proofpoint, INC. · AS26211 · US

  TECHNOLOGY
  DNS             Cloudflare DNS
  CDN/WAF         Cloudflare (CDN/WAF)
  Security        Okta, HackerOne (bug bounty)
  SaaS / apps     Atlassian (Jira/Confluence), DocuSign, Zoom, HubSpot

  REGISTRATION
  Registrar       GoDaddy.com, LLC  (IANA 146)
  Registered      2010-04-01 → 2027-04-01 · DNSSEC off
  Abuse contact   abuse@godaddy.com
  WHOIS privacy   LEAKED → registrant org=Acme Widgets Inc; registrant email=jadmin@acme.com

  ATTACK SURFACE
  Subdomains (CT) 42 — vpn.acme.com, owa.acme.com, dev.acme.com, ...  (+32 more, -v)

  EVIDENCE
    [+45] MX mxa-00123.pphosted.com
    [+25] CNAME autodiscover.acme.com -> autodiscover.outlook.com
    [+20] confirmed Exchange Online tenant (openid-configuration)
```

**MAIL**
- **Mailbox host / confidence** — where the inbox actually lives (`≥ 60%` with an active
  confirmation is solid).
- **Inbound path** — `direct (no gateway)`, or `via <gateway> (security gateway)` when a
  security gateway fronts the mailbox.
- **MX records** — the raw mail exchangers the call rests on.
- **Auth. senders** — the services authorized to send as the domain (SPF/DKIM),
  friendly-named; `+N unmapped` SPF sources shown with `-v`.
- **Spoofing risk** — `SPOOFABLE` / `partial` / `hardened`, with the SPF qualifier, DMARC
  policy and DKIM presence in brackets.

**IDENTITY** (only when a Microsoft/Entra tenant exists)
- **Platform / cloud** — Entra ID and which Microsoft cloud (Commercial / US Gov / China).
- **Tenant ID** — the Entra tenant GUID. **Default domain** — the `onmicrosoft.com` name.
- **Authentication** — `Managed` (login at Microsoft) or `Federated → <IdP URL>`
  (ADFS/Okta/…), a high-value pivot.
- **Tenant domains** — every domain registered in the tenant (first 8; `-v` for all).

**HOSTING** — for the web root and primary MX, a single labelled row:
`IP: … | Org: … (Cloud) | ASN: … | Country: …`.

**SERVICES** — open ports, service software/versions and known CVEs for the web/mail IPs,
pulled **passively** from Shodan's InternetDB (pre-indexed data; no packet is ever sent to
the target). Runs by default.

**WEBSITE** (only with `--web`) — GhostEye fetches the domain's web root (HTTPS, falling back
to HTTP) and reports, per page:
- **URL + status** (and redirect count) and page **title**
- **Activity** — what the company does, from the site's own `meta description` / OpenGraph
  description
- **Server** / `X-Powered-By`, any **CDN/WAF** (Cloudflare, CloudFront, Akamai, Fastly,
  Sucuri, Varnish), and detected **technologies** (CMS like WordPress/Drupal/Shopify, JS
  frameworks, backend language, analytics)
- **Careers / jobs** — a link to the company's careers/jobs page, and the **ATS** platform
  if the link points at one (Greenhouse, Lever, Workday, SmartRecruiters, Ashby, …) — i.e.
  their actual application portal
- the **favicon URL**
- the **security-header** posture, listed one per line with ✓ present / ✗ missing

This is the one feature that connects to the **target's own web server**, so it is opt-in
via `--web`. Add **`--web-url URL`** (repeatable) to also fetch and fingerprint specific
URLs — e.g. a login portal, an app subdomain, or a known careers page — each shown as its
own page block.

**TECHNOLOGY** — the single, comprehensive collection of everything the company runs:
domain-verification TXT tokens (Google, Atlassian, DocuSign, Zoom, Okta, HackerOne,
Datadog, Snowflake, Mixpanel, …), the NS delegation (DNS provider), the hosting cloud, and
— when `--web` is used — the full website stack. Grouped into DNS / CDN-WAF / Web stack /
Security / SaaS. (DNS-derived parts touch nothing; the Web stack part comes from `--web`.)

**REGISTRATION** — registrar + IANA ID, creation/expiry, DNSSEC, abuse contact, and the
**WHOIS privacy** status: `LEAKED` (exposed fields listed), `privacy-protected / redacted`,
or `contact details not published`.

**ATTACK SURFACE** — subdomains discovered via Certificate Transparency (first 10; `-v`
for all).

**EVIDENCE** — each matched signal and the points it added; `SPF via <host>` means the
match came from an expanded `include:`/`redirect=` target.

**Special results:**
- `Mailbox host : Unknown (behind <gateway>)` — the MX points at a gateway and nothing
  revealed the real mailbox behind it; the gateway and senders are still reported.
- `Mailbox host : <base> (unrecognised provider)` / `Self-hosted (<base>)` **(derived from
  MX)** — no signature matched, so the service name is taken from the MX's registrable
  domain (e.g. `smx.abv.bg` → `abv.bg`). If that base equals the target domain it's shown as
  `Self-hosted`; otherwise it names the third-party host running the mail.
- `Mailbox host : Unknown / self-hosted` — only when there are no usable MX records at all.
  An **IDENTITY** section may still appear if the org uses Entra for login.
- Mail and identity can legitimately **differ** (e.g. mail on Google, SSO on Entra) — the
  tool reports both rather than forcing one answer.

---

## 6. Rules of engagement

- Only run this against domains you are **explicitly authorized** to assess.
- GhostEye's domain recon is passive/OSINT-grade by default: public DNS + public metadata,
  domain name only — it does **not** enumerate users and never touches the target's systems.
- The active checks (`-w/--web`, `-s/--subs`) reach out to the target and/or third parties —
  keep them inside your scope.

---

## 7. Extending it

To add a new provider, edit the `PROVIDERS` dictionary in `ghosteye.py`. Each signature is
`(field, mode, needle, weight)` where `field` is `mx|spf|cname|dkim|txt`,
`mode` is `suffix|contains|equals`, `needle` is the lowercased string to match, and
`weight` is the points it contributes. No other code changes are needed.
