#!/usr/bin/env python3
"""
GhostEye - External reconnaissance for a domain
===============================================
Maps a domain's mail, identity, hosting, web stack, exposure and people from
public sources: DNS over multiple DoH resolvers, providers' public metadata,
RDAP/WHOIS, Certificate Transparency, and (opt-in) the target's own website.

Passive by default; active checks are opt-in. For authorized assessment use.
author: black3dm0nd · https://black3dm0nd.com
"""
from __future__ import annotations

import argparse
import asyncio
import contextlib
import csv
import html
import io
import ipaddress
import json
from html import unescape as html_unescape
import random
import re
import shutil
import socket
import ssl
import sys
import textwrap
import time
import xml.etree.ElementTree as ET
from urllib.parse import quote_plus, unquote, urljoin, urlparse
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

try:
    import httpx
except ImportError:
    sys.exit("missing dependency: pip install httpx")

# --------------------------------------------------------------------------- #
# DoH resolvers (public DNS-over-HTTPS JSON APIs)
# --------------------------------------------------------------------------- #
RESOLVERS: dict[str, str] = {
    "cloudflare": "https://cloudflare-dns.com/dns-query",
    "google": "https://dns.google/resolve",
    "quad9": "https://dns.quad9.net:5053/dns-query",
}

# DNS record type numbers -> names (for parsing DoH JSON "Answer" entries)
RRTYPE = {1: "A", 5: "CNAME", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 2: "NS", 6: "SOA"}

# DKIM selectors worth probing (selector -> hint only; match is on CNAME target).
# Lean default = the highest-yield selectors; the rest load with --deep.
DKIM_SELECTORS = [
    "selector1", "selector2",            # Microsoft 365
    "google",                            # Google Workspace
    "amazonses",                         # Amazon SES / WorkMail
    "fm1",                               # Fastmail
    "protonmail",                        # Proton
    "zmail",                             # Zoho
    "k1",                                # Mailchimp/Mandrill-ish
    "smtpapi",                           # SendGrid
]
DKIM_SELECTORS_DEEP = [
    "fm2", "fm3", "protonmail2", "protonmail3", "zoho",
    "k2", "k3", "mandrill", "mg", "pm",
    "s1", "s2", "default", "dkim", "mail", "smtp",
]

# Provider-indicative subdomains to resolve (looked up as CNAME + whatever answers)
PROBE_SUBDOMAINS = [
    "autodiscover",
    "enterpriseregistration",
    "enterpriseenrollment",
    "lyncdiscover",
    "sip",
    "_dmarc",
]

# --------------------------------------------------------------------------- #
# Signature database.
# Each signature: (field, mode, needle, weight)
#   field : "mx" | "spf" | "cname" | "dkim" | "txt"
#   mode  : "suffix" | "contains" | "equals"
#   needle: lowercased string to test
#   weight: contribution to this provider's score
# --------------------------------------------------------------------------- #
PROVIDERS: dict[str, list[tuple[str, str, str, int]]] = {
    "Microsoft 365 / Exchange Online": [
        ("mx", "suffix", "mail.protection.outlook.com", 45),
        ("spf", "contains", "include:spf.protection.outlook.com", 35),
        ("cname", "suffix", "autodiscover.outlook.com", 25),
        ("cname", "suffix", "enterpriseregistration.windows.net", 20),
        ("cname", "suffix", "enterpriseenrollment.manage.microsoft.com", 20),
        ("cname", "suffix", "online.lync.com", 15),
        ("dkim", "contains", "onmicrosoft.com", 25),
        ("txt", "contains", "ms=ms", 5),
    ],
    "Google Workspace": [
        ("mx", "suffix", "aspmx.l.google.com", 45),
        ("mx", "suffix", "googlemail.com", 35),
        ("mx", "suffix", "smtp.google.com", 35),
        ("spf", "contains", "include:_spf.google.com", 35),
        ("dkim", "contains", "google.com", 15),
        ("txt", "contains", "google-site-verification", 5),
    ],
    "Amazon WorkMail": [
        ("mx", "contains", "awsapps.com", 45),
        ("mx", "contains", "amazonaws.com", 35),
    ],
    "Amazon SES (sender)": [
        ("spf", "contains", "amazonses.com", 25),
        ("dkim", "contains", "amazonses.com", 20),
    ],
    "Proofpoint": [
        ("mx", "suffix", "pphosted.com", 45),
        ("mx", "suffix", "ppe-hosted.com", 45),
        ("spf", "contains", "pphosted.com", 25),
    ],
    "Mimecast": [
        ("mx", "contains", "mimecast", 45),      # .com / .co.za / -offshore.com / etc.
        ("spf", "contains", "mimecast", 25),
    ],
    "Barracuda": [
        ("mx", "contains", "barracudanetworks.com", 45),
        ("mx", "contains", "cudamail.com", 45),
    ],
    "Cisco Secure Email (IronPort)": [
        ("mx", "suffix", "iphmx.com", 45),
        ("spf", "contains", "iphmx.com", 25),
    ],
    "Trend Micro Email Security": [
        ("mx", "contains", "in.hes.trendmicro.com", 45),
        ("spf", "contains", "trendmicro.com", 20),
    ],
    "Sophos Email": [
        ("mx", "contains", "sophos.com", 40),
    ],
    "Zoho Mail": [
        ("mx", "contains", "zoho.com", 45),
        ("mx", "contains", "zoho.eu", 45),
        ("spf", "contains", "zoho.com", 25),
        ("spf", "contains", "zohomail", 25),
    ],
    "Proton Mail": [
        ("mx", "contains", "protonmail.ch", 45),
        ("mx", "contains", "protonmail", 40),
        ("spf", "contains", "_spf.protonmail.ch", 30),
        ("txt", "contains", "protonmail-verification", 20),
    ],
    "Fastmail": [
        ("mx", "contains", "messagingengine.com", 45),
        ("spf", "contains", "spf.messagingengine.com", 30),
    ],
    "Rackspace Email": [
        ("mx", "suffix", "emailsrvr.com", 45),
        ("spf", "contains", "emailsrvr.com", 25),
    ],
    "GoDaddy / Secureserver": [
        ("mx", "contains", "secureserver.net", 45),
        ("spf", "contains", "secureserver.net", 25),
    ],
    "Yandex 360": [
        ("mx", "contains", "mx.yandex.net", 45),
        ("spf", "contains", "_spf.yandex.net", 30),
    ],
    "Apple iCloud+": [
        ("mx", "contains", "icloud.com", 45),
        ("spf", "contains", "icloud.com", 25),
    ],
    "Namecheap Private Email": [
        ("mx", "contains", "privateemail.com", 45),
        ("spf", "contains", "privateemail.com", 25),
    ],
    "Intermedia": [
        ("mx", "contains", "intermedia.net", 45),
    ],
    # --- Microsoft sovereign clouds ----------------------------------------- #
    "Microsoft 365 (US Gov / GCC High / DoD)": [
        ("mx", "suffix", "mail.protection.office365.us", 45),
        ("spf", "contains", "spf.protection.office365.us", 35),
    ],
    "Microsoft 365 (21Vianet / China)": [
        ("mx", "suffix", "mail.protection.partner.outlook.cn", 45),
        ("spf", "contains", "spf.protection.partner.outlook.cn", 35),
    ],
    # --- Secure email gateways ---------------------------------------------- #
    "Trellix / FireEye Email Security (ETP)": [
        ("mx", "contains", "etp.fireeye.com", 45),
        ("mx", "contains", "etp.trellix.com", 45),
        ("spf", "contains", "etp.fireeye.com", 25),
        ("spf", "contains", "etp.trellix.com", 25),
    ],
    "Forcepoint Email Security": [
        ("mx", "suffix", "mailcontrol.com", 45),
        ("spf", "contains", "spf.mailcontrol.com", 25),
    ],
    "Agari": [
        ("spf", "contains", "spf.agari.com", 20),
    ],
    # --- Mailbox hosts ------------------------------------------------------- #
    "IONOS / 1&1": [
        ("mx", "contains", "kundenserver.de", 45),
        ("spf", "contains", "_spf.kundenserver.de", 25),
        ("spf", "contains", "_spf.perfora.net", 25),
    ],
    "OVHcloud Email": [
        ("mx", "contains", "mail.ovh.net", 45),
        ("mx", "contains", "mx.ovh.net", 45),
        ("spf", "contains", "mx.ovh.com", 20),
    ],
    "Titan Email": [
        ("mx", "contains", "titan.email", 45),
        ("spf", "contains", "spf.titan.email", 25),
    ],
    "Migadu": [
        ("mx", "contains", "migadu.com", 45),
    ],
    "Tuta (Tutanota)": [
        ("mx", "contains", "tutanota.de", 45),
        ("mx", "contains", "tuta.com", 45),
        ("spf", "contains", "_spf.tutanota.de", 25),
    ],
    "mailbox.org": [
        ("mx", "contains", "mailbox.org", 45),
    ],
    "Mail.ru / VK": [
        ("mx", "contains", "emx.mail.ru", 45),
        ("spf", "contains", "_spf.mail.ru", 25),
    ],
    "GMX / web.de": [
        ("mx", "contains", "gmx.net", 40),
        ("mx", "contains", "mx.web.de", 40),
    ],
    "Cloudflare Email Routing": [
        ("mx", "suffix", "mx.cloudflare.net", 45),
        ("spf", "contains", "_spf.mx.cloudflare.net", 25),
    ],
    # --- Transactional / bulk senders (low weight: outbound only, not the ---- #
    # --- mailbox host; surface only when nothing stronger matches) ---------- #
    "SendGrid (sender)": [
        ("spf", "contains", "sendgrid.net", 18),
        ("dkim", "contains", "sendgrid.net", 15),
    ],
    "Mailgun (sender)": [
        ("spf", "contains", "mailgun.org", 18),
        ("dkim", "contains", "mailgun.org", 15),
    ],
    "Mailchimp / Mandrill (sender)": [
        ("spf", "contains", "mailchimp", 15),
        ("spf", "contains", "mandrillapp.com", 15),
        ("dkim", "contains", "mandrill", 15),
    ],
    "Postmark (sender)": [
        ("spf", "contains", "spf.mtasv.net", 15),
    ],
    "SparkPost (sender)": [
        ("spf", "contains", "sparkpostmail.com", 15),
    ],
}

# Role of each provider in the mail flow:
#   "mailbox" = hosts the actual inbox (default for anything unlisted)
#   "gateway" = inbound security filter that sits IN FRONT of the mailbox (MX points here)
#   "sender"  = outbound-only / transactional-ESP (appears in SPF/DKIM, not the inbox)
PROVIDER_ROLE: dict[str, str] = {
    "Proofpoint": "gateway",
    "Mimecast": "gateway",
    "Barracuda": "gateway",
    "Cisco Secure Email (IronPort)": "gateway",
    "Trend Micro Email Security": "gateway",
    "Sophos Email": "gateway",
    "Trellix / FireEye Email Security (ETP)": "gateway",
    "Forcepoint Email Security": "gateway",
    "Agari": "sender",
    "Amazon SES (sender)": "sender",
    "SendGrid (sender)": "sender",
    "Mailgun (sender)": "sender",
    "Mailchimp / Mandrill (sender)": "sender",
    "Postmark (sender)": "sender",
    "SparkPost (sender)": "sender",
}

# Map an SPF include:/redirect= hostname to a friendly sending-service name.
# First substring hit wins; unmapped hosts are reported raw so nothing is lost.
SENDER_MAP: list[tuple[str, str]] = [
    ("spf.protection.outlook.com", "Microsoft 365"),
    ("protection.office365.us", "Microsoft 365 (US Gov)"),
    ("protection.partner.outlook.cn", "Microsoft 365 (China)"),
    ("_spf.google.com", "Google Workspace"),
    ("amazonses.com", "Amazon SES"),
    ("sendgrid.net", "SendGrid"),
    ("mailgun.org", "Mailgun"),
    ("mandrillapp.com", "Mandrill"),
    ("mcsv.net", "Mailchimp"), ("mcdlv.net", "Mailchimp"), ("rsgsv.net", "Mailchimp"),
    ("mailchimp", "Mailchimp"),
    ("mtasv.net", "Postmark"),
    ("sparkpostmail.com", "SparkPost"),
    ("pphosted.com", "Proofpoint"), ("ppops.net", "Proofpoint"),
    ("mimecast", "Mimecast"),
    ("zoho", "Zoho"),
    ("_spf.protonmail.ch", "Proton"),
    ("messagingengine.com", "Fastmail"),
    ("mailcontrol.com", "Forcepoint"),
    ("iphmx.com", "Cisco"),
    ("salesforce.com", "Salesforce"), ("exacttarget.com", "Salesforce Marketing Cloud"),
    ("pardot.com", "Pardot"),
    ("mailjet.com", "Mailjet"),
    ("sendinblue.com", "Brevo"), ("sibmail.com", "Brevo"),
    ("hubspotemail.net", "HubSpot"), ("hubspot", "HubSpot"),
    ("zendesk.com", "Zendesk"),
    ("freshemail.io", "Freshdesk"), ("freshdesk", "Freshdesk"),
    ("createsend.com", "Campaign Monitor"),
    ("constantcontact.com", "Constant Contact"),
    ("intercom.io", "Intercom"),
    ("qualtrics.com", "Qualtrics"),
    ("mktomail.com", "Marketo"), ("mktdns.com", "Marketo"),
    ("secureserver.net", "GoDaddy"),
    ("servers.mcsv.net", "Mailchimp"),
]


def map_sender(host: str) -> str | None:
    h = host.lower()
    for sub, name in SENDER_MAP:
        if sub in h:
            return name
    return None


# --------------------------------------------------------------------------- #
# Passive technology fingerprinting — which SaaS / apps / vendors the org uses,
# inferred from public DNS only (domain-verification TXT tokens, NS delegation,
# hosting cloud). No contact with the target's own servers.
# --------------------------------------------------------------------------- #
# (substring in a root TXT record, product name, category)
TXT_TECH: list[tuple[str, str, str]] = [
    ("google-site-verification", "Google (Workspace / Search Console)", "saas"),
    ("facebook-domain-verification", "Meta / Facebook", "saas"),
    ("workplace-domain-verification", "Meta Workplace", "saas"),
    ("atlassian-domain-verification", "Atlassian (Jira/Confluence)", "saas"),
    ("atlassian-sending-domain", "Atlassian", "saas"),
    ("docusign=", "DocuSign", "saas"),
    ("adobe-idp-site-verification", "Adobe", "saas"),
    ("adobe-sign-verification", "Adobe Sign", "saas"),
    ("stripe-verification", "Stripe", "saas"),
    ("dropbox-domain-verification", "Dropbox", "saas"),
    ("zoom-domain-verification", "Zoom", "saas"),
    ("miro-verification", "Miro", "saas"),
    ("notion-domain-verification", "Notion", "saas"),
    ("canva-site-verification", "Canva", "saas"),
    ("mongodb-site-verification", "MongoDB Atlas", "saas"),
    ("cisco-ci-domain-verification", "Cisco Webex", "saas"),
    ("webexdomainverification", "Cisco Webex", "saas"),
    ("logmein-verification", "GoTo / LogMeIn", "saas"),
    ("citrix-verification", "Citrix", "saas"),
    ("yandex-verification", "Yandex", "saas"),
    ("pinterest", "Pinterest", "saas"),
    ("zendesk", "Zendesk", "saas"),
    ("freshservice", "Freshservice", "saas"),
    ("freshdesk", "Freshdesk", "saas"),
    ("statuspage", "Atlassian Statuspage", "saas"),
    ("twilio-domain-verification", "Twilio", "saas"),
    ("klaviyo", "Klaviyo", "saas"),
    ("hubspot", "HubSpot", "saas"),
    ("marketo", "Marketo", "saas"),
    ("pardot", "Salesforce Pardot", "saas"),
    ("salesforce", "Salesforce", "saas"),
    ("servicenow", "ServiceNow", "saas"),
    ("workday", "Workday", "saas"),
    ("smartsheet", "Smartsheet", "saas"),
    ("onetrust", "OneTrust", "saas"),
    ("segment", "Segment", "saas"),
    ("intercom", "Intercom", "saas"),
    ("sendinblue", "Brevo", "saas"), ("brevo", "Brevo", "saas"),
    ("slack-domain-verification", "Slack", "saas"),
    ("gitlab", "GitLab", "saas"),
    ("shopify", "Shopify", "saas"),
    ("wix-domain-verification", "Wix", "saas"),
    ("squarespace", "Squarespace", "saas"),
    ("tableau", "Tableau", "saas"),
    ("box-verification", "Box", "saas"),
    ("apple-domain-verification", "Apple Business Manager", "saas"),
    # security / identity vendors
    ("okta-verification", "Okta", "security"), ("okta-domain", "Okta", "security"),
    ("duosecurity", "Cisco Duo", "security"),
    ("knowbe4", "KnowBe4 (awareness training)", "security"),
    ("mimecast", "Mimecast", "security"),
    ("proofpoint", "Proofpoint", "security"),
    ("globalsign-domain-verification", "GlobalSign (CA)", "security"),
    ("h1-domain-verification", "HackerOne (bug bounty)", "security"),
    ("bugcrowd", "Bugcrowd (bug bounty)", "security"),
    ("detectify", "Detectify (ASM)", "security"),
    ("onelogin", "OneLogin", "security"), ("pingidentity", "Ping Identity", "security"),
    ("ping-identity", "Ping Identity", "security"), ("jumpcloud", "JumpCloud", "security"),
    ("zscaler", "Zscaler", "security"), ("cloudflare-verify", "Cloudflare", "security"),
    ("mongodb-site-verification", "MongoDB Atlas", "saas"),
    ("elastic-domain-verification", "Elastic", "saas"),
    ("qualys", "Qualys", "security"), ("tenable", "Tenable", "security"),
    # expanded SaaS / collaboration / dev / analytics
    ("asana", "Asana", "saas"), ("monday.com", "monday.com", "saas"),
    ("clickup", "ClickUp", "saas"), ("airtable", "Airtable", "saas"),
    ("coda.io", "Coda", "saas"), ("figma", "Figma", "saas"),
    ("calendly", "Calendly", "saas"), ("typeform", "Typeform", "saas"),
    ("surveymonkey", "SurveyMonkey", "saas"), ("loom.com", "Loom", "saas"),
    ("drift.com", "Drift", "saas"), ("intercom", "Intercom", "saas"),
    ("freshworks", "Freshworks", "saas"), ("sap-", "SAP", "saas"),
    ("looker", "Looker", "saas"), ("snowflakecomputing", "Snowflake", "saas"),
    ("datadoghq", "Datadog", "saas"), ("newrelic", "New Relic", "saas"),
    ("sentry.io", "Sentry", "saas"), ("pagerduty", "PagerDuty", "saas"),
    ("gitlab", "GitLab", "saas"), ("github-challenge", "GitHub", "saas"),
    ("bitbucket", "Bitbucket", "saas"), ("bigcommerce", "BigCommerce", "saas"),
    ("magento", "Magento", "saas"), ("klaviyo", "Klaviyo", "saas"),
    ("segment", "Segment", "saas"), ("amplitude", "Amplitude", "saas"),
    ("mixpanel", "Mixpanel", "saas"), ("optimizely", "Optimizely", "saas"),
    ("pendo", "Pendo", "saas"), ("fullstory", "FullStory", "saas"),
    ("pardot", "Salesforce Pardot", "saas"), ("marketo", "Marketo", "saas"),
    ("twilio-domain", "Twilio", "saas"), ("paypal", "PayPal", "saas"),
    ("stripe-verification", "Stripe", "saas"), ("baidu-site-verification", "Baidu", "saas"),
    ("adobe-aem", "Adobe Experience Manager", "saas"),
]
# (substring in an NS hostname, DNS provider)
NS_TECH: list[tuple[str, str]] = [
    ("cloudflare", "Cloudflare DNS"), ("awsdns", "AWS Route 53"),
    ("azure-dns", "Azure DNS"), ("domaincontrol.com", "GoDaddy DNS"),
    ("nsone.net", "NS1"), ("ultradns", "UltraDNS"), ("dnsmadeeasy", "DNS Made Easy"),
    ("akam.net", "Akamai DNS"), ("akamai", "Akamai DNS"),
    ("googledomains", "Google Cloud DNS"), ("google.com", "Google Cloud DNS"),
    ("dnsimple", "DNSimple"), ("registrar-servers.com", "Namecheap DNS"),
    ("name-services.com", "Enom"), ("digitalocean.com", "DigitalOcean DNS"),
    ("worldnic.com", "Network Solutions DNS"), ("dynect", "Oracle Dyn"),
]


def detect_tech(res: DomainResult) -> None:
    """Infer the org's technology/SaaS footprint from public DNS signals only."""
    found: dict[str, str] = {}
    blob = " ".join(res.txt).lower()
    for sub, name, cat in TXT_TECH:
        if sub in blob:
            found.setdefault(name, cat)
    for ns in res.ns:
        for sub, name in NS_TECH:
            if sub in ns:
                found.setdefault(name, "dns")
                break
    web_cloud = (res.hosting.get("web") or {}).get("cloud")
    if web_cloud in ("Cloudflare", "Akamai", "Fastly"):
        found.setdefault(f"{web_cloud} (CDN/WAF)", "cdn")
    # Fold in everything the website fingerprint found, so TECHNOLOGY is the single
    # comprehensive collection of what the company runs.
    for page in res.website:
        for t in page.get("tech", []):
            found.setdefault(t, "web")
        for c in page.get("cdn_waf", []):
            found.setdefault(f"{c} (CDN/WAF)", "cdn")
    for h in res.discovery.get("hosts", []):      # subdomain tech profiler
        for t in h.get("tech", []):
            found.setdefault(t, "web")
    # De-duplicate: collapse "jQuery" + "jQuery 3.6.0" into the most specific one.
    def _base(name: str) -> str:
        n = re.sub(r"\s*\(.*?\)", "", name)            # drop "(CMS)" etc.
        n = re.sub(r"\s+[\d][\d.]*$", "", n)           # drop a trailing version
        return n.strip().lower()
    merged: dict[str, tuple[str, str]] = {}
    for name, cat in found.items():
        key = _base(name)
        if key not in merged or len(name) > len(merged[key][0]):
            merged[key] = (name, cat)
    res.tech = {name: cat for name, cat in merged.values()}


# --------------------------------------------------------------------------- #
# Result model
# --------------------------------------------------------------------------- #
@dataclass
class DomainResult:
    domain: str
    mx: list[str] = field(default_factory=list)
    spf: str = ""
    txt: list[str] = field(default_factory=list)
    ns: list[str] = field(default_factory=list)
    cnames: dict[str, str] = field(default_factory=dict)   # subdomain -> target
    dkim: dict[str, str] = field(default_factory=dict)     # selector -> target
    dmarc: str = ""
    spf_chain: list[tuple[str, str]] = field(default_factory=list)  # (source, spf)
    scores: dict[str, int] = field(default_factory=dict)
    evidence: dict[str, list[str]] = field(default_factory=dict)
    fields_hit: dict[str, set] = field(default_factory=dict)
    identity: dict[str, Any] = field(default_factory=dict)   # Entra ID tenant, etc.
    # Mail-flow analysis (filled by analyze()):
    mailbox: str = ""            # where the inbox actually lives
    mailbox_conf: int = 0
    mailbox_src: str = ""        # signature | gateway | mx | unknown
    gateway: str = ""            # inbound security filter in front of the mailbox (if any)
    senders: list[str] = field(default_factory=list)       # known outbound services
    sender_raw: list[str] = field(default_factory=list)    # unmapped SPF includes
    registration: dict[str, Any] = field(default_factory=dict)  # RDAP/WHOIS
    spoof: dict[str, Any] = field(default_factory=dict)          # SPF/DMARC/DKIM posture
    subdomains: list[str] = field(default_factory=list)         # from crt.sh
    hosting: dict[str, Any] = field(default_factory=dict)       # web + mail IP/ASN/cloud
    tech: dict[str, str] = field(default_factory=dict)          # name -> category
    website: list[dict] = field(default_factory=list)           # --web page fingerprints
    discovery: dict[str, Any] = field(default_factory=dict)     # --subs subdomain intel
    people: dict[str, Any] = field(default_factory=dict)        # --people email/OSINT
    services: dict[str, Any] = field(default_factory=dict)      # Shodan InternetDB (passive)
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        mailbox = None if self.error else (self.mailbox or "Unknown / self-hosted")
        return {
            "domain": self.domain,
            "provider": mailbox,          # = mailbox host (back-compat key)
            "confidence": self.mailbox_conf,
            "mailbox_source": self.mailbox_src or None,
            "error": self.error or None,
            "mail_flow": {
                "receiving": {
                    "mailbox": mailbox,
                    "inbound_gateway": self.gateway or None,
                },
                "sending": self.senders,
                "sending_other": self.sender_raw,
            },
            "records": {
                "mx": self.mx,
                "spf": self.spf,
                "ns": self.ns,
                "dmarc": self.dmarc,
                "cnames": self.cnames,
                "dkim": self.dkim,
            },
            "scores": self.scores,
            "evidence": self.evidence,
            "identity": self.identity or None,
            "registration": self.registration or None,
            "spoofability": self.spoof or None,
            "subdomains": self.subdomains or None,
            "hosting": self.hosting or None,
            "technology": self.tech or None,
            "website": self.website or None,
            "discovery": self.discovery or None,
            "people": self.people or None,
            "services": self.services or None,
        }


# --------------------------------------------------------------------------- #
# DNS over HTTPS
# --------------------------------------------------------------------------- #
async def _doh_one(client: httpx.AsyncClient, url: str,
                   name: str, rtype: str) -> list[dict]:
    try:
        r = await client.get(
            url,
            params={"name": name, "type": rtype},
            headers={"accept": "application/dns-json"},
        )
        if r.status_code != 200:
            return []
        return r.json().get("Answer", []) or []
    except (httpx.HTTPError, json.JSONDecodeError):
        return []


async def doh_query(client: httpx.AsyncClient, resolvers: list[str],
                    name: str, rtype: str) -> list[str]:
    """Query the record type across resolvers CONCURRENTLY; merge, dedupe rdata.

    Resolvers run in parallel so one slow or filtered endpoint cannot serialize-
    block the lookup — it just contributes nothing within its own timeout.
    """
    results = await asyncio.gather(
        *[_doh_one(client, RESOLVERS[r], name, rtype) for r in resolvers]
    )
    answers: list[str] = []
    seen: set[str] = set()
    for ans_list in results:
        for ans in ans_list:
            if RRTYPE.get(ans.get("type")) != rtype:   # DoH returns numeric type
                continue
            val = str(ans.get("data", "")).strip().strip('"').rstrip(".").lower()
            if val and val not in seen:
                seen.add(val)
                answers.append(val)
    return answers


def _spf_from_txt(txts: list[str]) -> str:
    for t in txts:
        if t.lower().startswith("v=spf1"):
            return t
    return ""


def _spf_targets(spf: str) -> list[str]:
    """Extract include: / redirect= hostnames from an SPF string."""
    out = []
    for tok in spf.lower().split():
        if tok.startswith("include:"):
            out.append(tok[8:])
        elif tok.startswith("redirect="):
            out.append(tok[9:])
    # drop macro-based includes (e.g. %{ir}...) that can't be resolved by name
    return [t for t in out if t and "%" not in t]


async def expand_spf(client: httpx.AsyncClient, resolvers: list[str], spf: str,
                     depth: int = 2, seen: set[str] | None = None
                     ) -> list[tuple[str, str]]:
    """Recursively resolve SPF include:/redirect= targets, returning (source, spf)
    pairs. Lets delegated domains (e.g. iana.org -> redirect=icann.org) still be
    classified by the provider referenced deeper in the SPF chain."""
    seen = seen if seen is not None else set()
    chain: list[tuple[str, str]] = []
    for tgt in _spf_targets(spf):
        if tgt in seen:
            continue
        seen.add(tgt)
        sub = _spf_from_txt(await doh_query(client, resolvers, tgt, "TXT"))
        if sub:
            chain.append((tgt, sub))
            if depth > 1:
                chain += await expand_spf(client, resolvers, sub, depth - 1, seen)
    return chain


async def collect_dns(client: httpx.AsyncClient, resolvers: list[str],
                      domain: str, deep: bool = False) -> DomainResult:
    res = DomainResult(domain=domain)
    # Critical signals (MX/TXT/NS/DMARC/SPF) use every resolver and are merged;
    # high-volume presence probes (subdomains, DKIM) hit one resolver to cut the
    # request count roughly in half — a missing CNAME on one resolver is rare and
    # never the deciding signal.
    probe = resolvers[:1]
    selectors = DKIM_SELECTORS + (DKIM_SELECTORS_DEEP if deep else [])

    mx, txt, ns, dmarc_txt, *sub_res = await asyncio.gather(
        doh_query(client, resolvers, domain, "MX"),
        doh_query(client, resolvers, domain, "TXT"),
        doh_query(client, resolvers, domain, "NS"),
        doh_query(client, resolvers, f"_dmarc.{domain}", "TXT"),
        *[doh_query(client, probe, f"{s}.{domain}", "CNAME")
          for s in PROBE_SUBDOMAINS if s != "_dmarc"],
    )
    res.mx = [m.split()[-1] if " " in m else m for m in mx]
    res.txt = txt
    res.spf = _spf_from_txt(txt)
    res.ns = ns
    res.dmarc = _spf_from_txt_dmarc(dmarc_txt)
    for sub, answers in zip([s for s in PROBE_SUBDOMAINS if s != "_dmarc"], sub_res):
        if answers:
            res.cnames[sub] = answers[0]

    # SPF chain + DKIM sweep, concurrently.
    spf_chain, *dk_res = await asyncio.gather(
        expand_spf(client, resolvers, res.spf) if res.spf else _empty(),
        *[doh_query(client, probe, f"{sel}._domainkey.{domain}", "CNAME")
          for sel in selectors],
    )
    res.spf_chain = spf_chain
    for sel, answers in zip(selectors, dk_res):
        if answers:
            res.dkim[sel] = answers[0]

    return res


def _spf_from_txt_dmarc(txts: list[str]) -> str:
    for t in txts:
        if t.lower().startswith("v=dmarc1"):
            return t
    return ""


# --------------------------------------------------------------------------- #
# Scoring
# --------------------------------------------------------------------------- #
def _field_values(res: DomainResult, fld: str) -> list[tuple[str, str]]:
    """Return (value, label) pairs for a signature field."""
    if fld == "mx":
        return [(v, f"MX {v}") for v in res.mx]
    if fld == "spf":
        vals = []
        if res.spf:
            vals.append((res.spf.lower(), f"SPF {res.spf}"))
        for src, s in res.spf_chain:
            vals.append((s.lower(), f"SPF via {src}"))
        return vals
    if fld == "txt":
        return [(v.lower(), f"TXT {v}") for v in res.txt]
    if fld == "cname":
        return [(v, f"CNAME {k}.{res.domain} -> {v}") for k, v in res.cnames.items()]
    if fld == "dkim":
        return [(v, f"DKIM {k}._domainkey -> {v}") for k, v in res.dkim.items()]
    return []


def _matches(value: str, mode: str, needle: str) -> bool:
    if mode == "suffix":
        return value.endswith(needle)
    if mode == "contains":
        return needle in value
    if mode == "equals":
        return value == needle
    return False


def score(res: DomainResult) -> None:
    for provider, sigs in PROVIDERS.items():
        total = 0
        ev: list[str] = []
        used: set[str] = set()      # don't count the same record under 2 signatures
        hit: set[str] = set()
        for fld, mode, needle, weight in sigs:
            for value, label in _field_values(res, fld):
                if value in used:
                    continue
                if _matches(value, mode, needle):
                    used.add(value)
                    total += weight
                    ev.append(f"[+{weight}] {label}")
                    hit.add(fld)
                    break
        if total:
            res.scores[provider] = total
            res.evidence[provider] = ev
            res.fields_hit[provider] = hit


# Common two-level public suffixes, so `mx.example.co.uk` → `example.co.uk`, not `co.uk`.
_TWO_LEVEL_TLDS = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "ltd.uk", "plc.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "co.nz", "net.nz", "org.nz",
    "co.jp", "or.jp", "ne.jp", "co.kr", "co.in", "net.in", "org.in", "co.za",
    "com.br", "com.mx", "com.ar", "com.tr", "com.cn", "net.cn", "com.sg",
    "com.hk", "com.tw", "co.il", "com.ua", "com.pl", "com.ph", "com.my",
    "co.id", "com.sa", "com.eg", "com.ng", "co.th", "com.vn",
}


def _registrable(host: str) -> str:
    """Best-effort registrable domain from a hostname (no PSL dependency)."""
    parts = host.lower().rstrip(".").split(".")
    if len(parts) <= 2:
        return ".".join(parts)
    if ".".join(parts[-2:]) in _TWO_LEVEL_TLDS:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def analyze(res: DomainResult) -> None:
    """Split the evidence into the three mail-flow roles: the mailbox host (where the
    inbox lives), the inbound gateway (a filter in front of it), and the sending
    services (who is authorized to send as the domain)."""
    strong = {p: s for p, s in res.scores.items()
              if res.fields_hit.get(p, set()) - {"txt"}}

    # Inbound gateway = a gateway-role provider the MX points at.
    gw, gw_score = "", -1
    for p, s in strong.items():
        if PROVIDER_ROLE.get(p) == "gateway" and "mx" in res.fields_hit.get(p, set()):
            if s > gw_score:
                gw, gw_score = p, s
    res.gateway = gw

    # Mailbox host = best mailbox-role provider; else "behind the gateway"; else unknown.
    mbs = {p: s for p, s in strong.items()
           if PROVIDER_ROLE.get(p, "mailbox") == "mailbox"}
    if mbs:
        mb = max(mbs, key=mbs.get)
        # Confidence in the mailbox is measured among mailbox candidates only, so a
        # gateway sitting in front (scored separately) doesn't deflate it.
        base = sum(mbs.values()) or 1
        res.mailbox = mb
        res.mailbox_conf = min(100, round(mbs[mb] / base * 100))
        res.mailbox_src = "signature"
    elif gw:
        res.mailbox = f"Unknown (behind {gw})"
        res.mailbox_conf = 0
        res.mailbox_src = "gateway"
    elif res.mx:
        # No signature matched, but the MX itself names the service — derive it from
        # the MX's registrable domain (e.g. smx.abv.bg / pmx.abv.bg -> abv.bg).
        mx_base = _registrable(res.mx[0])
        if mx_base == _registrable(res.domain):
            res.mailbox = f"Self-hosted ({mx_base})"
        else:
            res.mailbox = f"{mx_base} (unrecognised provider)"
        res.mailbox_conf = 0
        res.mailbox_src = "mx"
    else:
        res.mailbox = "No mail service (no MX records)"
        res.mailbox_conf = 0
        res.mailbox_src = "none"

    # Sending services = everything authorized to send: the SPF include/redirect chain
    # (mapped to friendly names) plus any sender-role provider seen via DKIM.
    named: list[str] = []
    raw: list[str] = []
    seen: set[str] = set()

    def _add(name: str, bucket: list[str]) -> None:
        if name and name not in seen:
            seen.add(name)
            bucket.append(name)

    includes: list[str] = _spf_targets(res.spf)
    for src, s in res.spf_chain:
        includes.append(src)
        includes += _spf_targets(s)
    for inc in includes:
        friendly = map_sender(inc)
        if friendly:
            _add(friendly, named)
        else:
            _add(inc, raw)
    for p in res.scores:
        if PROVIDER_ROLE.get(p) == "sender" and {"dkim"} & res.fields_hit.get(p, set()):
            _add(p.replace(" (sender)", ""), named)
    res.senders = named
    res.sender_raw = raw


# --------------------------------------------------------------------------- #
# Active confirmation (public, unauthenticated metadata only)
# --------------------------------------------------------------------------- #
# Microsoft login endpoints per sovereign cloud. The tenant is checked against
# each until found, so a domain living in the US Gov cloud (login.microsoftonline.us)
# or China cloud is correctly located, not missed.
M365_CLOUDS: list[tuple[str, str]] = [
    ("Commercial (Worldwide)", "login.microsoftonline.com"),
    ("US Gov (GCC High / DoD)", "login.microsoftonline.us"),
    ("China (21Vianet)", "login.partner.microsoftonline.cn"),
]

# Autodiscover SOAP endpoint per cloud, for GetFederationInformation.
AUTOD_SVC: dict[str, str] = {
    "login.microsoftonline.com": "https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc",
    "login.microsoftonline.us": "https://autodiscover-s.office365.us/autodiscover/autodiscover.svc",
    "login.partner.microsoftonline.cn": "https://autodiscover-s.partner.outlook.cn/autodiscover/autodiscover.svc",
}

_FED_ACTION = ("http://schemas.microsoft.com/exchange/2010/Autodiscover/"
               "Autodiscover/GetFederationInformation")
_FED_SOAP = """<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:exm="http://schemas.microsoft.com/exchange/services/2006/messages"
 xmlns:ext="http://schemas.microsoft.com/exchange/services/2006/types"
 xmlns:a="http://www.w3.org/2005/08/addressing"
 xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>
    <a:Action soap:mustUnderstand="1">{action}</a:Action>
    <a:To soap:mustUnderstand="1">{to}</a:To>
    <a:ReplyTo><a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address></a:ReplyTo>
  </soap:Header>
  <soap:Body>
    <GetFederationInformationRequestMessage
      xmlns="http://schemas.microsoft.com/exchange/2010/Autodiscover">
      <Request><Domain>{domain}</Domain></Request>
    </GetFederationInformationRequestMessage>
  </soap:Body>
</soap:Envelope>"""


async def enum_tenant_domains(client: httpx.AsyncClient, domain: str,
                              login_host: str) -> list[str]:
    """Public GetFederationInformation SOAP call: returns every domain registered
    in the tenant (incl. the <tenant>.onmicrosoft.com name). Unauthenticated."""
    svc = AUTOD_SVC.get(login_host, AUTOD_SVC["login.microsoftonline.com"])
    body = _FED_SOAP.format(action=_FED_ACTION, to=svc, domain=domain)
    headers = {
        "Content-Type": "text/xml; charset=utf-8",
        "SOAPAction": f'"{_FED_ACTION}"',
        "User-Agent": "AutodiscoverClient",
    }
    try:
        r = await client.post(svc, content=body, headers=headers)
        if r.status_code != 200:
            return []
        root = ET.fromstring(r.text)
    except (httpx.HTTPError, ET.ParseError):
        return []
    doms: set[str] = set()
    for el in root.iter():
        if el.tag.split("}")[-1] == "Domain" and el.text and "." in el.text:
            doms.add(el.text.strip().lower())
    return sorted(doms)


async def confirm_m365(client: httpx.AsyncClient, domain: str) -> dict[str, Any]:
    """Locate an M365/Entra tenant across sovereign clouds and read its federation
    posture. Domain-only lookups — no real user is ever queried."""
    out: dict[str, Any] = {"tenant_present": False}
    login_host = None

    # 1) OpenID configuration per cloud -> which cloud + tenant GUID
    for cloud_name, host in M365_CLOUDS:
        try:
            r = await client.get(
                f"https://{host}/{domain}/v2.0/.well-known/openid-configuration")
            if r.status_code == 200:
                issuer = r.json().get("issuer", "")
                out["tenant_present"] = True
                out["cloud"] = cloud_name
                out["login_host"] = host
                for p in issuer.split("/"):
                    if len(p) == 36 and p.count("-") == 4:
                        out["tenant_id"] = p
                        break
                login_host = host
                break
        except (httpx.HTTPError, json.JSONDecodeError):
            continue
    if not login_host:
        return out

    # 2) GetUserRealm (domain only) on the matching cloud -> Managed vs Federated
    try:
        r = await client.get(
            f"https://{login_host}/getuserrealm.srf?login={domain}&xml=1")
        if r.status_code == 200 and r.text.strip().startswith("<"):
            root = ET.fromstring(r.text)
            def _t(tag: str) -> str:
                el = root.find(tag)
                return el.text if el is not None and el.text else ""
            for tag, key in (("NameSpaceType", "namespace_type"),
                             ("FederationBrandName", "brand"),
                             ("AuthURL", "federation_auth_url"),
                             ("CloudInstanceName", "cloud_instance")):
                val = _t(tag)
                if val:
                    out[key] = val
    except (httpx.HTTPError, ET.ParseError):
        pass

    # 3) GetFederationInformation -> all tenant domains + onmicrosoft name
    doms = await enum_tenant_domains(client, domain, login_host)
    if doms:
        out["tenant_domains"] = doms
        onmib = [d for d in doms
                 if d.endswith(".onmicrosoft.com") and ".mail." not in d]
        if onmib:
            out["onmicrosoft"] = onmib[0]
    return out


async def confirm(client: httpx.AsyncClient, res: DomainResult) -> None:
    # Always query the public Entra/M365 metadata: a tenant may exist for identity
    # (SSO/Azure) even when mail is hosted elsewhere, and vice versa.
    info = await confirm_m365(client, res.domain)
    if info and info.get("tenant_present"):
        res.identity = info
        # Only harden the *mail* verdict when MX actually points at Exchange Online
        # (commercial, US Gov, or China cloud).
        eo_suffixes = ("mail.protection.outlook.com",
                       "mail.protection.office365.us",
                       "mail.protection.partner.outlook.cn")
        mx_is_eo = any(m.endswith(eo_suffixes) for m in res.mx)
        if mx_is_eo:
            prov = "Microsoft 365 / Exchange Online"
            res.scores[prov] = res.scores.get(prov, 0) + 20
            res.evidence.setdefault(prov, []).append(
                "[+20] confirmed Exchange Online tenant (openid-configuration)")
            res.fields_hit.setdefault(prov, set()).add("mx")


# --------------------------------------------------------------------------- #
# Domain registration (RDAP) + contact-leak check
# --------------------------------------------------------------------------- #
# Markers that indicate a WHOIS/RDAP field is privacy-protected, not real PII.
PRIVACY_MARKERS = (
    "redacted", "privacy", "whoisguard", "domains by proxy", "data protected",
    "withheld", "not disclosed", "gdpr", "statutory", "contactprivacy",
    "perfect privacy", "privacyguardian", "identity protection", "proxy",
    "private registration", "obscured", "data redacted", "non-public",
)
# Entity roles that carry registrant PII (vs. registrar/abuse which are expected public).
_PII_ROLES = ("registrant", "administrative", "technical", "billing")


def _vcard_to_dict(entity: dict) -> dict[str, str]:
    """Flatten an RDAP jCard (vcardArray) into {type: value}."""
    out: dict[str, str] = {}
    va = entity.get("vcardArray")
    if not isinstance(va, list) or len(va) < 2:
        return out
    for item in va[1]:
        if not isinstance(item, list) or len(item) < 4:
            continue
        key = str(item[0]).lower()
        val = item[3]
        if isinstance(val, list):
            val = " ".join(str(x) for x in val if x)
        val = str(val).strip()
        if val:
            out.setdefault(key, val)
    return out


def _is_privacy(text: str) -> bool:
    t = (text or "").lower()
    return any(m in t for m in PRIVACY_MARKERS)


async def lookup_rdap(client: httpx.AsyncClient, domain: str) -> dict[str, Any]:
    """Query public RDAP (via the rdap.org bootstrap) for registration data and flag
    whether registrant contact details are leaked rather than privacy-protected."""
    out: dict[str, Any] = {}
    try:
        r = await client.get(f"https://rdap.org/domain/{domain}",
                             headers={"accept": "application/rdap+json"})
        if r.status_code != 200:
            out["error"] = f"rdap http {r.status_code}"
            return out
        data = r.json()
    except (httpx.HTTPError, json.JSONDecodeError) as exc:
        out["error"] = type(exc).__name__
        return out

    for ev in data.get("events", []) or []:
        action, date = ev.get("eventAction"), ev.get("eventDate")
        if not date:
            continue
        date = date[:10]
        if action == "registration":
            out["created"] = date
        elif action == "expiration":
            out["expires"] = date
        elif action in ("last changed", "last update of RDAP database"):
            out.setdefault("updated", date)

    out["status"] = data.get("status", []) or []
    out["dnssec"] = bool((data.get("secureDNS") or {}).get("delegationSigned"))
    out["nameservers"] = sorted(
        ns["ldhName"].lower() for ns in data.get("nameservers", []) or []
        if ns.get("ldhName"))

    registrar = None
    abuse = None
    leaks: list[str] = []
    privacy = False

    def walk(ents: list) -> None:
        nonlocal registrar, abuse, privacy
        for ent in ents or []:
            roles = [str(x).lower() for x in ent.get("roles", []) or []]
            vc = _vcard_to_dict(ent)
            if "registrar" in roles:
                registrar = vc.get("fn") or registrar
                for pid in ent.get("publicIds", []) or []:
                    if str(pid.get("type", "")).lower().startswith("iana"):
                        out["registrar_ianaid"] = pid.get("identifier")
            if "abuse" in roles and vc.get("email"):
                abuse = abuse or vc.get("email")
            if any(role in roles for role in _PII_ROLES):
                role = next(r for r in _PII_ROLES if r in roles)
                for key, label in (("fn", "name"), ("org", "org"),
                                   ("email", "email"), ("adr", "address"),
                                   ("tel", "tel")):
                    v = vc.get(key)
                    if not v:
                        continue
                    if _is_privacy(v):
                        privacy = True
                    else:
                        leaks.append(f"{role} {label}={v[:60]}")
            walk(ent.get("entities"))

    walk(data.get("entities"))
    if data.get("redacted"):
        privacy = True

    if registrar:
        out["registrar"] = registrar
    if abuse:
        out["abuse_email"] = abuse
    out["leaks"] = leaks
    out["contact_status"] = ("leaked" if leaks
                             else "protected" if privacy else "not published")
    return out


async def whois_lookup(domain: str) -> dict[str, Any]:
    """Port-43 WHOIS fallback for TLDs without RDAP (many ccTLDs: .bg, .fr, …).
    Uses the <tld>.whois-servers.net alias; best-effort field parsing."""
    tld = domain.rsplit(".", 1)[-1]
    server = f"{tld}.whois-servers.net"
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(server, 43), timeout=6)
        writer.write((domain + "\r\n").encode())
        await writer.drain()
        raw = await asyncio.wait_for(reader.read(65535), timeout=6)
        writer.close()
    except (OSError, asyncio.TimeoutError):
        return {}
    text = raw.decode("utf-8", "ignore")
    if not text.strip():
        return {}

    def find(patterns: tuple[str, ...]) -> str:
        for p in patterns:
            m = re.search(p, text, re.I)
            if m:
                return m.group(1).strip().split("T")[0].strip()
        return ""

    registrar = find((r"Registrar:\s*(.+)", r"Registrar Name:\s*(.+)",
                      r"Sponsoring Registrar:\s*(.+)", r"registrar:\s*(.+)"))
    created = find((r"Creation Date:\s*(.+)", r"Registered On:\s*(.+)",
                   r"Registration Time:\s*(.+)", r"Domain Registration Date:\s*(.+)",
                   r"created:\s*(.+)", r"registered:\s*(.+)"))
    expires = find((r"Registry Expiry Date:\s*(.+)", r"Expiration Date:\s*(.+)",
                   r"Expiry Date:\s*(.+)", r"paid-till:\s*(.+)",
                   r"Expires On:\s*(.+)", r"renewal date:\s*(.+)", r"expire:\s*(.+)"))
    low = text.lower()
    if not (registrar or created or expires) and \
            ("no match" in low or "not found" in low or "no entries found" in low):
        return {"error": "whois: no record"}
    if not (registrar or created or expires):
        return {}
    return {"registrar": registrar, "created": created, "expires": expires,
            "contact_status": "not published", "source": "whois"}


# --------------------------------------------------------------------------- #
# Spoofability (SPF / DMARC / DKIM posture) — pure, no network
# --------------------------------------------------------------------------- #
def assess_spoofability(res: DomainResult) -> None:
    """Grade the domain's ability to resist email spoofing from SPF + DMARC + DKIM."""
    out: dict[str, Any] = {}
    spf = res.spf.lower()
    if not spf:
        spf_policy = "none"
    elif "+all" in spf:
        spf_policy = "pass-all (+all)"
    elif "-all" in spf:
        spf_policy = "hardfail (-all)"
    elif "~all" in spf:
        spf_policy = "softfail (~all)"
    elif "?all" in spf:
        spf_policy = "neutral (?all)"
    else:
        spf_policy = "no all-qualifier"
    out["spf"] = spf_policy

    dmarc = res.dmarc.lower()
    p, pct, rua = None, 100, False
    for tok in dmarc.replace(" ", "").split(";"):
        if tok.startswith("p="):
            p = tok[2:]
        elif tok.startswith("pct="):
            try:
                pct = int(tok[4:])
            except ValueError:
                pass
        elif tok.startswith("rua="):
            rua = True
    out["dmarc"] = (f"p={p}" + (f" pct={pct}" if pct != 100 else "")) if dmarc else "none"
    out["dmarc_rua"] = rua
    out["dkim"] = bool(res.dkim)

    reasons: list[str] = []
    spoofable = False
    if spf_policy in ("none", "neutral (?all)", "pass-all (+all)", "no all-qualifier"):
        spoofable = True
        reasons.append(f"weak/absent SPF ({spf_policy})")
    if not dmarc or p in (None, "none"):
        spoofable = True
        reasons.append("DMARC not enforced (p=none/absent)")
    elif p in ("quarantine", "reject") and pct < 100:
        reasons.append(f"DMARC only {pct}% enforced")

    if spoofable:
        verdict = "SPOOFABLE"
    elif p == "reject" and pct == 100 and spf_policy == "hardfail (-all)":
        verdict = "hardened"
    else:
        verdict = "partial"
    out["spoofable"] = spoofable
    out["verdict"] = verdict
    out["reasons"] = reasons
    res.spoof = out


# --------------------------------------------------------------------------- #
# Certificate Transparency (crt.sh) — subdomain / related-name discovery
# --------------------------------------------------------------------------- #
async def lookup_crtsh(client: httpx.AsyncClient, domain: str) -> list[str]:
    """Pull names from issued certificates via crt.sh — external subdomain OSINT.
    crt.sh is often overloaded (502/503), so retry a few times with a longer timeout."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json&exclude=expired"
    data = None
    for attempt in range(2):
        try:
            r = await client.get(url, headers={"accept": "application/json"},
                                 timeout=httpx.Timeout(12.0, connect=6.0))
            if r.status_code == 200 and r.text.strip():
                data = r.json()
                break
            if r.status_code < 500:        # 4xx won't fix on retry
                return []
        except (httpx.HTTPError, json.JSONDecodeError):
            break                          # timeout/transport: a retry just repeats it
        # only a fast 5xx is worth one short retry (crt.sh overload)
        if attempt == 0:
            await asyncio.sleep(0.5)
    if not data:
        return []
    subs: set[str] = set()
    for entry in data:
        for nm in str(entry.get("name_value", "")).replace("\r", "").split("\n"):
            nm = nm.strip().lower().lstrip("*.")
            if nm and nm != domain and nm.endswith("." + domain) and "@" not in nm:
                subs.add(nm)
    return sorted(subs)


# --------------------------------------------------------------------------- #
# Hosting / ASN attribution via Team Cymru IP-to-ASN (over DoH, no new services)
# --------------------------------------------------------------------------- #
CLOUD_BY_ASNAME: list[tuple[str, str]] = [
    ("AMAZON", "AWS"), ("AWS", "AWS"),
    ("MICROSOFT", "Microsoft/Azure"),
    ("GOOGLE", "Google"),
    ("CLOUDFLARE", "Cloudflare"),
    ("AKAMAI", "Akamai"), ("FASTLY", "Fastly"),
    ("DIGITALOCEAN", "DigitalOcean"), ("LINODE", "Linode/Akamai"),
    ("OVH", "OVH"), ("HETZNER", "Hetzner"),
    ("GODADDY", "GoDaddy"), ("SECURESERVER", "GoDaddy"),
    ("AUTOMATTIC", "WordPress/Automattic"),
    ("SQUARESPACE", "Squarespace"), ("SHOPIFY", "Shopify"),
    ("ALIBABA", "Alibaba"), ("ORACLE", "Oracle Cloud"),
    ("DIGITAL OCEAN", "DigitalOcean"), ("VULTR", "Vultr"),
]


def _cloud_of(as_name: str) -> str:
    u = (as_name or "").upper()
    for needle, label in CLOUD_BY_ASNAME:
        if needle in u:
            return label
    return ""


async def _cymru_ip_info(client: httpx.AsyncClient, resolvers: list[str],
                         ip: str) -> dict[str, Any]:
    if ip.count(".") != 3:          # IPv4 only (Cymru origin zone)
        return {"ip": ip}
    q = ".".join(reversed(ip.split("."))) + ".origin.asn.cymru.com"
    txts = await doh_query(client, resolvers, q, "TXT")
    if not txts:
        return {"ip": ip}
    parts = [p.strip() for p in txts[0].split("|")]
    asn = parts[0].split()[0] if parts and parts[0] else ""
    info: dict[str, Any] = {"ip": ip, "asn": f"AS{asn}" if asn else "",
                            "prefix": parts[1] if len(parts) > 1 else "",
                            "cc": parts[2] if len(parts) > 2 else ""}
    if asn:
        nt = await doh_query(client, resolvers, f"AS{asn}.asn.cymru.com", "TXT")
        if nt:
            info["as_name"] = [p.strip() for p in nt[0].split("|")][-1]
    info["cloud"] = _cloud_of(info.get("as_name", ""))
    return info


async def lookup_hosting(client: httpx.AsyncClient, resolvers: list[str],
                         res: DomainResult) -> dict[str, Any]:
    """Resolve the web root and primary MX to IPs and attribute each to an ASN/cloud."""
    out: dict[str, Any] = {}
    web_ips, mail_ips = await asyncio.gather(
        doh_query(client, resolvers, res.domain, "A"),
        doh_query(client, resolvers, res.mx[0], "A") if res.mx else _empty(),
    )
    if web_ips:
        out["web"] = await _cymru_ip_info(client, resolvers, web_ips[0])
    if mail_ips:
        out["mail"] = await _cymru_ip_info(client, resolvers, mail_ips[0])
    return out


async def _empty() -> list[str]:
    return []


def _cpe_name(cpe: str) -> str:
    """cpe:/a:igor_sysoev:nginx:1.18.0 -> 'nginx 1.18.0' (adjacent dups collapsed)."""
    s = cpe.replace("cpe:2.3:", "").replace("cpe:/", "")
    parts = [p for p in s.split(":") if p and p not in ("a", "o", "h", "*", "-")]
    out = []
    for p in parts:
        if not out or out[-1].lower() != p.lower():
            out.append(p)
    return " ".join(out[-2:]) if len(out) > 1 else " ".join(out)


async def lookup_services(client: httpx.AsyncClient, ips: list[str]) -> dict[str, Any]:
    """Open ports / software / CVEs from Shodan InternetDB — a PASSIVE lookup of
    Shodan's pre-indexed data (no packet is ever sent to the target)."""
    out: dict[str, Any] = {}

    async def one(ip: str) -> None:
        if ip.count(".") != 3:
            return
        try:
            r = await client.get(f"https://internetdb.shodan.io/{ip}",
                                 timeout=httpx.Timeout(8.0, connect=5.0))
            if r.status_code != 200:
                return
            d = r.json()
        except (httpx.HTTPError, json.JSONDecodeError):
            return
        if d.get("ports") or d.get("cpes") or d.get("vulns"):
            out[ip] = {"ports": sorted(d.get("ports", [])),
                       "software": sorted({_cpe_name(c) for c in d.get("cpes", []) if c}),
                       "vulns": sorted(d.get("vulns", []))}

    await asyncio.gather(*(one(ip) for ip in dict.fromkeys(ips)))
    return out


# well-known port → service name (ports NOT in this map are hidden from the table)
_PORT_SVC = {21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
             110: "pop3", 143: "imap", 443: "https", 445: "smb", 587: "smtp",
             993: "imaps", 995: "pop3s", 1433: "mssql", 3306: "mysql", 3389: "rdp",
             5432: "postgres", 6379: "redis", 8080: "http-alt", 8443: "https-alt",
             9200: "elasticsearch", 27017: "mongodb"}
# product keyword (from CPE) → typical ports, to attach a version to the right row
_PROD_PORTS = {
    "openssh": {22}, "ssh": {22}, "nginx": {80, 443, 8080, 8443},
    "apache": {80, 443, 8080, 8443}, "httpd": {80, 443}, "openresty": {80, 443},
    "litespeed": {80, 443}, "iis": {80, 443}, "tomcat": {8080, 8443, 80, 443},
    "exchange": {25, 443, 587, 993, 995}, "outlook": {443}, "postfix": {25, 587},
    "exim": {25, 587}, "dovecot": {110, 143, 993, 995}, "mysql": {3306},
    "mariadb": {3306}, "postgresql": {5432}, "redis": {6379}, "mongodb": {27017},
    "elasticsearch": {9200}, "proftpd": {21}, "vsftpd": {21}, "pure-ftpd": {21},
    "rdp": {3389}, "cloudflare": {80, 443}}
# Load-balancer / WAF vendor tokens stripped from a software string so the real
# product is kept, not the appliance — "f5 nginx 1.20" -> "nginx 1.20".
_SW_STRIP = {"f5", "big-ip"}


def _strip_lb(sw: str) -> str:
    toks = [t for t in sw.split() if t.lower() not in _SW_STRIP]
    return " ".join(toks)


def _service_table(s: dict) -> list[tuple]:
    """Build [(port, service, software)] rows for known ports only."""
    ports = [p for p in s.get("ports", []) if p in _PORT_SVC]
    # map each software string to the port(s) it typically serves
    port_sw: dict[int, list[str]] = {}
    for sw in s.get("software", []):
        low = sw.lower()
        hit: set[int] = set()
        for key, prts in _PROD_PORTS.items():
            if key in low:
                hit |= prts
        clean = _strip_lb(sw)      # drop the F5/BIG-IP token, keep e.g. "nginx"
        if not clean:              # a pure load-balancer entry -> nothing to show
            continue
        for p in hit & set(ports):
            port_sw.setdefault(p, []).append(clean)
    return [(p, _PORT_SVC[p], " / ".join(dict.fromkeys(port_sw.get(p, []))))
            for p in ports]


async def _check_buckets(client: httpx.AsyncClient, sld: str) -> list[str]:
    """Probe common cloud-storage bucket names for the company (hits the cloud
    provider, never the target). Reports buckets that exist."""
    names = list(dict.fromkeys([
        sld, f"{sld}-assets", f"{sld}-static", f"{sld}-backup", f"{sld}-media",
        f"{sld}-uploads", f"{sld}-prod", f"{sld}-dev"]))
    checks = []
    for n in names:
        checks.append(("S3", n, f"https://{n}.s3.amazonaws.com"))
        checks.append(("GCS", n, f"https://storage.googleapis.com/{n}"))
    results = await asyncio.gather(*(_probe(client, u) for _, _, u in checks))
    found: dict[str, str] = {}      # key -> label, so a bucket is never repeated
    for (prov, n, _), r in zip(checks, results):
        if r is None:
            continue
        sc, body = r.status_code, r.text[:1000].lower()
        key = f"{prov}:{n}"
        # Only trust the provider's own storage-API XML markers (no false positives).
        if sc == 200 and "<listbucketresult" in body:
            found[key] = f"{prov}: {n}  (public — listable)"
        elif sc == 403 and "accessdenied" in body and "<error" in body:
            found[key] = f"{prov}: {n}  (exists, private)"
        # 404 / NoSuchBucket / anything else → treat as not present
    return list(found.values())


async def _check_sourcemaps(client: httpx.AsyncClient, base: str, html: str) -> list[str]:
    """Look for exposed JS source maps (<bundle>.js.map) that leak frontend source."""
    base_host = urlparse(base).hostname or ""
    found, checked = [], 0
    srcs = re.findall(r'<script[^>]+src=["\']([^"\']+?\.js)(?:\?[^"\']*)?["\']', html, re.I)
    for s in dict.fromkeys(srcs):
        u = urljoin(base, s)
        if urlparse(u).hostname != base_host:
            continue
        checked += 1
        if checked > 6:
            break
        r = await _probe(client, u + ".map")
        if r is not None and r.status_code == 200 and '"sources"' in r.text[:2000]:
            found.append(u + ".map")
    return found


# --------------------------------------------------------------------------- #
# Website fingerprint (--web) — ACTIVE: fetches the target's own web root.
# --------------------------------------------------------------------------- #
_SEC_HEADERS = [
    ("strict-transport-security", "HSTS"),
    ("content-security-policy", "CSP"),
    ("x-frame-options", "X-Frame-Options"),
    ("x-content-type-options", "X-Content-Type-Options"),
    ("referrer-policy", "Referrer-Policy"),
    ("permissions-policy", "Permissions-Policy"),
]


def _detect_web_tech(headers, cookie_names: list[str], html: str
                     ) -> tuple[list[str], list[str]]:
    """Return (cdn_waf, tech) fingerprints from headers, cookies and HTML."""
    h = {k.lower(): str(v).lower() for k, v in headers.items()}
    srv = h.get("server", "")
    xpb = h.get("x-powered-by", "")
    hl = html.lower()
    cset = {c.lower() for c in cookie_names}
    gen = ""
    m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)',
                  html, re.I)
    if m:
        gen = m.group(1).lower()

    tech: list[str] = []
    def add(x: str) -> None:
        if x not in tech:
            tech.append(x)

    # CMS / site builders
    if "wp-content" in hl or "wp-includes" in hl or "wordpress" in gen \
            or any(c.startswith(("wordpress_", "wp-")) for c in cset):
        add("WordPress (CMS)")
    if "sites/default/files" in hl or "drupal" in gen or "x-drupal-cache" in h:
        add("Drupal (CMS)")
    if "/media/jui/" in hl or "joomla" in gen or "com_content" in hl:
        add("Joomla (CMS)")
    if "cdn.shopify.com" in hl or "x-shopify-stage" in h or "x-shopid" in h:
        add("Shopify")
    if "static.wixstatic.com" in hl or "x-wix-request-id" in h:
        add("Wix")
    if "squarespace" in hl:
        add("Squarespace")
    if "assets.website-files.com" in hl or "webflow" in hl:
        add("Webflow")
    if "hs-scripts.com" in hl or "hsforms" in hl:
        add("HubSpot CMS")
    if "ghost" in gen:
        add("Ghost (CMS)")
    # JS frameworks
    if "__next_data__" in hl or "/_next/" in hl:
        add("Next.js (React)")
    elif "data-reactroot" in hl or "reactdom" in hl:
        add("React")
    if "__nuxt__" in hl or "/_nuxt/" in hl:
        add("Nuxt (Vue)")
    elif "data-v-" in hl or "vue.js" in hl:
        add("Vue.js")
    if "ng-version" in hl or "ng-app" in hl:
        add("Angular")
    if "jquery" in hl:
        add("jQuery")
    if "bootstrap" in hl:
        add("Bootstrap")
    # backend languages
    if "php" in xpb or "phpsessid" in cset:
        add("PHP")
    if "asp.net" in xpb or "x-aspnet-version" in h or "asp.net_sessionid" in cset:
        add("ASP.NET")
    if "express" in xpb:
        add("Node.js / Express")
    if "jsessionid" in cset:
        add("Java (JSP/Servlet)")
    if "laravel_session" in cset:
        add("Laravel (PHP)")
    if "csrftoken" in cset and "csrfmiddlewaretoken" in hl:
        add("Django (Python)")
    if "_session_id" in cset or 'name="csrf-param"' in hl:
        add("Ruby on Rails")
    # analytics / marketing
    if "google-analytics.com" in hl or "googletagmanager.com" in hl or "gtag(" in hl:
        add("Google Analytics/GTM")
    if "hotjar" in hl:
        add("Hotjar")
    if "fbevents.js" in hl or "connect.facebook.net" in hl:
        add("Meta Pixel")

    cdn: list[str] = []
    def addc(x: str) -> None:
        if x not in cdn:
            cdn.append(x)
    if "cf-ray" in h or "cloudflare" in srv:
        addc("Cloudflare")
    if "x-amz-cf-id" in h or "cloudfront" in (h.get("via", "") + srv):
        addc("AWS CloudFront")
    if "x-akamai-transformed" in h or "akamaighost" in srv:
        addc("Akamai")
    if ("x-served-by" in h and "fastly" in h.get("x-served-by", "")) or "fastly" in srv:
        addc("Fastly")
    if "x-sucuri-id" in h:
        addc("Sucuri WAF")
    if "x-varnish" in h or "varnish" in h.get("via", ""):
        addc("Varnish")

    # ---- version enrichment -------------------------------------------------
    def _setver(prefix: str, version: str) -> None:
        for i, t in enumerate(tech):
            if t.startswith(prefix):
                if version and version not in t:
                    tech[i] = t.replace(prefix, f"{prefix} {version}", 1)
                return
    for lib, pat in (("jQuery", r"jquery[-/@. ]?(\d+\.\d+(?:\.\d+)?)"),
                     ("Bootstrap", r"bootstrap[-/@. ]?(\d+\.\d+(?:\.\d+)?)")):
        mv = re.search(pat, hl)
        if mv:
            _setver(lib, mv.group(1))
    mg = re.search(r"(wordpress|drupal|joomla|ghost)\s*([\d]+\.[\d.]+)", gen)
    if mg:
        _setver({"wordpress": "WordPress", "drupal": "Drupal",
                 "joomla": "Joomla", "ghost": "Ghost"}[mg.group(1)], mg.group(2))
    _SW = {"php": "PHP", "nginx": "Nginx", "apache": "Apache", "iis": "IIS",
           "microsoft-iis": "IIS", "openresty": "OpenResty", "litespeed": "LiteSpeed",
           "tomcat": "Tomcat", "jetty": "Jetty", "express": "Express"}
    for raw in (srv, xpb):
        mm = re.match(r"([a-z][a-z\-]*)/(\d[\w.]*)", raw)
        if mm:
            add(f"{_SW.get(mm.group(1), mm.group(1).capitalize())} {mm.group(2)}")
    return cdn, tech


def _favicon_url(html: str, base_url: str) -> str:
    for m in re.finditer(r'<link\b[^>]*>', html, re.I):
        tag = m.group(0)
        if re.search(r'rel=["\'][^"\']*icon', tag, re.I):
            hm = re.search(r'href=["\']([^"\']+)', tag, re.I)
            if hm:
                return urljoin(base_url, hm.group(1))
    return urljoin(base_url, "/favicon.ico")


def _meta_description(html: str) -> str:
    """What the site says it is — meta description / OpenGraph description."""
    for pat in (r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']+)',
                r'<meta[^>]+property=["\']og:description["\'][^>]+content=["\']([^"\']+)',
                r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\']description["\']'):
        m = re.search(pat, html, re.I)
        if m:
            txt = html_unescape(re.sub(r"\s+", " ", m.group(1)).strip())
            return txt[:180] + ("…" if len(txt) > 180 else "")
    return ""


# Applicant-tracking systems — a link to one is the company's real job portal.
_ATS = [
    ("boards.greenhouse.io", "Greenhouse"), ("greenhouse.io", "Greenhouse"),
    ("jobs.lever.co", "Lever"), ("lever.co", "Lever"),
    ("myworkdayjobs.com", "Workday"), ("smartrecruiters.com", "SmartRecruiters"),
    ("bamboohr.com", "BambooHR"), ("jobvite.com", "Jobvite"),
    ("ashbyhq.com", "Ashby"), ("recruitee.com", "Recruitee"),
    ("teamtailor.com", "Teamtailor"), ("workable.com", "Workable"),
    ("icims.com", "iCIMS"), ("taleo.net", "Oracle Taleo"),
    ("successfactors.com", "SAP SuccessFactors"), ("breezy.hr", "Breezy"),
    ("personio.", "Personio"), ("join.com", "Join"), ("careers-page.com", "CareersPage"),
    ("workforcenow.adp.com", "ADP"), ("eightfold.ai", "Eightfold"),
]
_CAREER_HREF = ("career", "/jobs", "jobs.", "join-us", "joinus", "vacanc",
                "hiring", "work-with-us", "opportunit", "job-opening")
_CAREER_TEXT = ("career", "jobs", "join us", "join our team", "we're hiring",
                "we are hiring", "vacanc", "work with us", "hiring", "open role")


_SOCIAL = [
    ("linkedin.com/company", "LinkedIn"), ("linkedin.com/school", "LinkedIn"),
    ("linkedin.com/in/", "LinkedIn"), ("facebook.com", "Facebook"),
    ("twitter.com", "X/Twitter"), ("x.com/", "X/Twitter"),
    ("instagram.com", "Instagram"), ("youtube.com", "YouTube"), ("youtu.be", "YouTube"),
    ("github.com", "GitHub"), ("gitlab.com", "GitLab"),
    ("t.me/", "Telegram"), ("tiktok.com", "TikTok"), ("pinterest.", "Pinterest"),
    ("medium.com", "Medium"), ("discord.gg", "Discord"), ("discord.com/invite", "Discord"),
    ("wa.me/", "WhatsApp"), ("reddit.com", "Reddit"), ("vimeo.com", "Vimeo"),
    ("crunchbase.com", "Crunchbase"), ("glassdoor.", "Glassdoor"), ("threads.net", "Threads"),
]
_SOCIAL_SKIP = ("/share", "sharer", "/intent/", "shareartic", "share?", "=share")


def _extract_social(html: str, base_url: str) -> dict[str, str]:
    """Collect the company's social-media / profile links (first of each platform)."""
    found: dict[str, str] = {}
    base_reg = _registrable(urlparse(base_url).hostname or "")
    for m in re.finditer(r'href=["\']([^"\']+)["\']', html, re.I):
        href = m.group(1)
        hl = href.lower()
        if hl.startswith(("mailto:", "tel:", "javascript:", "#")):
            continue
        if any(s in hl for s in _SOCIAL_SKIP):     # skip share-button links
            continue
        full = urljoin(base_url, href)
        host = urlparse(full).hostname or ""
        if _registrable(host) == base_reg:         # skip links to the target's own domain
            continue
        for sub, name in _SOCIAL:
            if sub in hl:
                found.setdefault(name, full)
                break
    return found


def _cert_status(not_after: str) -> tuple[Any, str]:
    """Parse an RFC-1123-ish notAfter string; return (days_left, YYYY-MM-DD)."""
    try:
        dt = datetime.strptime(not_after.replace(" GMT", ""),
                               "%b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc)
    except ValueError:
        return None, not_after
    return (dt - datetime.now(timezone.utc)).days, dt.strftime("%Y-%m-%d")


def _extract_careers(html: str, base_url: str) -> tuple[str, str]:
    """Find the careers/jobs URL; prefer a direct ATS link. Returns (url, ats_name)."""
    best = ""
    for m in re.finditer(r'<a\b[^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)</a>',
                         html, re.I | re.S):
        href = m.group(1)
        hl = href.lower()
        if hl.startswith(("mailto:", "tel:", "javascript:", "#")):
            continue
        for sub, name in _ATS:          # ATS link is the strongest signal
            if sub in hl:
                return urljoin(base_url, href), name
        if not best:
            text = re.sub(r"<[^>]+>", "", m.group(2)).strip().lower()
            if any(k in hl for k in _CAREER_HREF) or any(k in text for k in _CAREER_TEXT):
                best = urljoin(base_url, href)
    return best, ""


def _parse_page(resp: "httpx.Response") -> dict[str, Any]:
    """Build a website fingerprint from a fetched response."""
    final = str(resp.url)
    out: dict[str, Any] = {"url": final, "status": resp.status_code,
                           "https": final.startswith("https")}
    if resp.history:
        out["redirects"] = [str(h.url) for h in resp.history]
    body = resp.text if "html" in resp.headers.get("content-type", "").lower() else ""
    tm = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    if tm:
        out["title"] = html_unescape(re.sub(r"\s+", " ", tm.group(1)).strip())[:120]
    desc = _meta_description(body)
    if desc:
        out["description"] = desc
    try:
        cookie_names = [c.split("=", 1)[0].strip()
                        for c in resp.headers.get_list("set-cookie")]
    except Exception:  # noqa: BLE001
        cookie_names = []
    out["server"] = resp.headers.get("server", "")
    out["powered_by"] = resp.headers.get("x-powered-by", "")
    cdn, tech = _detect_web_tech(resp.headers, cookie_names, body)
    out["cdn_waf"] = cdn
    out["tech"] = tech
    hk_present = {k.lower() for k in resp.headers}
    out["security_headers"] = {
        "present": [lbl for hk, lbl in _SEC_HEADERS if hk in hk_present],
        "missing": [lbl for hk, lbl in _SEC_HEADERS if hk not in hk_present],
    }
    careers, ats = _extract_careers(body, final)
    if careers:
        out["careers_url"] = careers
    if ats:
        out["ats"] = ats
    social = _extract_social(body, final)
    if social:
        out["social"] = social
    out["favicon"] = _favicon_url(body, final)
    return out


async def fetch_page(client: httpx.AsyncClient, url: str) -> dict[str, Any]:
    """Fetch one explicit URL and fingerprint it (scheme auto-added if missing)."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    try:
        resp = await client.get(
            url, headers={"User-Agent": random.choice(USER_AGENTS),
                          "Accept": "text/html,application/xhtml+xml,*/*;q=0.8"},
            timeout=httpx.Timeout(7.0, connect=4.0))
    except httpx.HTTPError as exc:
        return {"url": url, "error": type(exc).__name__}
    return _parse_page(resp)


def _cert_info(domain: str, timeout: float = 6.0) -> dict[str, Any]:
    """TLS certificate intelligence (issuer, expiry, SANs) via a validated handshake."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ss:
                cert = ss.getpeercert()
    except Exception:  # noqa: BLE001 - invalid/expired cert or unreachable
        return {}
    issuer = {}
    for part in cert.get("issuer", []):
        for k, v in part:
            issuer[k] = v
    sans = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]
    return {"issuer": issuer.get("organizationName") or issuer.get("commonName", ""),
            "not_after": cert.get("notAfter", ""), "sans": sans}


async def _probe(client: httpx.AsyncClient, url: str) -> "httpx.Response | None":
    try:
        return await client.get(url, headers={"User-Agent": random.choice(USER_AGENTS)},
                               timeout=httpx.Timeout(8.0, connect=5.0))
    except httpx.HTTPError:
        return None


async def _web_extras(client: httpx.AsyncClient, base: str, domain: str) -> dict[str, Any]:
    """robots/sitemap/.git/docs presence, first-seen (Wayback) and TLS cert."""
    out: dict[str, Any] = {}
    robots_u = urljoin(base, "/robots.txt")
    sitemap_u = urljoin(base, "/sitemap.xml")
    robots, sitemap, git, wb, cert = await asyncio.gather(
        _probe(client, robots_u),
        _probe(client, sitemap_u),
        _probe(client, urljoin(base, "/.git/HEAD")),
        _probe(client, f"http://web.archive.org/cdx/search/cdx?url={domain}"
                       "&output=json&fl=timestamp&limit=1&sort=ascending"),
        asyncio.to_thread(_cert_info, domain),
    )
    if robots is not None and robots.status_code == 200 and \
            any(k in robots.text.lower() for k in ("user-agent", "disallow", "sitemap")):
        out["robots"] = robots_u
    if sitemap is not None and sitemap.status_code == 200 and \
            ("<urlset" in sitemap.text.lower() or "<sitemapindex" in sitemap.text.lower()):
        out["sitemap"] = sitemap_u
    if git is not None and git.status_code == 200 and git.text.strip().startswith("ref:"):
        out["git_exposed"] = True
    if wb is not None and wb.status_code == 200:
        try:
            rows = wb.json()
            if len(rows) > 1 and rows[1]:
                ts = rows[1][0]
                out["first_seen"] = f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}"
        except (json.JSONDecodeError, IndexError):
            pass
    if cert:
        out["cert"] = cert
    return out


async def fetch_website(client: httpx.AsyncClient, domain: str) -> list[dict]:
    """Fingerprint the domain's web root (trying HTTPS, then HTTP)."""
    resp = None
    err = ""
    for scheme in ("https", "http"):
        try:
            resp = await client.get(
                f"{scheme}://{domain}",
                headers={"User-Agent": random.choice(USER_AGENTS),
                         "Accept": "text/html,application/xhtml+xml,*/*;q=0.8"},
                timeout=httpx.Timeout(10.0, connect=5.0))
            break
        except httpx.HTTPError as exc:
            err = type(exc).__name__
    if resp is None:
        return [{"url": f"https://{domain}", "error": err or "unreachable"}]
    root = _parse_page(resp)
    base = str(resp.url)
    extras, buckets, smaps = await asyncio.gather(
        _web_extras(client, base, domain),
        _check_buckets(client, domain.split(".")[0]),
        _check_sourcemaps(client, base, resp.text if "html" in
                          resp.headers.get("content-type", "").lower() else ""))
    root.update(extras)
    if buckets:
        root["buckets"] = buckets
    if smaps:
        root["sourcemaps"] = smaps
    return [root]


# --------------------------------------------------------------------------- #
# Subdomain intelligence (--subs) — probe common hostnames; flag VPN/portals and
# the likely origin behind a CDN/WAF.
# --------------------------------------------------------------------------- #
_SUBS = [
    "www", "mail", "webmail", "owa", "autodiscover", "smtp", "imap", "mx",
    "vpn", "sslvpn", "remote", "portal", "gateway", "citrix", "access",
    "sso", "adfs", "okta", "auth", "login",
    "api", "dev", "staging", "stage", "test", "uat", "demo",
    "git", "gitlab", "jenkins", "jira", "confluence", "wiki",
    "admin", "cpanel", "whm", "ftp", "intranet", "internal",
    "app", "apps", "cloud", "m", "blog", "shop", "status", "cdn", "assets",
]
_VPN_HINTS = ("vpn", "sslvpn", "remote", "portal", "gateway", "citrix", "access")


async def discover_subdomains(client: httpx.AsyncClient, resolvers: list[str],
                              domain: str, ct_subs: list[str]) -> dict[str, Any]:
    probe = resolvers[:1]
    # Candidate hostnames = curated probe list + every CT-discovered name, merged.
    names = {f"{s}.{domain}" for s in _SUBS}
    names |= {s for s in ct_subs if s.endswith("." + domain)}
    names = sorted(names)
    # Wildcard-DNS detection: if a random label resolves, the zone answers every
    # name — drop hosts that merely echo that wildcard IP so the list isn't noise.
    rnd = await doh_query(client, probe,
                          f"zz{random.randint(10**9, 10**10)}no.{domain}", "A")
    wildcard_ip = rnd[0] if rnd else None
    answers = await asyncio.gather(
        *[doh_query(client, probe, name, "A") for name in names])
    hosts: list[dict] = []
    for name, ips in zip(names, answers):
        if ips and ips[0] != wildcard_ip:
            first = name.split(".", 1)[0]
            hosts.append({"host": name, "ip": ips[0],
                          "vpn": any(h in first for h in _VPN_HINTS)})
    # Technology profiler: fetch each live subdomain and fingerprint it. Skip hosts
    # that are mail/FTP/infra only (they rarely serve HTTP and just waste a timeout).
    _NOHTTP = ("mx", "smtp", "imap", "pop", "ftp", "ns1", "ns2", "mail")
    sem = asyncio.Semaphore(16)

    async def _profile(h: dict) -> None:
        if h["host"].split(".", 1)[0] in _NOHTTP:
            return
        async with sem:
            page = await fetch_page(client, f"https://{h['host']}")
            if page.get("tech"):
                h["tech"] = page["tech"]
            if page.get("title"):
                h["title"] = page["title"]
    # IPs are resolved for every host above; tech-profile up to 50 to bound runtime.
    await asyncio.gather(*(_profile(h) for h in hosts[:50]))
    return {"hosts": hosts, "wildcard": wildcard_ip,
            "vpn_portals": [h["host"] for h in hosts if h["vpn"]]}


# --------------------------------------------------------------------------- #
# People / email OSINT (--people) — harvest employee emails & names from the
# company's own pages, infer the email format, and emit ready-to-run OSINT
# queries for sources that can't be scraped programmatically (LinkedIn/ZoomInfo/
# RocketReach/Google). No credentials; only the target's public pages + dork URLs.
# --------------------------------------------------------------------------- #
_PEOPLE_PATHS = ["", "/about", "/about-us", "/team", "/our-team", "/company",
                 "/leadership", "/people", "/contact", "/contact-us", "/staff",
                 "/management", "/about/team", "/en/about", "/company/team"]
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")


def _infer_email_format(emails: list[str], domain: str) -> str:
    locals_ = [e.split("@", 1)[0].lower() for e in emails]
    for pat, label in ((r"[a-z]+\.[a-z]+", "first.last"),
                       (r"[a-z]\.[a-z]+", "f.last"),
                       (r"[a-z]+_[a-z]+", "first_last"),
                       (r"[a-z]+-[a-z]+", "first-last")):
        if any(re.fullmatch(pat, loc) for loc in locals_):
            return f"{label}@{domain}"
    if locals_:
        return f"(unclear — sample: {locals_[0]}@{domain})"
    return ""


async def _ddg(client: httpx.AsyncClient, query: str, limit: int = 30) -> list[tuple]:
    """Scrape-friendly search via DuckDuckGo HTML; returns (title, url) results."""
    try:
        r = await client.get("https://html.duckduckgo.com/html/",
                             params={"q": query},
                             headers={"User-Agent": random.choice(USER_AGENTS)},
                             timeout=httpx.Timeout(9.0, connect=5.0))
        if r.status_code != 200:
            return []
        body = r.text
    except httpx.HTTPError:
        return []
    out = []
    for m in re.finditer(
            r'<a[^>]+class="result__a"[^>]+href="([^"]+)"[^>]*>(.*?)</a>',
            body, re.I | re.S):
        href, title = m.group(1), html_unescape(re.sub(r"<[^>]+>", "", m.group(2)))
        title = re.sub(r"\s+", " ", title).strip()
        mm = re.search(r"uddg=([^&]+)", href)
        if mm:
            href = unquote(mm.group(1))
        out.append((title, href))
        if len(out) >= limit:
            break
    return out


def _parse_linkedin_title(title: str) -> tuple | None:
    """'First Last - Position - Company | LinkedIn' -> (name, position)."""
    t = re.split(r"\s[|–]\sLinkedIn|\s\|\s", title)[0]
    parts = re.split(r"\s[-–]\s", t)
    name = parts[0].strip()
    pos = parts[1].strip() if len(parts) > 1 else ""
    if re.fullmatch(r"[A-Z][\w.'’\-]+(?: [A-Z][\w.'’\-]+){1,3}", name):
        return name, pos
    return None


def _email_from_name(name: str, fmt: str, domain: str) -> str:
    toks = [re.sub(r"[^a-z]", "", t.lower()) for t in name.split()]
    toks = [t for t in toks if t]
    if len(toks) < 2 or not fmt:
        return ""
    first, last = toks[0], toks[-1]
    if fmt.startswith("first.last"):
        local = f"{first}.{last}"
    elif fmt.startswith("f.last"):
        local = f"{first[0]}.{last}"
    elif fmt.startswith("first_last"):
        local = f"{first}_{last}"
    elif fmt.startswith("first-last"):
        local = f"{first}-{last}"
    else:
        return ""
    return f"{local}@{domain}"


async def gather_people(client: httpx.AsyncClient, domain: str) -> dict[str, Any]:
    urls = [f"https://{domain}{p}" for p in _PEOPLE_PATHS]
    pages = await asyncio.gather(*[_probe(client, u) for u in urls])
    emails: set[str] = set()
    names: set[str] = set()
    for r in pages:
        if r is None or r.status_code != 200 or "html" not in \
                r.headers.get("content-type", "").lower():
            continue
        body = r.text
        for e in _EMAIL_RE.findall(body):
            if e.lower().endswith("@" + domain):
                emails.add(e.lower())
        for m in re.finditer(r'mailto:([^"\'?>]+)["\'][^>]*>([^<]{2,60})<', body):
            addr, txt = m.group(1).strip().lower(), re.sub(r"\s+", " ", m.group(2)).strip()
            if addr.endswith("@" + domain):
                emails.add(addr)
            if txt and "@" not in txt and re.fullmatch(r"[A-Z][A-Za-z.'\- ]{2,40}", txt):
                names.add(txt)
    sld = domain.split(".")[0]
    fmt = _infer_email_format(sorted(emails), domain)

    # --- Find the company on LinkedIn (via DuckDuckGo); only list it if found ---
    company_url = ""
    for _title, url in await _ddg(client, f'site:linkedin.com/company "{sld}"'):
        if "linkedin.com/company/" in url:
            company_url = url.split("?")[0]
            break
    employees: list[dict] = []
    if company_url:
        seen: set[str] = set()
        for title, url in await _ddg(client, f'site:linkedin.com/in "{sld}"'):
            if "linkedin.com/in/" not in url:
                continue
            parsed = _parse_linkedin_title(title)
            if not parsed:
                continue
            nm, pos = parsed
            if nm.lower() in seen:
                continue
            seen.add(nm.lower())
            employees.append({"name": nm, "position": pos,
                              "email": _email_from_name(nm, fmt, domain)})
            if len(employees) >= 20:
                break

    # --- Google operator leads: LinkedIn people + documents & sensitive info ---
    g = "https://www.google.com/search?q="
    leads = [
        ("LinkedIn employees", g + quote_plus(f'site:linkedin.com/in "{sld}"')),
        ("LinkedIn company", g + quote_plus(f'site:linkedin.com/company "{sld}"')),
        ("Public documents", g + quote_plus(
            f"site:{domain} (filetype:pdf OR filetype:docx OR filetype:xlsx "
            "OR filetype:pptx OR filetype:csv)")),
        ("Sensitive content", g + quote_plus(
            f'site:{domain} (confidential OR "internal use only" OR password '
            'OR "not for distribution")')),
        ("Open directories", g + quote_plus(f'site:{domain} intitle:"index of"')),
        ("Login & admin portals", g + quote_plus(
            f"site:{domain} (inurl:login OR inurl:admin OR inurl:portal)")),
        ("Indexed email addresses", g + quote_plus(f'"@{domain}"')),
    ]
    return {"emails": sorted(emails), "names": sorted(names), "email_format": fmt,
            "company_linkedin": company_url, "employees": employees, "leads": leads}


# Browser User-Agents rotated for the website fetch (shared by the web helpers).
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
]

# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #
async def assess(client: httpx.AsyncClient, resolvers: list[str], domain: str,
                 passive: bool, rdap: bool, ct: bool, hosting: bool,
                 deep: bool = False, web: bool = False, subs: bool = False,
                 people: bool = False) -> DomainResult:
    try:
        res = await collect_dns(client, resolvers, domain, deep)
        score(res)
        if not passive:
            # All active lookups run concurrently; one failing never kills the rest.
            jobs: dict[str, Any] = {"confirm": confirm(client, res)}
            if rdap:
                jobs["reg"] = lookup_rdap(client, domain)
            if ct:
                jobs["ct"] = lookup_crtsh(client, domain)
            if hosting:
                jobs["host"] = lookup_hosting(client, resolvers, res)
            if web:
                jobs["web"] = fetch_website(client, domain)
            done = await asyncio.gather(*jobs.values(), return_exceptions=True)
            out = dict(zip(jobs.keys(), done))
            if isinstance(out.get("reg"), dict):
                res.registration = out["reg"]
            if isinstance(out.get("ct"), list):
                res.subdomains = out["ct"]
            if isinstance(out.get("host"), dict):
                res.hosting = out["host"]
            if isinstance(out.get("web"), list):
                res.website = out["web"]
            if subs:
                res.discovery = await discover_subdomains(
                    client, resolvers, domain, res.subdomains)
            # People/email OSINT only for a registered domain with a real identity.
            if people and res.ns and res.identity.get("tenant_present"):
                res.people = await gather_people(client, domain)
            # Passive open-ports/service lookup (Shodan InternetDB) — web IP only.
            web_ip = (res.hosting.get("web") or {}).get("ip")
            if web_ip:
                res.services = await lookup_services(client, [web_ip])
            # RDAP failed (often a ccTLD without RDAP) → try a port-43 WHOIS fallback.
            if rdap and res.registration.get("error"):
                w = await whois_lookup(domain)
                if w:
                    res.registration = w
        analyze(res)
        assess_spoofability(res)        # pure; useful even in --passive
        detect_tech(res)                # pure; passive SaaS/tech fingerprint
    except Exception as exc:  # noqa: BLE001 - keep the batch alive
        res = DomainResult(domain=domain, error=f"{type(exc).__name__}: {exc}")
    return res


async def run(domains: list[str], resolvers: list[str], passive: bool,
              concurrency: int, timeout: float, rdap: bool = True,
              ct: bool = True, hosting: bool = True, deep: bool = False,
              web: bool = False, subs: bool = False, people: bool = False,
              proxy: str | None = None, on_done=None) -> list[DomainResult]:
    # Explicit connect timeout so a filtered endpoint (e.g. Quad9 :5053 behind a
    # firewall) fails fast instead of hanging past the read timeout.
    tmo = httpx.Timeout(timeout, connect=min(timeout, 4.0))
    limits = httpx.Limits(max_connections=concurrency * 4)
    sem = asyncio.Semaphore(concurrency)
    async with httpx.AsyncClient(
        timeout=tmo, limits=limits, follow_redirects=True, proxy=proxy or None,
        headers={"User-Agent": "ghosteye/1.0 (+authorized-assessment)"},
    ) as client:
        async def _bounded(d: str) -> DomainResult:
            async with sem:
                return await assess(client, resolvers, d, passive, rdap, ct,
                                    hosting, deep, web, subs, people)
        results: list[DomainResult] = []
        # Stream: emit each domain the moment it finishes, so a slow target never
        # swallows the whole run's output.
        for fut in asyncio.as_completed([_bounded(d) for d in domains]):
            res = await fut
            results.append(res)
            if on_done:
                on_done(res)
        return results


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #
class C:
    G = "\033[92m"; Y = "\033[93m"; R = "\033[91m"; B = "\033[94m"
    C_ = "\033[96m"; DIM = "\033[2m"; BOLD = "\033[1m"; X = "\033[0m"


def _color_conf(conf: int) -> str:
    c = C.G if conf >= 60 else C.Y if conf >= 30 else C.R
    return f"{c}{conf}%{C.X}"


_LW = 16          # label column width
_GUTTER = 2 + _LW  # left indent + label width


def _term_width() -> int:
    try:
        return max(60, shutil.get_terminal_size((100, 24)).columns)
    except OSError:
        return 100


def _row(label: str, value: str) -> None:
    """Print 'label  value', wrapping long plain values to the value column so the
    layout survives a narrow terminal. Coloured values are printed as-is (their ANSI
    codes would break width maths) but are always short."""
    avail = _term_width() - _GUTTER
    if "\033" in value or len(value) <= avail:
        print(f"  {label:<{_LW}}{value}")
        return
    lines = textwrap.wrap(value, max(24, avail),
                          break_long_words=False, break_on_hyphens=False) or [value]
    print(f"  {label:<{_LW}}{lines[0]}")
    for cont in lines[1:]:
        print(f"  {'':<{_LW}}{cont}")


def _rows(label: str, items: list[str]) -> None:
    """Label once, then one item per line aligned under the value column."""
    if not items:
        return
    print(f"  {label:<{_LW}}{items[0]}")
    for it in items[1:]:
        print(f"  {'':<{_LW}}{it}")


def _section(title: str) -> None:
    print(f"\n  {C.BOLD}{C.B}{title}{C.X}")


_ORG_UPPER = {"llc", "inc", "ltd", "lp", "plc", "sa", "sas", "ag", "bv", "gmbh",
              "srl", "spa", "pty", "corp", "co", "as", "oy", "ab"}


def _pretty_org(s: str) -> str:
    """Cymru returns lowercased org names; title-case them, keeping LLC/INC/etc upper."""
    out = []
    for w in s.split():
        out.append(w.upper() if w.strip(",.").lower() in _ORG_UPPER
                   else w[:1].upper() + w[1:])
    return " ".join(out)


_CDN_NETS = [ipaddress.ip_network(n) for n in (
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22")]   # Cloudflare


def _is_cdn_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _CDN_NETS)


def _host_str(h: dict) -> str:
    if not h:
        return ""
    ip = h.get("ip", "")
    asn = h.get("asn", "")
    cc = (h.get("cc", "") or "").upper()
    # Cymru AS name looks like "DIGITALOCEAN-ASN - DigitalOcean, LLC, US";
    # keep the descriptive part and drop the trailing country duplicate.
    name = h.get("as_name", "")
    org = name.split(" - ", 1)[1] if " - " in name else name
    if cc and org.upper().rstrip(".").endswith(", " + cc):
        org = org.rsplit(",", 1)[0]
    org = _pretty_org(org.strip().strip(",").strip())
    cloud = h.get("cloud", "")
    tag = f" ({cloud})" if cloud and cloud.lower() not in org.lower() else ""
    # labelled, single row: IP | Org | ASN | Country
    parts = []
    if ip:
        parts.append(f"IP: {ip}")
    if org:
        parts.append(f"Org: {org}{tag}")
    if asn:
        parts.append(f"ASN: {asn}")
    if cc:
        parts.append(f"Country: {cc}")
    return " | ".join(parts)


def print_human(res: DomainResult, full: bool = False) -> None:
    if res.error:
        print(f"\n{C.BOLD}{C.C_}{res.domain}{C.X}  {C.R}ERROR{C.X} {res.error}")
        return

    # ---- header ----
    print(f"\n  {C.BOLD}{C.C_}{res.domain}{C.X}")
    print(f"  {C.DIM}{'─' * 58}{C.X}")

    # ---- DOMAIN REGISTRATION ----
    reg = res.registration
    if reg and not reg.get("error"):
        _section("DOMAIN REGISTRATION")
        if reg.get("registrar"):
            iana = f"  (IANA {reg['registrar_ianaid']})" if reg.get("registrar_ianaid") else ""
            _row("Registrar", f"{reg['registrar']}{iana}")
        if reg.get("created") or reg.get("expires"):
            _row("Registered", f"{reg.get('created','?')} → {reg.get('expires','?')} | "
                               f"DNSSEC {'on' if reg.get('dnssec') else 'off'}")
        if reg.get("abuse_email"):
            _row("Abuse contact", reg["abuse_email"])
        status = reg.get("contact_status")
        if status == "leaked":
            _row("WHOIS privacy", f"{C.R}LEAKED → {'; '.join(reg.get('leaks', []))}{C.X}")
        elif status == "protected":
            _row("WHOIS privacy", f"{C.G}privacy-protected / redacted{C.X}")
        else:
            _row("WHOIS privacy", f"{C.DIM}contact details not published{C.X}")
    elif reg.get("error"):
        _section("DOMAIN REGISTRATION")
        err = str(reg.get("error", ""))
        # Only "not registered" when the registry has no object AND the domain is not
        # delegated; a ccTLD without RDAP that still has nameservers is registered.
        if "404" in err and not res.ns:
            _row("Status", f"{C.Y}domain appears NOT registered "
                           f"(no registration record and no nameservers){C.X}")
        elif res.ns:
            _row("Status", f"{C.DIM}registered (registration data not published "
                           f"over RDAP for this TLD){C.X}")
        else:
            _row("Status", f"{C.DIM}registration data unavailable ({err}){C.X}")

    # ---- HOSTING ----
    web, mail = _host_str(res.hosting.get("web", {})), _host_str(res.hosting.get("mail", {}))
    _section("HOSTING")
    _row("Website", f"https://{res.domain}")
    if web:
        _row("Web server", web)
    if mail:
        _row("Mail server", mail)

    # ---- IDENTITY ---- (only for a real, confirmed Entra/M365 tenant)
    ci = res.identity
    if ci and ci.get("tenant_present") and ci.get("tenant_id"):
        _section("IDENTITY")
        plat = "Entra ID"
        if ci.get("cloud"):
            plat += f" - {ci['cloud']}"
        _row("Platform", plat)
        if ci.get("tenant_id"):
            _row("Tenant ID", ci["tenant_id"])
        if ci.get("onmicrosoft"):
            _row("Default domain", ci["onmicrosoft"])
        if ci.get("brand"):
            _row("Tenant brand", ci["brand"])
        if ci.get("namespace_type"):
            auth = ci["namespace_type"]
            if ci.get("federation_auth_url"):
                auth += f" → {ci['federation_auth_url']}"
            _row("Authentication", auth)
        doms = ci.get("tenant_domains") or []
        if doms:
            _row("Tenant domains", ", ".join(doms))

    # ---- MAIL ----
    _section("MAIL")
    tail = (f"   ({_color_conf(res.mailbox_conf)} confidence)"
            if res.mailbox_src == "signature" else "")
    _row("Mailbox host", f"{C.BOLD}{res.mailbox or 'Unknown / self-hosted'}{C.X}{tail}")
    if res.gateway:
        _row("Inbound path", f"{C.Y}via {res.gateway} (security gateway){C.X}")
    elif res.mx:
        _row("Inbound path", "direct (no gateway)")
    if res.mx:
        _row("MX records", ", ".join(res.mx))
    if res.senders or res.sender_raw:
        slist = res.senders + res.sender_raw
        _row("Auth. senders", ", ".join(slist) if slist else "(none mapped)")
    if res.spoof and res.mailbox_src != "none":
        sp = res.spoof
        v = sp.get("verdict", "")
        vc = C.R if v == "SPOOFABLE" else C.G if v == "hardened" else C.Y
        detail = (f"{C.DIM}[SPF {sp.get('spf')} · DMARC {sp.get('dmarc')} · "
                  f"DKIM {'yes' if sp.get('dkim') else 'no'}]{C.X}")
        why = f"  {C.DIM}({'; '.join(sp['reasons'])}){C.X}" if sp.get("reasons") else ""
        _row("Spoofing risk", f"{vc}{v}{C.X}  {detail}{why}")

    # ---- SERVICES (passive · Shodan InternetDB) ----
    svc_rows = {ip: _service_table(s) for ip, s in res.services.items()}
    svc_rows = {ip: t for ip, t in svc_rows.items() if t or res.services[ip].get("vulns")}
    if svc_rows:
        _section("SERVICES")
        print(f"  {C.DIM}(passive — Shodan InternetDB; nothing sent to the target){C.X}")
        for ip, table in svc_rows.items():
            _row(ip, "")
            if table:
                print(f"  {'':<{_LW}}{C.DIM}{'PORT':<7}{'SERVICE':<13}SOFTWARE{C.X}")
                for port, svc, sw in table:
                    print(f"  {'':<{_LW}}{str(port):<7}{svc:<13}{sw}")
            vulns = res.services[ip].get("vulns") or []
            if vulns:
                print(f"  {'':<{_LW}}{C.R}CVEs: {', '.join(vulns[:12])}{C.X}"
                      + (f"  (+{len(vulns)-12} more)" if len(vulns) > 12 else ""))

    # ---- TECHNOLOGY STACK ---- (DNS / CDN / security / SaaS; web stack moves to WEBSITE)
    cats: dict[str, list[str]] = {}
    for name, cat in res.tech.items():
        cats.setdefault(cat, []).append(name)
    tech_rows = [(label, cats[cat]) for cat, label in
                 (("dns", "DNS"), ("cdn", "CDN/WAF"), ("security", "Security"),
                  ("saas", "SaaS / apps")) if cats.get(cat)]
    if tech_rows:
        _section("TECHNOLOGY STACK")
        for label, items in tech_rows:
            _row(label, " | ".join(sorted(items)))

    # ---- WEBSITE ----
    if res.website:
        _section("WEBSITE")
        web_stack = sorted(cats.get("web", []))
        for i, w in enumerate(res.website):
            if i:
                print()                       # blank line between pages
            if w.get("error"):
                _row("URL", f"{w.get('url','?')}  {C.DIM}(unreachable: {w['error']}){C.X}")
                continue
            _row("URL", f"{w['url']}  ({w.get('status','?')})"
                        + (f"  {C.DIM}[{len(w['redirects'])} redirect(s)]{C.X}"
                           if w.get("redirects") else ""))
            if w.get("title"):
                _row("Title", w["title"])
            if w.get("description"):
                _row("Activity", w["description"])
            if w.get("first_seen"):
                _row("First seen", f"{w['first_seen']}  {C.DIM}(Wayback){C.X}")
            if w.get("server"):
                srv = w["server"][:1].upper() + w["server"][1:]
                if w.get("powered_by"):
                    pb = w["powered_by"]
                    srv += f" | {pb[:1].upper() + pb[1:]}"
                _row("Server", srv)
            if i == 0 and web_stack:
                _row("Web stack", " | ".join(web_stack))
            if w.get("cdn_waf"):
                _row("CDN / WAF", " | ".join(w["cdn_waf"]))
            if w.get("careers_url"):
                ats = f"  {C.DIM}(ATS: {w['ats']}){C.X}" if w.get("ats") else ""
                _row("Careers / jobs", f"{w['careers_url']}{ats}")
            if w.get("cert"):
                ct_ = w["cert"]
                days, iso = _cert_status(ct_.get("not_after", ""))
                if days is None:
                    status = ""
                elif days < 0:
                    status = f"  {C.R}EXPIRED {abs(days)}d ago{C.X}"
                elif days < 30:
                    status = f"  {C.Y}expires in {days}d{C.X}"
                else:
                    status = f"  {C.DIM}valid, {days}d left{C.X}"
                _row("TLS cert", f"{ct_.get('issuer','?')} | expires {iso}{status}")
                if ct_.get("sans"):
                    extra = (f"  {C.DIM}(+{len(ct_['sans'])-3} more){C.X}"
                             if len(ct_["sans"]) > 3 else "")
                    _row("Cert SANs", ", ".join(ct_["sans"][:3]) + extra)
            if w.get("robots"):
                _row("Robots.txt", w["robots"])
            if w.get("sitemap"):
                _row("Sitemap.xml", w["sitemap"])
            if w.get("git_exposed"):
                _row("Git exposure", f"{C.R}/.git/ is exposed!{C.X}")
            if w.get("buckets"):
                _rows("Cloud buckets", [f"{C.R if 'public' in b else C.Y}{b}{C.X}"
                                        for b in w["buckets"]])
            if w.get("sourcemaps"):
                _rows("Source maps", [f"{C.R}{m}{C.X}" for m in w["sourcemaps"]])
            if w.get("favicon"):
                _row("Favicon", w["favicon"])
            sh = w.get("security_headers") or {}
            if sh.get("present") or sh.get("missing"):
                present = set(sh.get("present", []))
                sec_items = [
                    f"{lbl:<24}" + (f"{C.G}✓ present{C.X}" if lbl in present
                                    else f"{C.R}✗ missing{C.X}")
                    for _hk, lbl in _SEC_HEADERS]
                _rows("Security", sec_items)

    # ---- SOCIAL MEDIA & profiles ---- (only links actually found on the site)
    social = res.website[0].get("social") if res.website else None
    if social:
        _section("SOCIAL MEDIA")
        for platform, url in social.items():
            _row(platform, url)

    # ---- SUBDOMAINS (probed + Certificate Transparency) ----
    disc = res.discovery
    if disc.get("hosts") or res.subdomains or disc.get("wildcard"):
        _section("SUBDOMAINS")
        if disc.get("wildcard"):
            _row("Wildcard DNS", f"{C.Y}* → {disc['wildcard']} (common names filtered; "
                                 f"only distinct-IP hosts shown){C.X}")
        hosts = sorted(disc.get("hosts") or [], key=lambda h: h["host"])
        for h in hosts:
            flag = f" {C.Y}[VPN/portal]{C.X}" if h.get("vpn") else ""
            tech = (f"  {C.DIM}→ {', '.join(h['tech'])}{C.X}" if h.get("tech") else "")
            print(f"  {'':<16}{h['host']:<40} {C.DIM}{h.get('ip',''):<16}{C.X}"
                  f"{flag}{tech}")
        if not hosts and res.subdomains:        # CT-only (no --subs): list names
            _row("Subdomains", f"{len(res.subdomains)} from CT")
            _row("", ", ".join(res.subdomains))
        if disc.get("vpn_portals"):
            _row("VPN / portals", " | ".join(disc["vpn_portals"]))
        web_pages = res.website or []
        web_cdn = web_pages[0].get("cdn_waf") if web_pages else None
        if web_cdn and hosts:
            web_ip = (res.hosting.get("web") or {}).get("ip")
            origins = sorted({h["ip"] for h in hosts
                              if h.get("ip") and h["ip"] != web_ip
                              and not _is_cdn_ip(h["ip"])})
            if origins:
                print()
                _row("Possible origin", f"{C.Y}{', '.join(origins[:6])}{C.X}  "
                                        f"{C.DIM}(real IP leaked via subdomain){C.X}")

    # ---- PEOPLE & EMAIL OSINT ----
    pp = res.people
    if pp and (pp.get("emails") or pp.get("company_linkedin") or pp.get("leads")):
        _section("PEOPLE & EMAIL OSINT")
        if pp.get("email_format"):
            _row("Email format", pp["email_format"])
        if pp.get("emails"):
            _rows("Emails (site)", pp["emails"])
        if pp.get("names"):
            _rows("Names (site)", pp["names"])
        # LinkedIn only if the company profile was actually found
        if pp.get("company_linkedin"):
            _row("LinkedIn", pp["company_linkedin"])
            emps = pp.get("employees") or []
            if emps:
                _row("Employees", f"{len(emps)} found via LinkedIn")
                for e in emps:
                    line = e["name"]
                    if e.get("position"):
                        line += f"  — {e['position']}"
                    if e.get("email"):
                        line += f"  {C.DIM}→ {e['email']}{C.X}"
                    print(f"  {'':<16}{line}")
        if pp.get("leads"):
            print(f"  {C.DIM}Google dorks:{C.X}")
            for lbl, url in pp["leads"]:
                print(f"    {lbl:<26}{url}")

    # ---- EVIDENCE ---- (--full only)
    if full:
        shown = sorted(res.scores, key=res.scores.get, reverse=True)
        if shown:
            _section("EVIDENCE")
            primary = {res.mailbox, res.gateway}
            for p in shown:
                if p not in primary:
                    print(f"  {C.DIM}· {p} (score {res.scores[p]}){C.X}")
                for line in res.evidence.get(p, []):
                    print(f"    {C.DIM}{line}{C.X}")


# Eye of Horus (Udjat), trimmed of blank margins to keep it compact.
_EYE = """\
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
"""


def print_banner() -> None:
    """Banner shown on each run (suppressed with --json)."""
    print()
    for line in _EYE.rstrip("\n").split("\n"):
        print(f"      {C.C_}{line}{C.X}")
    print(f"\n      {C.C_}{C.BOLD}G H O S T E Y E{C.X}\n")
    print(f"   {C.DIM}The all-seeing eye for external recon — map a domain's mail, "
          f"identity,{C.X}")
    print(f"   {C.DIM}hosting, web stack, and exposure from public sources.{C.X}")
    print(f"   {C.B}author: {C.X}{C.BOLD}black3dm0nd{C.X}")
    print(f"   {C.B}website:{C.X} {C.BOLD}https://black3dm0nd.com{C.X}")
    print(f"   {C.B}github: {C.X}{C.BOLD}https://github.com/black3dm0nd{C.X}\n")


def print_summary(results: list[DomainResult]) -> None:
    """End-of-run roll-up: provider breakdown and key exposure counts."""
    from collections import Counter
    ok = [r for r in results if not r.error]
    errs = len(results) - len(ok)
    if not ok:
        print(f"{C.BOLD}summary{C.X}: {errs} domain(s), all errored")
        return
    mb = Counter(r.mailbox or "Unknown / self-hosted" for r in ok)
    gateways = Counter(r.gateway for r in ok if r.gateway)
    spoofable = sum(1 for r in ok if r.spoof.get("spoofable"))
    leaked = sum(1 for r in ok if r.registration.get("contact_status") == "leaked")
    tenants = sum(1 for r in ok if r.identity.get("tenant_present"))
    clouds = Counter(
        h["cloud"] for r in ok for h in (r.hosting.get("web"), r.hosting.get("mail"))
        if h and h.get("cloud"))

    print(f"{C.BOLD}{C.C_}{'='*60}{C.X}")
    print(f"{C.BOLD}SUMMARY{C.X}  ({len(ok)} domain(s)"
          + (f", {errs} errored" if errs else "") + ")")
    print(f"{C.BOLD}mailbox hosts:{C.X}")
    for prov, n in mb.most_common():
        print(f"  {n:>4}  {prov}")
    if gateways:
        print(f"{C.BOLD}inbound gateways:{C.X}")
        for gw, n in gateways.most_common():
            print(f"  {n:>4}  {gw}")
    if clouds:
        print(f"{C.BOLD}hosting clouds:{C.X}")
        for cl, n in clouds.most_common():
            print(f"  {n:>4}  {cl}")
    print(f"{C.BOLD}exposure:{C.X}")
    print(f"  {C.R if spoofable else C.G}{spoofable:>4}{C.X}  spoofable (weak SPF/DMARC)")
    print(f"  {C.R if leaked else C.G}{leaked:>4}{C.X}  whois contact leaked")
    print(f"  {tenants:>4}  with an Entra ID tenant")


_HTML_CSS = """
:root{--bg:#0d1117;--card:#161b22;--line:#30363d;--fg:#e6edf3;--dim:#8b949e;
--cyan:#39c5cf;--green:#3fb950;--red:#f85149;--yellow:#d29922;--accent:#58a6ff}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:14px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}
.wrap{max-width:1100px;margin:0 auto;padding:28px 18px 60px}
h1{font-size:26px;margin:0 0 2px;color:var(--cyan);letter-spacing:.5px}
.sub{color:var(--dim);margin:0 0 22px}
h2{font-size:13px;letter-spacing:1px;text-transform:uppercase;color:var(--accent);
margin:20px 0 8px;border-bottom:1px solid var(--line);padding-bottom:4px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;
padding:18px 20px;margin:18px 0}
.card h3{margin:0 0 12px;font-size:18px;color:var(--cyan)}
table{border-collapse:collapse;width:100%;margin:0 0 6px}
td,th{text-align:left;padding:5px 10px;vertical-align:top;border-bottom:1px solid var(--line)}
th{color:var(--dim);font-weight:600;white-space:nowrap;width:160px}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:13px}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
.b{display:inline-block;padding:1px 8px;border-radius:12px;font-size:12px;font-weight:600}
.red{background:rgba(248,81,73,.15);color:var(--red)}
.green{background:rgba(63,185,80,.15);color:var(--green)}
.yellow{background:rgba(210,153,34,.15);color:var(--yellow)}
.dim{color:var(--dim)}.tag{color:var(--dim);font-size:12px}
.sumtab td,.sumtab th{white-space:nowrap}.sumtab th{width:auto}
.subtab td{border-bottom:1px solid #21262d;padding:3px 10px}
"""


def _badge(verdict: str) -> str:
    cls = {"SPOOFABLE": "red", "hardened": "green", "LEAKED": "red",
           "partial": "yellow"}.get(verdict, "dim")
    return f'<span class="b {cls}">{html.escape(verdict)}</span>'


def write_html(results: list[DomainResult], path: str) -> None:
    """Render a styled, self-contained HTML report (summary table + per-domain cards)."""
    def e(x: Any) -> str:
        return html.escape(str(x))

    def kv(rows: list[tuple]) -> str:
        out = []
        for k, v in rows:
            if v in (None, "", [], {}):
                continue
            out.append(f"<tr><th>{e(k)}</th><td>{v}</td></tr>")
        return "<table>" + "".join(out) + "</table>" if out else ""

    # ---- summary table ----
    srows = []
    for r in results:
        if r.error:
            srows.append(f"<tr><td class=mono>{e(r.domain)}</td>"
                         f"<td colspan=5 class=red>{e(r.error)}</td></tr>")
            continue
        sp = r.spoof.get("verdict", "")
        wc = (r.hosting.get("web") or {}).get("cloud") or \
             (r.hosting.get("web") or {}).get("ip", "")
        leaked = r.registration.get("contact_status") == "leaked"
        srows.append(
            f"<tr><td class=mono><a href='#{e(r.domain)}'>{e(r.domain)}</a></td>"
            f"<td>{e(r.mailbox)}</td><td>{e(r.gateway or '—')}</td>"
            f"<td>{e(wc or '—')}</td><td>{_badge(sp) if sp else '—'}</td>"
            f"<td>{'<span class=\"b red\">yes</span>' if leaked else '—'}</td></tr>")
    summary = (
        "<h2>Summary</h2><table class=sumtab><tr><th>Domain</th><th>Mailbox</th>"
        "<th>Gateway</th><th>Hosting</th><th>Spoofing</th><th>WHOIS leak</th></tr>"
        + "".join(srows) + "</table>") if len(results) > 1 else ""

    # ---- per-domain cards ----
    cards = []
    for r in results:
        if r.error:
            continue
        secs = []
        # MAIL
        mail = [("Mailbox host", e(r.mailbox)),
                ("Inbound", "via %s (gateway)" % e(r.gateway) if r.gateway else
                 ("direct" if r.mx else "")),
                ("MX", ", ".join(e(m) for m in r.mx)),
                ("Senders", ", ".join(e(s) for s in r.senders + r.sender_raw))]
        if r.spoof and r.mailbox_src != "none":
            sp = r.spoof
            mail.append(("Spoofing", f"{_badge(sp.get('verdict',''))} "
                         f"<span class=tag>SPF {e(sp.get('spf'))} · DMARC "
                         f"{e(sp.get('dmarc'))} · DKIM {'yes' if sp.get('dkim') else 'no'}"
                         "</span>"))
        secs.append(("Mail", kv(mail)))
        # IDENTITY
        ci = r.identity
        if ci.get("tenant_present") and ci.get("tenant_id"):
            auth = e(ci.get("namespace_type", ""))
            if ci.get("federation_auth_url"):
                auth += f" → <span class=mono>{e(ci['federation_auth_url'])}</span>"
            secs.append(("Identity", kv([
                ("Platform", "Entra ID - " + e(ci.get("cloud", ""))),
                ("Tenant ID", f"<span class=mono>{e(ci.get('tenant_id'))}</span>"),
                ("Default domain", e(ci.get("onmicrosoft", ""))),
                ("Brand", e(ci.get("brand", ""))), ("Auth", auth),
                ("Tenant domains", ", ".join(e(d) for d in ci.get("tenant_domains", [])))])))
        # HOSTING
        host = [("Website", f"<a href='https://{e(r.domain)}'>https://{e(r.domain)}</a>")]
        for lbl, key in (("Web server", "web"), ("Mail server", "mail")):
            h = r.hosting.get(key) or {}
            if h:
                host.append((lbl, f"<span class=mono>{e(h.get('ip',''))}</span> · "
                             f"{e((h.get('as_name') or '').split(' - ')[-1] or h.get('asn',''))} "
                             f"· {e(h.get('cc','').upper())}"))
        secs.append(("Hosting", kv(host)))
        # SERVICES (Shodan InternetDB) — port/service/software table per IP
        if r.services:
            sv = []
            for ip, s in r.services.items():
                table = _service_table(s)
                if not table and not s.get("vulns"):
                    continue
                rows = "".join(
                    f"<tr><td class=mono>{p}</td><td>{e(svc)}</td>"
                    f"<td>{e(sw)}</td></tr>" for p, svc, sw in table)
                val = (f"<table class=subtab><tr><th>Port</th><th>Service</th>"
                       f"<th>Software</th></tr>{rows}</table>") if rows else ""
                if s.get("vulns"):
                    val += (f"<span class='b red'>CVEs</span> <span class=mono>"
                            f"{e(', '.join(s['vulns'][:30]))}</span>")
                sv.append((ip, val))
            if sv:
                secs.append(("Services", kv(sv)))
        # TECHNOLOGY
        cats: dict[str, list[str]] = {}
        for name, cat in r.tech.items():
            cats.setdefault(cat, []).append(name)
        techrows = [(lbl, ", ".join(e(x) for x in sorted(cats[c])))
                    for c, lbl in (("dns", "DNS"), ("cdn", "CDN/WAF"),
                                   ("web", "Web stack"), ("security", "Security"),
                                   ("saas", "SaaS / apps")) if cats.get(c)]
        if techrows:
            secs.append(("Technology", kv(techrows)))
        # WEBSITE
        if r.website and not r.website[0].get("error"):
            w = r.website[0]
            wr = [("URL", f"<a href='{e(w.get('url'))}'>{e(w.get('url'))}</a> "
                   f"<span class=tag>({e(w.get('status'))})</span>"),
                  ("Title", e(w.get("title", ""))),
                  ("Activity", e(w.get("description", ""))),
                  ("First seen", e(w.get("first_seen", ""))),
                  ("Server", e(w.get("server", ""))),
                  ("Careers", f"<a href='{e(w.get('careers_url'))}'>{e(w.get('careers_url'))}"
                   f"</a>" if w.get("careers_url") else "")]
            if w.get("cert"):
                days, iso = _cert_status(w["cert"].get("not_after", ""))
                wr.append(("TLS cert", f"{e(w['cert'].get('issuer'))} · expires {e(iso)}"))
            if w.get("robots"):
                wr.append(("robots.txt", f"<a href='{e(w['robots'])}'>{e(w['robots'])}</a>"))
            if w.get("git_exposed"):
                wr.append(("Git", '<span class="b red">/.git/ exposed</span>'))
            if w.get("buckets"):
                wr.append(("Cloud buckets", "<br>".join(e(b) for b in w["buckets"])))
            if w.get("sourcemaps"):
                wr.append(("Source maps", "<br>".join(
                    f'<span class="b red">{e(m)}</span>' for m in w["sourcemaps"])))
            secs.append(("Website", kv(wr)))
        # SOCIAL
        soc = (r.website[0].get("social") if r.website else None) or {}
        if soc:
            secs.append(("Social media", kv(
                [(p, f"<a href='{e(u)}'>{e(u)}</a>") for p, u in soc.items()])))
        # SUBDOMAINS
        hosts = sorted(r.discovery.get("hosts") or [], key=lambda h: h["host"])
        if hosts:
            trs = "".join(
                f"<tr><td class=mono>{e(h['host'])}</td><td class=mono>{e(h.get('ip',''))}</td>"
                f"<td>{'<span class=\"b yellow\">VPN/portal</span>' if h.get('vpn') else ''}"
                f" {e(', '.join(h.get('tech', [])))}</td></tr>" for h in hosts)
            secs.append(("Subdomains (%d)" % len(hosts),
                         f"<table class=subtab><tr><th>Host</th><th>IP</th>"
                         f"<th>Notes</th></tr>{trs}</table>"))
        # REGISTRATION
        reg = r.registration
        if reg and not reg.get("error"):
            rr = [("Registrar", e(reg.get("registrar", ""))),
                  ("Created", e(reg.get("created", ""))),
                  ("Expires", e(reg.get("expires", ""))),
                  ("DNSSEC", "on" if reg.get("dnssec") else "off"),
                  ("Abuse", e(reg.get("abuse_email", "")))]
            cs = reg.get("contact_status")
            if cs == "leaked":
                rr.append(("WHOIS", f'<span class="b red">LEAKED</span> '
                           + e("; ".join(reg.get("leaks", [])))))
            secs.append(("Registration", kv(rr)))
        # PEOPLE
        pp = r.people
        if pp:
            pr = [("Email format", e(pp.get("email_format", ""))),
                  ("Emails", ", ".join(e(x) for x in pp.get("emails", [])))]
            if pp.get("company_linkedin"):
                pr.append(("LinkedIn", f"<a href='{e(pp['company_linkedin'])}'>"
                           f"{e(pp['company_linkedin'])}</a>"))
            for e_ in pp.get("employees", [])[:30]:
                pr.append((e(e_["name"]), e(e_.get("position", ""))
                           + (f" · {e(e_['email'])}" if e_.get("email") else "")))
            for lbl, url in pp.get("leads", []):
                pr.append((lbl, f"<a href='{e(url)}'>search</a>"))
            secs.append(("People & OSINT", kv(pr)))

        order = ["Registration", "Hosting", "Identity", "Mail", "Services",
                 "Technology", "Website", "Social", "Subdomains", "People"]
        secs.sort(key=lambda s: next(
            (i for i, o in enumerate(order) if s[0].startswith(o)), 99))
        body = "".join(f"<h2>{t}</h2>{tbl}" for t, tbl in secs if tbl)
        cards.append(f"<div class=card id='{e(r.domain)}'><h3>{e(r.domain)}</h3>{body}</div>")

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    doc = (f"<!doctype html><html><head><meta charset=utf-8>"
           f"<meta name=viewport content='width=device-width,initial-scale=1'>"
           f"<title>GhostEye report — {e(results[0].domain if results else '')}</title>"
           f"<style>{_HTML_CSS}</style></head><body><div class=wrap>"
           f"<h1>GHOSTEYE — external recon report</h1>"
           f"<p class=sub>{len(results)} domain(s) · generated {ts} · "
           f"<a href='https://black3dm0nd.com'>black3dm0nd</a></p>"
           f"{summary}{''.join(cards)}</div></body></html>")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(doc)


_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def write_csv(results: list[DomainResult], path: str) -> None:
    """One summary row per domain."""
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["domain", "mailbox", "gateway", "web_ip", "web_cloud", "mail_ip",
                    "spoofing", "tenant_id", "registrar", "created", "expires",
                    "whois", "subdomains", "emails", "error"])
        for r in results:
            if r.error:
                w.writerow([r.domain] + [""] * 13 + [r.error])
                continue
            web, mail = r.hosting.get("web") or {}, r.hosting.get("mail") or {}
            w.writerow([
                r.domain, r.mailbox, r.gateway, web.get("ip", ""), web.get("cloud", ""),
                mail.get("ip", ""), r.spoof.get("verdict", ""),
                r.identity.get("tenant_id", ""), r.registration.get("registrar", ""),
                r.registration.get("created", ""), r.registration.get("expires", ""),
                r.registration.get("contact_status", ""),
                len(r.discovery.get("hosts") or []),
                " ".join((r.people or {}).get("emails", [])), ""])


def write_txt(results: list[DomainResult], path: str) -> None:
    """Plain-text version of the formatted report (ANSI stripped)."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        for r in results:
            print_human(r, full=True)
        if len(results) > 1:
            print()
            print_summary(results)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(_ANSI_RE.sub("", buf.getvalue()))


def write_output(results: list[DomainResult], path: str) -> str:
    """Dispatch on file extension; returns a short label of the format written."""
    ext = path.lower().rsplit(".", 1)[-1] if "." in path else ""
    if ext in ("html", "htm"):
        write_html(results, path)
        return "HTML report"
    if ext == "csv":
        write_csv(results, path)
        return "CSV summary"
    if ext == "json":
        with open(path, "w", encoding="utf-8") as fh:
            json.dump([r.to_dict() for r in results], fh, indent=2)
        return "JSON"
    write_txt(results, path)
    return "text report"



def main() -> None:
    ap = argparse.ArgumentParser(
        description="GhostEye — external reconnaissance of a domain's mail, identity, "
                    "hosting, web stack and exposure, from public sources.")
    ap.add_argument("domain", nargs="*",
                    help="Target domain(s) to assess, e.g. example.com.")
    ap.add_argument("-f", "--file",
                    help="Read target domains from a file (one per line; '#' comments ok).")
    ap.add_argument("-c", "--concurrency", type=int, default=15,
                    help="How many domains to assess in parallel (default 15).")
    ap.add_argument("--resolver", default="cloudflare,google",
                    help="DNS-over-HTTPS resolvers to query, comma-separated "
                         "(default: cloudflare,google; quad9 also available).")
    ap.add_argument("--timeout", type=float, default=8.0,
                    help="Per-request network timeout in seconds (default 8).")
    ap.add_argument("--proxy",
                    help="Send all traffic through this HTTP or SOCKS proxy "
                         "(e.g. socks5://127.0.0.1:9050).")
    ap.add_argument("-o", "--output", metavar="FILE",
                    help="Write results to a file; format chosen by extension — "
                         ".html, .csv, .json or .txt.")

    ag = ap.add_argument_group("active checks (connect to the target / third parties)")
    ag.add_argument("-w", "--web", action="store_true",
                    help="Fetch the website and fingerprint it — technologies & versions, "
                         "server/HTTP headers, TLS certificate, robots.txt & sitemap.xml, "
                         "exposed /.git, first-seen (Wayback), favicon, social links.")
    ag.add_argument("-s", "--subs", action="store_true",
                    help="Find live subdomains, fingerprint each one's technologies, and "
                         "reveal the real origin IP behind a CDN/WAF.")
    ag.add_argument("-C", "--ct", action="store_true",
                    help="Add subdomains from Certificate Transparency logs (crt.sh).")
    ag.add_argument("-O", "--osint", action="store_true",
                    help="People & email OSINT — scrape employee emails/names from the "
                         "site, infer the email format, find the company on LinkedIn, and "
                         "build Google dorks for documents and sensitive files.")
    ag.add_argument("-a", "--all", action="store_true", dest="all_checks",
                    help="Enable every active check (-w -s -C -O) and show the evidence.")
    args = ap.parse_args()

    print_banner()

    domains: list[str] = []
    for d in args.domain:
        d = d.strip().lower()
        if d:
            domains.append(d)
    if args.file:
        with open(args.file, encoding="utf-8") as fh:
            for line in fh:
                line = line.split("#", 1)[0].strip().lower()
                if line:
                    domains.append(line)
    # dedupe, keep order
    domains = list(dict.fromkeys(domains))
    if not domains:
        ap.error("provide a domain or --file")

    resolvers = [r.strip() for r in args.resolver.split(",") if r.strip() in RESOLVERS]
    if not resolvers:
        ap.error(f"no valid resolvers; choose from {', '.join(RESOLVERS)}")

    # Stream the formatted report as each domain completes. --full also runs every
    # active module and prints the EVIDENCE block.
    cb = lambda r: print_human(r, args.all_checks)
    results = asyncio.run(run(domains, resolvers, False,
                              args.concurrency, args.timeout,
                              rdap=True, ct=args.ct or args.all_checks,
                              hosting=True, deep=False,
                              web=args.web or args.all_checks,
                              subs=args.subs or args.all_checks,
                              people=args.osint or args.all_checks,
                              proxy=args.proxy, on_done=cb))
    print()
    if len(results) > 1:
        print_summary(results)
    if args.output:
        kind = write_output(results, args.output)
        print(f"{C.G}{kind} written to {args.output}{C.X}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
