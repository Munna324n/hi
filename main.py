import os
import re
import ssl
import socket
import json
import time
import io
import threading
import urllib.request
import urllib.parse
import html
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

import telebot
from telebot import types
from flask import Flask, jsonify

try:
    import dns.resolver
except ImportError:
    dns = None

# ============================================================
# Website Info Hunter Pro
#
# Deployment pattern:
# Flask -> background Thread -> bot.infinity_polling()
# This follows the same working pattern as the supplied
# Premium Service Bot project.
#
# Admin:
#   One fixed ADMIN_ID only.
#   Telegram group-admin status does NOT grant bot-admin access.
#
# Deep Scan:
#   Adds public WHOIS/RDAP, public DNS intelligence,
#   certificate/hosting clues and selected TCP ports.
#   It does NOT bypass registrar privacy controls.
# ============================================================

BOT_NAME = "Website Info Hunter Pro"
BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
ADMIN_ID = int(os.getenv("ADMIN_ID", "0"))
PORT = int(os.getenv("PORT", "8080"))

if not BOT_TOKEN:
    raise RuntimeError("BOT_TOKEN environment variable is missing.")
if not ADMIN_ID:
    raise RuntimeError("ADMIN_ID environment variable is missing.")

bot = telebot.TeleBot(BOT_TOKEN)
app = Flask("")

AUTHORIZED_GROUPS = set()
SCAN_MODE = {}
LAST_SCAN = {}
SCAN_COOLDOWN = 10

# Runtime-only user/activity tracking. No database is used; data resets on restart.
USERS = {}
ACTIVE_SCANS = {}
BROADCAST_WAITING = set()
ACTIVITY_LOCK = threading.Lock()

# Public WHOIS server map based on the original desktop version.
WHOIS_SERVERS = {
    "com": "whois.verisign-grs.com",
    "net": "whois.verisign-grs.com",
    "org": "whois.pir.org",
    "info": "whois.afilias.net",
    "biz": "whois.neulevel.biz",
    "us": "whois.nic.us",
    "uk": "whois.nic.uk",
    "ca": "whois.cira.ca",
    "de": "whois.denic.de",
    "fr": "whois.nic.fr",
    "au": "whois.auda.org.au",
    "ru": "whois.tcinet.ru",
    "jp": "whois.jprs.jp",
    "cn": "whois.cnnic.cn",
    "br": "whois.registro.br",
    "in": "whois.registry.in",
    "io": "whois.nic.io",
    "co": "whois.nic.co",
    "me": "whois.nic.me",
    "tv": "whois.nic.tv",
    "cc": "whois.nic.cc",
    "xyz": "whois.nic.xyz",
    "online": "whois.nic.online",
    "site": "whois.nic.site",
    "top": "whois.nic.top",
    "club": "whois.nic.club",
    "shop": "whois.nic.shop",
    "blog": "whois.nic.blog",
    "app": "whois.nic.google",
    "dev": "whois.nic.google",
}

HOSTING_PROVIDERS = {
    "amazonaws.com": "Amazon AWS",
    "googleusercontent.com": "Google Cloud",
    "azure.com": "Microsoft Azure",
    "digitalocean.com": "DigitalOcean",
    "linode.com": "Linode",
    "godaddy.com": "GoDaddy",
    "secureserver.net": "GoDaddy",
    "hostgator.com": "HostGator",
    "websitewelcome.com": "HostGator",
    "bluehost.com": "Bluehost",
    "unifiedlayer.com": "Bluehost",
    "siteground.com": "SiteGround",
    "dreamhost.com": "DreamHost",
    "a2hosting.com": "A2 Hosting",
    "inmotionhosting.com": "InMotion Hosting",
    "wpengine.com": "WP Engine",
    "kinsta.com": "Kinsta",
    "cloudflare.com": "Cloudflare",
    "akamai.com": "Akamai",
    "ovh.com": "OVH",
    "hetzner.com": "Hetzner",
    "vultr.com": "Vultr",
    "choopa.com": "Vultr",
    "namecheaphosting.com": "Namecheap",
    "hostinger.com": "Hostinger",
    "ipage.com": "iPage",
    "liquidweb.com": "Liquid Web",
    "rackspace.com": "Rackspace",
    "alibabacloud.com": "Alibaba Cloud",
    "oraclecloud.com": "Oracle Cloud",
    "softlayer.com": "IBM Cloud",
    "fastly.com": "Fastly",
    "stackpath.com": "StackPath",
    "bunnycdn.com": "BunnyCDN",
}

# -------------------- Render / keep alive --------------------

@app.route("/")
def home():
    return "Website Info Hunter Pro is Running Smoothly! 🚀"

@app.route("/health")
def health():
    return jsonify({
        "status": "ok",
        "bot": BOT_NAME,
        "time": datetime.utcnow().isoformat() + "Z",
        "authorized_groups": len(AUTHORIZED_GROUPS),
    })

def run():
    app.run(host="0.0.0.0", port=PORT, use_reloader=False)

def keep_alive():
    t = threading.Thread(target=run, daemon=True)
    t.start()

# -------------------- Permissions --------------------

def is_admin(message):
    return message.from_user.id == ADMIN_ID

def group_is_authorized(chat_id):
    return chat_id in AUTHORIZED_GROUPS

def group_allowed(message):
    return (
        message.chat.type not in ("group", "supergroup")
        or group_is_authorized(message.chat.id)
    )

def admin_only(message):
    if not is_admin(message):
        bot.reply_to(message, "⛔ Admin access denied.")
        return False
    return True

def track_user(message):
    """Track users only in RAM; no persistent database."""
    user = message.from_user
    if not user:
        return
    with ACTIVITY_LOCK:
        USERS[user.id] = {
            "id": user.id,
            "username": user.username or "",
            "name": (f"{user.first_name or ''} {user.last_name or ''}").strip(),
            "chat_id": message.chat.id,
            "last_seen": time.time(),
        }

def user_label(user_id):
    u = USERS.get(user_id, {})
    if u.get("username"):
        return f"@{u['username']}"
    return u.get("name") or f"ID {user_id}"

def notify_admin(text):
    try:
        bot.send_message(ADMIN_ID, text, disable_web_page_preview=True)
    except Exception as exc:
        print(f"Admin notification failed: {exc}")

# -------------------- Helpers --------------------

def normalize_domain(value):
    value = value.strip()
    value = re.sub(r"^https?://", "", value, flags=re.I)
    value = re.sub(r"^www\.", "", value, flags=re.I)
    value = value.split("/")[0].split("?")[0].split("#")[0]
    if ":" in value:
        value = value.split(":")[0]
    value = value.lower().rstrip(".")

    if not re.fullmatch(
        r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}",
        value,
    ):
        raise ValueError("Invalid domain. Example: example.com")
    return value

def http_get(url, timeout=6, headers=None):
    req = urllib.request.Request(
        url,
        headers=headers or {
            "User-Agent": "Mozilla/5.0 Website-Info-Hunter-Pro/2.0"
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return response.read().decode("utf-8", errors="replace")

def resolve_all_ips(domain):
    result = {"A": [], "AAAA": []}
    try:
        result["A"] = sorted({
            item[4][0]
            for item in socket.getaddrinfo(domain, None, socket.AF_INET)
        })
    except Exception:
        pass

    try:
        result["AAAA"] = sorted({
            item[4][0]
            for item in socket.getaddrinfo(domain, None, socket.AF_INET6)
        })
    except Exception:
        pass
    return result

def resolve_ip(domain):
    ips = resolve_all_ips(domain).get("A", [])
    return ips[0] if ips else None

# -------------------- DNS --------------------

def get_dns_info(domain):
    result = {
        "A": [],
        "AAAA": [],
        "MX": [],
        "NS": [],
        "TXT": [],
        "CNAME": [],
        "PTR": [],
        "SOA": [],
    }

    addresses = resolve_all_ips(domain)
    result["A"] = addresses["A"]
    result["AAAA"] = addresses["AAAA"]

    if dns is not None:
        for record in ("MX", "NS", "TXT", "CNAME", "SOA"):
            try:
                answers = dns.resolver.resolve(domain, record, lifetime=3)
                if record == "MX":
                    result[record] = [
                        str(x.exchange).rstrip(".") for x in answers
                    ]
                elif record == "SOA":
                    result[record] = [str(x) for x in answers]
                elif record == "TXT":
                    result[record] = [str(x).strip('"') for x in answers]
                else:
                    result[record] = [
                        str(x).rstrip(".") for x in answers
                    ]
            except Exception:
                pass

    for ip in result["A"]:
        try:
            ptr = socket.gethostbyaddr(ip)[0]
            result["PTR"].append(f"{ip} -> {ptr}")
        except Exception:
            pass

    return result

def dns_intelligence(domain):
    info = {"source": "dns_public"}

    if dns is None:
        return info

    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 3

        try:
            answers = resolver.resolve(domain, "SOA")
            for rdata in answers:
                info["soa_mname"] = str(rdata.mname).rstrip(".")
                # SOA RNAME is an encoded DNS mailbox, not proof of a person.
                info["soa_rname"] = str(rdata.rname).rstrip(".")
        except Exception:
            pass

        try:
            answers = resolver.resolve(domain, "TXT")
            txt_records = [str(x).strip('"') for x in answers]
            info["txt_records"] = txt_records[:30]
            info["has_google_verification"] = any(
                "google-site-verification" in x.lower()
                for x in txt_records
            )
            info["has_microsoft_verification"] = any(
                "ms=" in x.lower() for x in txt_records
            )
            info["has_spf"] = any("v=spf1" in x.lower() for x in txt_records)

            includes = []
            for txt in txt_records:
                includes.extend(re.findall(r"include:([^\s]+)", txt))
            if includes:
                info["spf_includes"] = sorted(set(includes))
        except Exception:
            pass

        try:
            answers = resolver.resolve(domain, "MX")
            mx = [str(x.exchange).rstrip(".") for x in answers]
            info["mx_records"] = mx

            providers = []
            for record in mx:
                low = record.lower()
                if "google" in low or "googlemail" in low:
                    providers.append("Google Workspace")
                elif "outlook" in low or "protection.outlook" in low:
                    providers.append("Microsoft 365")
                elif "zoho" in low:
                    providers.append("Zoho Mail")
                elif "hostinger" in low:
                    providers.append("Hostinger Mail")

            if providers:
                info["email_provider"] = sorted(set(providers))
        except Exception:
            pass

    except Exception as e:
        info["error"] = str(e)

    return info

# -------------------- HTTP / SSL / GEO --------------------

def get_headers(domain):
    for scheme in ("https", "http"):
        try:
            req = urllib.request.Request(
                f"{scheme}://{domain}/",
                method="HEAD",
                headers={
                    "User-Agent": "Mozilla/5.0 Website-Info-Hunter-Pro/2.0"
                },
            )
            with urllib.request.urlopen(req, timeout=6) as response:
                return {
                    "headers": dict(response.headers.items()),
                    "status": response.status,
                    "scheme": scheme,
                }
        except Exception:
            continue
    return {"headers": {}, "status": None, "scheme": None}

def get_geo(ip):
    if not ip:
        return {}

    try:
        url = (
            "http://ip-api.com/json/"
            + urllib.parse.quote(ip)
            + "?fields=status,country,countryCode,regionName,city,zip,"
              "lat,lon,timezone,isp,org,as,query"
        )
        data = json.loads(http_get(url, timeout=4))
        if data.get("status") == "success":
            return data
    except Exception:
        pass

    return {"query": ip}

def get_ssl(domain):
    result = {}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as raw:
            with ctx.wrap_socket(raw, server_hostname=domain) as conn:
                cert = conn.getpeercert()

                result["issuer"] = dict(
                    x[0] for x in cert.get("issuer", [])
                )
                result["subject"] = dict(
                    x[0] for x in cert.get("subject", [])
                )
                result["notBefore"] = cert.get("notBefore")
                result["notAfter"] = cert.get("notAfter")

                if cert.get("notAfter"):
                    try:
                        expiry = datetime.strptime(
                            cert["notAfter"],
                            "%b %d %H:%M:%S %Y %Z",
                        )
                        result["days_left"] = (
                            expiry - datetime.utcnow()
                        ).days
                    except Exception:
                        pass

                sans = [
                    value
                    for typ, value in cert.get("subjectAltName", [])
                    if typ == "DNS"
                ]
                result["SAN"] = sans[:50]
                result["total_domains_on_cert"] = len(sans)

    except Exception as e:
        result["error"] = str(e)

    return result

# -------------------- Ports --------------------

def scan_ports(domain):
    # Common TCP ports only. Use on systems you own/are authorized to test.
    ports = [80, 443, 21, 22, 25, 3306, 8080]
    ips = resolve_all_ips(domain).get("A", [])
    if not ips:
        return []

    ip = ips[0]
    service_map = {
        80: "HTTP",
        443: "HTTPS",
        21: "FTP",
        22: "SSH",
        25: "SMTP",
        3306: "MySQL",
        8080: "HTTP-Alt",
    }

    def check(port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.7)
        try:
            if sock.connect_ex((ip, port)) == 0:
                return (port, service_map.get(port, "Unknown"))
        except Exception:
            pass
        finally:
            sock.close()
        return None

    opened = []
    with ThreadPoolExecutor(max_workers=len(ports)) as executor:
        futures = [executor.submit(check, p) for p in ports]
        for future in futures:
            item = future.result()
            if item:
                opened.append(item)

    return sorted(opened)

# -------------------- Hosting / Technologies / Security --------------------

def detect_hosting(ip, headers, geo=None):
    try:
        hostname = socket.gethostbyaddr(ip)[0].lower() if ip else ""
    except Exception:
        hostname = ""

    header_text = " ".join(
        str(headers.get(k, ""))
        for k in ("Server", "Via", "X-Powered-By", "Platform")
    ).lower()

    geo_text = " ".join(
        str((geo or {}).get(k, ""))
        for k in ("isp", "org", "as")
    ).lower()

    combined = f"{hostname} {header_text} {geo_text}"

    for pattern, provider in HOSTING_PROVIDERS.items():
        if pattern in combined:
            return provider, hostname

    # Common provider clues not requiring a hostname match.
    if "hostinger" in combined:
        return "Hostinger", hostname
    if "hcdn" in combined or "hpanel" in combined:
        return "Hostinger / Hostinger CDN", hostname

    return "Unknown / Possibly Shared Hosting", hostname

def detect_technologies(headers, body=None):
    text = " ".join(
        f"{k}: {v}" for k, v in headers.items()
    ).lower()

    tech = []
    checks = [
        ("Cloudflare", "cloudflare"),
        ("Nginx", "nginx"),
        ("Apache", "apache"),
        ("LiteSpeed", "litespeed"),
        ("Microsoft IIS", "microsoft-iis"),
        ("PHP", "php"),
        ("ASP.NET", "asp.net"),
        ("WordPress", "wp-json"),
    ]

    for name, needle in checks:
        if needle in text:
            tech.append(name)

    if body:
        low = body.lower()
        if "wp-content/" in low or "/wp-includes/" in low:
            tech.append("WordPress")
        if "woocommerce" in low:
            tech.append("WooCommerce")
        if "laravel" in low:
            tech.append("Laravel")

    return list(dict.fromkeys(tech)) or ["Not detected"]

def security_analysis(headers):
    lower = {str(k).lower(): str(v) for k, v in headers.items()}

    checks = {
        "Strict-Transport-Security": "strict-transport-security" in lower,
        "Content-Security-Policy": "content-security-policy" in lower,
        "X-Frame-Options": "x-frame-options" in lower,
        "X-Content-Type-Options": "x-content-type-options" in lower,
        "Referrer-Policy": "referrer-policy" in lower,
    }

    score = sum(checks.values())
    return {
        "score": score,
        "total": len(checks),
        "checks": checks,
    }

# -------------------- Public WHOIS / RDAP --------------------

def whois_raw_query(domain, server, port=43):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(7)
    try:
        sock.connect((server, port))
        sock.sendall((domain + "\r\n").encode("utf-8"))

        chunks = []
        while True:
            try:
                data = sock.recv(4096)
            except socket.timeout:
                break
            if not data:
                break
            chunks.append(data)

        return b"".join(chunks).decode("utf-8", errors="ignore")
    finally:
        sock.close()

def parse_whois_response(response):
    info = {
        "source": "direct_whois",
        "has_privacy": False,
        "fields_found": 0,
    }

    patterns = {
        "registrar": [
            r"(?:Registrar|Sponsoring Registrar):\s*(.+)",
            r"Registrar Name:\s*(.+)",
        ],
        "creation_date": [
            r"(?:Creation Date|Created On|Registration Time|Domain Registration Date):\s*(.+)",
            r"Registered on:\s*(.+)",
        ],
        "expiration_date": [
            r"(?:Registrar Registration Expiration Date|Expiry Date|Registry Expiry Date|Expiration Date):\s*(.+)",
            r"Expiry date:\s*(.+)",
        ],
        "updated_date": [
            r"(?:Updated Date|Last Updated On|Last Modified):\s*(.+)",
            r"Last updated:\s*(.+)",
        ],
        "name_servers": [
            r"Name Server:\s*(.+)",
            r"nserver:\s*(.+)",
        ],
        "registrant_name": [
            r"Registrant Name:\s*(.+)",
            r"Registrant:\s*(.+)",
        ],
        "registrant_org": [
            r"Registrant Organization:\s*(.+)",
            r"Registrant Org:\s*(.+)",
        ],
        "registrant_email": [
            r"Registrant Email:\s*(.+)",
            r"Registrant E-mail:\s*(.+)",
        ],
        "registrant_phone": [
            r"Registrant Phone:\s*(.+)",
        ],
        "admin_email": [
            r"Admin Email:\s*(.+)",
            r"Admin Email:\s*(.+)",
        ],
        "tech_email": [
            r"Tech Email:\s*(.+)",
        ],
        "status": [
            r"Domain Status:\s*(.+)",
            r"Status:\s*(.+)",
        ],
        "dnssec": [
            r"DNSSEC:\s*(.+)",
        ],
    }

    privacy_indicators = [
        "redacted for privacy",
        "privacy protect",
        "whois guard",
        "private registration",
        "contact privacy",
        "domains by proxy",
        "whoisproxy",
        "privacy service",
        "registration private",
        "perfect privacy",
        "whois privacy",
        "private whois",
    ]

    low = response.lower()
    for indicator in privacy_indicators:
        if indicator in low:
            info["has_privacy"] = True
            info["privacy_type"] = indicator
            break

    for field, field_patterns in patterns.items():
        for pattern in field_patterns:
            matches = re.findall(
                pattern,
                response,
                re.IGNORECASE | re.MULTILINE,
            )
            if matches:
                if field == "name_servers":
                    info[field] = sorted({
                        str(x).strip().lower() for x in matches
                    })
                else:
                    info[field] = str(matches[0]).strip()
                info["fields_found"] += 1
                break

    emails = re.findall(
        r"[\w.\-+%]+@[\w.\-]+\.[A-Za-z]{2,}",
        response,
        re.IGNORECASE,
    )
    if emails:
        info["emails_found"] = sorted(set(emails))

    phones = re.findall(
        r"(?:\+?\d[\d .()\-]{6,}\d)",
        response,
    )
    if phones:
        info["phones_found"] = sorted(set(p.strip() for p in phones))[:20]

    return info

def direct_whois(domain):
    tld = domain.split(".")[-1].lower()
    server = WHOIS_SERVERS.get(tld)

    if not server:
        return {
            "source": "direct_whois",
            "error": f"No WHOIS server configured for .{tld}",
        }

    try:
        response = whois_raw_query(domain, server)

        # Follow a registrar referral when publicly supplied.
        referral = re.search(
            r"(?:Whois Server|Registrar WHOIS Server):\s*(\S+)",
            response,
            re.IGNORECASE,
        )
        if referral:
            referral_server = referral.group(1).strip()
            if referral_server and referral_server != server:
                try:
                    response2 = whois_raw_query(domain, referral_server)
                    if len(response2) > 100:
                        response = response2
                except Exception:
                    pass

        info = parse_whois_response(response)
        info["whois_server"] = server
        info["raw_length"] = len(response)
        return info

    except Exception as e:
        return {
            "source": "direct_whois",
            "error": str(e),
        }

def rdap_lookup(domain):
    tld = domain.split(".")[-1].lower()

    bases = {
        "com": "https://rdap.verisign.com/com/v1/domain/",
        "net": "https://rdap.verisign.com/net/v1/domain/",
        "org": "https://rdap.publicinterestregistry.org/rdap/domain/",
    }

    base = bases.get(tld)
    if not base:
        return {
            "source": "rdap",
            "status": "No configured RDAP endpoint for this TLD",
        }

    try:
        url = base + urllib.parse.quote(domain)
        data = json.loads(http_get(
            url,
            timeout=8,
            headers={
                "Accept": "application/rdap+json, application/json",
                "User-Agent": "Website-Info-Hunter-Pro/2.0",
            },
        ))

        info = {"source": "rdap"}

        events = {}
        for event in data.get("events", []):
            action = event.get("eventAction")
            if action:
                events[action] = event.get("eventDate")
        info["events"] = events

        info["status"] = data.get("status", [])

        info["nameservers"] = [
            item.get("ldhName")
            for item in data.get("nameservers", [])
            if item.get("ldhName")
        ][:30]

        # Only use contact fields that the RDAP response actually publishes.
        contacts = {}
        for entity in data.get("entities", []):
            roles = entity.get("roles", [])
            vcard = entity.get("vcardArray", [])
            if len(vcard) < 2:
                continue

            parsed = {}
            for item in vcard[1]:
                if len(item) < 4:
                    continue
                prop = item[0]
                value = item[3]
                if prop == "fn":
                    parsed["name"] = value
                elif prop == "org":
                    parsed["organization"] = value
                elif prop == "email":
                    parsed["email"] = value
                elif prop == "tel":
                    parsed["phone"] = value

            for role in roles:
                if role in ("registrant", "administrative", "technical"):
                    contacts[role] = parsed

        if contacts:
            info["contacts"] = contacts

        return info

    except Exception as e:
        return {
            "source": "rdap",
            "status": "unavailable",
            "error": str(e),
        }

# -------------------- Deep public intelligence --------------------

def certificate_intelligence(domain):
    info = {"source": "certificate"}

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as raw:
            with ctx.wrap_socket(raw, server_hostname=domain) as conn:
                cert = conn.getpeercert()
                subject = dict(x[0] for x in cert.get("subject", []))
                issuer = dict(x[0] for x in cert.get("issuer", []))

                if subject.get("commonName"):
                    info["common_name"] = subject["commonName"]
                if subject.get("organizationName"):
                    info["organization"] = subject["organizationName"]
                if issuer.get("commonName"):
                    info["issuer_common_name"] = issuer["commonName"]
                if issuer.get("organizationName"):
                    info["issuer_organization"] = issuer["organizationName"]

                sans = [
                    value
                    for typ, value in cert.get("subjectAltName", [])
                    if typ == "DNS"
                ]
                info["sans"] = sans[:50]
                info["total_sans"] = len(sans)

    except Exception as e:
        info["error"] = str(e)

    return info

def hosting_intelligence(domain, ip, headers, geo):
    provider, hostname = detect_hosting(ip, headers, geo)

    return {
        "provider": provider,
        "reverse_dns": hostname or None,
        "geo_org": (geo or {}).get("org"),
        "geo_isp": (geo or {}).get("isp"),
        "platform_header": headers.get("Platform"),
        "panel_header": headers.get("Panel"),
    }

# -------------------- Scanner --------------------

def run_scan(domain, deep=False):
    started = time.time()
    domain = normalize_domain(domain)

    result = {
        "domain": domain,
        "scan_type": "DEEP" if deep else "FAST",
        "time": datetime.utcnow().isoformat() + "Z",
    }

    all_ips = resolve_all_ips(domain)
    result["ips"] = all_ips
    result["ip"] = all_ips["A"][0] if all_ips["A"] else None

    jobs = {
        "dns": lambda: get_dns_info(domain),
        "headers": lambda: get_headers(domain),
        "ssl": lambda: get_ssl(domain),
        "geo": lambda: get_geo(result["ip"]),
    }

    if deep:
        jobs.update({
            "ports": lambda: scan_ports(domain),
            "whois": lambda: direct_whois(domain),
            "rdap": lambda: rdap_lookup(domain),
            "dns_intelligence": lambda: dns_intelligence(domain),
            "certificate_intelligence": lambda: certificate_intelligence(domain),
        })

    collected = {}
    with ThreadPoolExecutor(max_workers=min(10, len(jobs))) as executor:
        future_map = {
            executor.submit(fn): name
            for name, fn in jobs.items()
        }

        for future in as_completed(future_map):
            name = future_map[future]
            try:
                collected[name] = future.result()
            except Exception as e:
                collected[name] = {"error": str(e)}

    result.update(collected)

    header_data = result.get("headers") or {}
    headers = header_data.get("headers", {}) if isinstance(header_data, dict) else {}

    # Try a small GET only when headers don't reveal enough technology clues.
    body = None
    if deep and not detect_technologies(headers):
        try:
            req = urllib.request.Request(
                f"https://{domain}/",
                headers={"User-Agent": "Mozilla/5.0 Website-Info-Hunter-Pro/2.0"},
            )
            with urllib.request.urlopen(req, timeout=5) as response:
                body = response.read(200000).decode("utf-8", errors="ignore")
        except Exception:
            pass

    result["technologies"] = detect_technologies(headers, body)
    result["security"] = security_analysis(headers)
    result["hosting"] = detect_hosting(
        result["ip"],
        headers,
        result.get("geo") or {},
    )
    result["hosting_intelligence"] = hosting_intelligence(
        domain,
        result["ip"],
        headers,
        result.get("geo") or {},
    )
    result["elapsed"] = round(time.time() - started, 2)

    return result

# -------------------- Report --------------------

def add_contact(lines, label, data):
    if not isinstance(data, dict):
        return
    if data.get("name"):
        lines.append(f"{label} Name: {data['name']}")
    if data.get("organization"):
        lines.append(f"{label} Organization: {data['organization']}")
    if data.get("email"):
        lines.append(f"{label} Email: {data['email']}")
    if data.get("phone"):
        lines.append(f"{label} Phone: {data['phone']}")

def make_report(r):
    lines = [
        "+--------------------------------------------------+",
        f"|         {BOT_NAME:^40} |",
        "+--------------------------------------------------+",
        "",
        f"Domain: {r['domain']}",
        f"Scan Type: {r['scan_type']}",
        f"Time: {r['time']}",
        f"Elapsed: {r['elapsed']}s",
        "",
        "+--------------------------------------------------+",
        "|              HOSTING & IP INTELLIGENCE           |",
        "+--------------------------------------------------+",
        "",
        "IP ADDRESSES:",
    ]

    ips = r.get("ips") or {}
    if ips.get("A"):
        for ip in ips["A"]:
            lines.append(f"   IPv4: {ip}")
    if ips.get("AAAA"):
        for ip in ips["AAAA"]:
            lines.append(f"   IPv6: {ip}")

    geo = r.get("geo") or {}
    if geo:
        lines += [
            "",
            "LOCATION:",
            f"   Country: {geo.get('country', 'N/A')} ({geo.get('countryCode', 'N/A')})",
            f"   City: {geo.get('city', 'N/A')}",
            f"   Region: {geo.get('regionName', 'N/A')}",
            f"   ISP: {geo.get('isp', 'N/A')}",
            f"   Organization: {geo.get('org', 'N/A')}",
            f"   ASN: {geo.get('as', 'N/A')}",
            f"   Timezone: {geo.get('timezone', 'N/A')}",
        ]

    hosting = r.get("hosting_intelligence") or {}
    lines += [
        "",
        "HOSTING PROVIDER:",
        f"   Provider: {hosting.get('provider', 'Unknown')}",
        f"   Reverse DNS: {hosting.get('reverse_dns') or 'N/A'}",
    ]

    ssl_info = r.get("ssl") or {}
    lines += [
        "",
        "SSL CERTIFICATE:",
    ]
    if ssl_info.get("error"):
        lines.append(f"   Error: {ssl_info['error']}")
    else:
        issuer = ssl_info.get("issuer") or {}
        subject = ssl_info.get("subject") or {}
        lines.append(f"   Issuer: {issuer.get('organizationName') or issuer.get('commonName') or 'N/A'}")
        lines.append(f"   Status: VALID / {ssl_info.get('days_left', 'N/A')} days")
        lines.append(f"   Common Name: {subject.get('commonName', 'N/A')}")
        lines.append(f"   Expires: {ssl_info.get('notAfter', 'N/A')}")
        lines.append(f"   SAN count: {ssl_info.get('total_domains_on_cert', 0)}")

    if r.get("ports") is not None:
        lines += [
            "",
            "OPEN PORTS:",
        ]
        if r["ports"]:
            for port, service in r["ports"]:
                lines.append(f"   OK Port {port} ({service})")
        else:
            lines.append("   No selected ports reported open.")

    lines += [
        "",
        "+--------------------------------------------------+",
        "|                 DNS RECORDS                      |",
        "+--------------------------------------------------+",
    ]

    dnsinfo = r.get("dns") or {}
    for key in ("A", "AAAA", "CNAME", "MX", "NS", "PTR", "TXT"):
        values = dnsinfo.get(key) or []
        if values:
            lines.append(f" {key}:")
            for value in values[:30]:
                lines.append(f"   {value}")

    if r.get("dns_intelligence"):
        di = r["dns_intelligence"]
        lines += [
            "",
            "DNS INTELLIGENCE:",
        ]
        if di.get("soa_mname"):
            lines.append(f"   SOA MNAME: {di['soa_mname']}")
        if di.get("soa_rname"):
            lines.append(f"   SOA RNAME: {di['soa_rname']} (DNS mailbox notation)")
        if di.get("email_provider"):
            lines.append(f"   Email Provider: {', '.join(di['email_provider'])}")
        if di.get("spf_includes"):
            lines.append("   SPF Includes: " + ", ".join(di["spf_includes"]))
        if di.get("has_google_verification"):
            lines.append("   Google verification: present")
        if di.get("has_microsoft_verification"):
            lines.append("   Microsoft verification: present")

    headers_data = r.get("headers") or {}
    headers = headers_data.get("headers", {}) if isinstance(headers_data, dict) else {}

    lines += [
        "",
        "+--------------------------------------------------+",
        "|              HTTP RESPONSE HEADERS               |",
        "+--------------------------------------------------+",
        "",
        f" Status Code: {headers_data.get('status', 'N/A')}",
        f" Scheme: {headers_data.get('scheme', 'N/A')}",
    ]
    for key, value in headers.items():
        lines.append(f"   {key}: {value}")

    lines += [
        "",
        "+--------------------------------------------------+",
        "|             TECHNOLOGIES DETECTED                |",
        "+--------------------------------------------------+",
        "",
        "   " + ", ".join(r.get("technologies", ["Not detected"])),
        "",
        "+--------------------------------------------------+",
        "|              SECURITY ANALYSIS                   |",
        "+--------------------------------------------------+",
        "",
    ]

    security = r.get("security") or {}
    lines.append(
        f" SECURITY HEADERS: {security.get('score', 0)}/{security.get('total', 5)}"
    )
    for name, present in (security.get("checks") or {}).items():
        lines.append(f"   {'OK' if present else 'NO'} {name}")

    if r.get("whois") is not None:
        whois = r["whois"] or {}
        lines += [
            "",
            "+--------------------------------------------------+",
            "|          WHOIS PRIVACY BYPASS DEEP SCAN          |",
            "+--------------------------------------------------+",
            "",
            "   Note: Only publicly returned registration data is shown.",
            "   Registrar privacy controls are not bypassed.",
        ]

        if whois.get("error"):
            lines.append(f"   Error: {whois['error']}")
        else:
            for key, label in (
                ("registrar", "Registrar"),
                ("creation_date", "Creation Date"),
                ("expiration_date", "Expiration Date"),
                ("updated_date", "Updated Date"),
                ("registrant_name", "Registrant Name"),
                ("registrant_org", "Registrant Organization"),
                ("registrant_email", "Registrant Email"),
                ("registrant_phone", "Registrant Phone"),
                ("admin_email", "Admin Email"),
                ("tech_email", "Tech Email"),
                ("dnssec", "DNSSEC"),
            ):
                if whois.get(key):
                    lines.append(f"   {label}: {whois[key]}")

            if whois.get("name_servers"):
                lines.append(
                    "   Name Servers: " + ", ".join(whois["name_servers"][:20])
                )
            if whois.get("status"):
                lines.append(f"   Status: {whois['status']}")
            if whois.get("emails_found"):
                lines.append(
                    "   Emails Found: " + ", ".join(whois["emails_found"][:20])
                )
            if whois.get("phones_found"):
                lines.append(
                    "   Phones Found: " + ", ".join(whois["phones_found"][:20])
                )
            if whois.get("has_privacy"):
                lines.append(
                    f"   Privacy indicator: {whois.get('privacy_type', 'detected')}"
                )

    if r.get("rdap") is not None:
        rdap = r["rdap"] or {}
        lines += [
            "",
            "PUBLIC RDAP:",
        ]
        if rdap.get("status"):
            lines.append(f"   Status: {rdap['status']}")
        events = rdap.get("events") or {}
        for key, value in events.items():
            lines.append(f"   {key}: {value}")

        contacts = rdap.get("contacts") or {}
        for role, data in contacts.items():
            add_contact(lines, role.title(), data)

    if r.get("certificate_intelligence") is not None:
        ci = r["certificate_intelligence"] or {}
        lines += [
            "",
            "CERTIFICATE INTELLIGENCE:",
        ]
        for key in (
            "common_name",
            "organization",
            "issuer_common_name",
            "issuer_organization",
        ):
            if ci.get(key):
                lines.append(f"   {key.replace('_', ' ').title()}: {ci[key]}")
        if ci.get("sans"):
            lines.append("   SANs: " + ", ".join(ci["sans"][:20]))

    lines += [
        "",
        "==================================================",
        "Deep Scan collects public DNS/WHOIS/RDAP/certificate",
        "information and selected TCP-port status.",
        "Use active scanning only on systems you own or are",
        "authorized to test.",
        "",
        "╔══════════════════════════════════════════╗",
        "║      🔎 Website Info Hunter Pro         ║",
        "║          Developed by PH Hamid          ║",
        "╚══════════════════════════════════════════╝",
        "Telegram: https://t.me/PHhamid",
    ]

    return "\n".join(lines)

# -------------------- User UI --------------------

def main_menu():
    markup = types.InlineKeyboardMarkup(row_width=2)
    markup.add(
        types.InlineKeyboardButton("⚡ Fast Scan", callback_data="scan_fast"),
        types.InlineKeyboardButton("🔬 Deep Scan", callback_data="scan_deep"),
    )
    markup.add(types.InlineKeyboardButton("ℹ️ Help", callback_data="help"))
    return markup

def persistent_menu():
    markup = types.ReplyKeyboardMarkup(resize_keyboard=True, row_width=2)
    markup.add("⚡ Fast Scan", "🔬 Deep Scan")
    markup.add("ℹ️ Help", "🏠 Main Menu")
    return markup

def send_main_menu(chat_id):
    bot.send_message(
        chat_id,
        f"🔎 *{BOT_NAME}*\n\nFast Scan অথবা Deep Scan নির্বাচন করুন, তারপর domain পাঠান.",
        reply_markup=persistent_menu(),
        parse_mode="Markdown",
    )

@bot.message_handler(commands=["start", "menu"])
def start(message):
    if not group_allowed(message):
        return
    track_user(message)
    send_main_menu(message.chat.id)
    # Inline menu is still shown once, while the persistent keyboard stays available.
    bot.send_message(message.chat.id, "👇 Quick menu", reply_markup=main_menu())

@bot.message_handler(commands=["help"])
def help_command(message):
    if not group_allowed(message):
        return
    track_user(message)

    bot.send_message(
        message.chat.id,
        "⚡ Fast Scan — IP/GEO, DNS, Headers, SSL, Hosting, Technologies\n"
        "🔬 Deep Scan — Fast + selected ports + public WHOIS/RDAP + DNS intelligence\n\n"
        "/id — Telegram User ID ও Chat ID\n"
        "/cancel — current scan cancel\n\n"
        "⚠️ Deep Scan-এর active port checks শুধু authorized systems-এ ব্যবহার করুন.",
        reply_markup=main_menu(),
    )

@bot.message_handler(commands=["id"])
def id_command(message):
    track_user(message)
    bot.send_message(
        message.chat.id,
        f"User ID: `{message.from_user.id}`\nChat ID: `{message.chat.id}`",
        parse_mode="Markdown",
    )

@bot.message_handler(commands=["cancel"])
def cancel_command(message):
    track_user(message)
    SCAN_MODE.pop(message.from_user.id, None)
    ACTIVE_SCANS.pop(message.from_user.id, None)
    BROADCAST_WAITING.discard(message.from_user.id)
    bot.send_message(message.chat.id, "❌ Cancelled.", reply_markup=persistent_menu())

@bot.callback_query_handler(
    func=lambda call: call.data in ("scan_fast", "scan_deep", "help")
)
def menu_callbacks(call):
    # Inline-button users are tracked in RAM too.
    if call.from_user:
        USERS[call.from_user.id] = {
            "id": call.from_user.id,
            "username": call.from_user.username or "",
            "name": (f"{call.from_user.first_name or ''} {call.from_user.last_name or ''}").strip(),
            "chat_id": call.message.chat.id,
            "last_seen": time.time(),
        }

    if call.data == "help":
        bot.answer_callback_query(call.id)
        bot.send_message(
            call.message.chat.id,
            "Fast Scan অথবা Deep Scan নির্বাচন করুন, তারপর domain পাঠান.",
            reply_markup=main_menu(),
        )
        return

    if (
        call.message.chat.type in ("group", "supergroup")
        and not group_is_authorized(call.message.chat.id)
    ):
        bot.answer_callback_query(
            call.id,
            "⛔ এই group authorized নয়.",
            show_alert=True,
        )
        return

    mode = call.data.replace("scan_", "")
    SCAN_MODE[call.from_user.id] = mode

    bot.answer_callback_query(call.id)
    bot.send_message(
        call.message.chat.id,
        f"Send domain for *{mode.upper()} SCAN*.\nExample: `example.com`",
        parse_mode="Markdown",
    )

@bot.message_handler(
    func=lambda m: bool(m.text) and not m.text.startswith("/"),
    content_types=["text"],
)
def domain_handler(message):
    if not group_allowed(message):
        return

    track_user(message)

    # Admin broadcast input mode.
    if message.from_user.id in BROADCAST_WAITING:
        BROADCAST_WAITING.discard(message.from_user.id)
        sent = 0
        failed = 0
        text = message.text.strip()
        with ACTIVITY_LOCK:
            targets = list(USERS.keys())
        for uid in targets:
            try:
                bot.send_message(uid, text, disable_web_page_preview=False)
                sent += 1
            except Exception:
                failed += 1
        bot.send_message(
            ADMIN_ID,
            f"📢 *Broadcast completed*\n\n👥 Targets: {len(targets)}\n✅ Sent: {sent}\n❌ Failed: {failed}",
            parse_mode="Markdown",
            reply_markup=admin_menu(),
        )
        return

    # Persistent reply-keyboard actions.
    if message.text in ("⚡ Fast Scan", "🔬 Deep Scan"):
        mode = "fast" if message.text.startswith("⚡") else "deep"
        SCAN_MODE[message.from_user.id] = mode
        bot.send_message(
            message.chat.id,
            f"Send domain for *{mode.upper()} SCAN*.\nExample: `example.com`",
            parse_mode="Markdown",
            reply_markup=persistent_menu(),
        )
        return

    if message.text == "ℹ️ Help":
        help_command(message)
        return

    if message.text == "🏠 Main Menu":
        SCAN_MODE.pop(message.from_user.id, None)
        send_main_menu(message.chat.id)
        return

    mode = SCAN_MODE.get(message.from_user.id)
    if not mode:
        return

    now = time.time()
    last = LAST_SCAN.get(message.from_user.id, 0)

    if now - last < SCAN_COOLDOWN:
        remaining = int(SCAN_COOLDOWN - (now - last)) + 1
        bot.reply_to(message, f"⏳ {remaining}s পরে আবার scan করুন.", reply_markup=persistent_menu())
        return

    try:
        domain = normalize_domain(message.text)
    except ValueError as e:
        bot.reply_to(message, f"❌ {e}", reply_markup=persistent_menu())
        return

    LAST_SCAN[message.from_user.id] = now
    SCAN_MODE.pop(message.from_user.id, None)
    ACTIVE_SCANS[message.from_user.id] = {
        "domain": domain,
        "mode": mode,
        "started": now,
        "chat_id": message.chat.id,
    }

    notify_admin(
        "🔴 *LIVE SCAN STARTED*\n\n"
        f"👤 User: `{user_label(message.from_user.id)}`\n"
        f"🆔 ID: `{message.from_user.id}`\n"
        f"🌐 Website: `{domain}`\n"
        f"🔬 Mode: `{mode.upper()}`",
    )

    progress = bot.reply_to(
        message,
        f"⏳ *{mode.upper()} SCAN* চলছে...\n🌐 `{domain}`",
        parse_mode="Markdown",
        reply_markup=persistent_menu(),
    )

    try:
        result = run_scan(domain, deep=(mode == "deep"))
        report = make_report(result)

        ACTIVE_SCANS.pop(message.from_user.id, None)
        notify_admin(
            "🟢 *LIVE SCAN COMPLETED*\n\n"
            f"👤 User: `{user_label(message.from_user.id)}`\n"
            f"🌐 Website: `{domain}`\n"
            f"🔬 Mode: `{mode.upper()}`\n"
            f"⏱ Time: `{result.get('elapsed', 'N/A')}s`",
        )

        # Telegram delivery/edit errors must NOT turn a successful scan into
        # a false "LIVE SCAN FAILED" notification. The scan is already
        # completed at this point, so handle report delivery separately.
        try:
            if len(report) <= 3900:
                report_html = html.escape(report).replace(
                    "Developed by PH Hamid",
                    'Developed by <a href="https://t.me/PHhamid">PH Hamid</a>'
                )
                try:
                    bot.edit_message_text(
                        report_html,
                        message.chat.id,
                        progress.message_id,
                        parse_mode="HTML",
                        disable_web_page_preview=True,
                    )
                except Exception as edit_error:
                    # The progress message may already have been edited/deleted
                    # or Telegram may reject the edit. Send the report as a new
                    # message instead; do NOT raise this as a scan failure.
                    print(f"Report edit failed (scan still successful): {edit_error}")
                    bot.send_message(
                        message.chat.id,
                        report_html,
                        parse_mode="HTML",
                        disable_web_page_preview=True,
                        reply_markup=persistent_menu(),
                    )
            else:
                try:
                    bot.edit_message_text(
                        f"✅ {mode.upper()} Scan completed — `{domain}`",
                        message.chat.id,
                        progress.message_id,
                        parse_mode="Markdown",
                    )
                except Exception as edit_error:
                    print(f"Completion message edit failed (scan still successful): {edit_error}")
                    bot.send_message(
                        message.chat.id,
                        f"✅ {mode.upper()} Scan completed — `{domain}`",
                        parse_mode="Markdown",
                        reply_markup=persistent_menu(),
                    )

                document = io.BytesIO(report.encode("utf-8"))
                document.name = f"{domain}_{mode}_report.txt"
                bot.send_document(
                    message.chat.id,
                    document,
                    caption="📄 Full scan report",
                )
        except Exception as delivery_error:
            # Report delivery failed, but the website scan itself succeeded.
            print(f"Report delivery failed (scan still successful): {delivery_error}")
            try:
                bot.send_message(
                    message.chat.id,
                    f"✅ {mode.upper()} Scan completed — `{domain}`\n\n⚠️ রিপোর্ট পাঠাতে সমস্যা হয়েছে। আবার চেষ্টা করুন।",
                    parse_mode="Markdown",
                    reply_markup=persistent_menu(),
                )
            except Exception as fallback_error:
                print(f"Fallback report message failed: {fallback_error}")

    except Exception as e:
        ACTIVE_SCANS.pop(message.from_user.id, None)
        notify_admin(
            "🔴 *LIVE SCAN FAILED*\n\n"
            f"👤 User: `{user_label(message.from_user.id)}`\n"
            f"🌐 Website: `{domain}`\n"
            f"❌ Error: `{str(e)[:500]}`",
        )
        bot.edit_message_text(
            f"❌ Scan failed:\n`{str(e)[:3500]}`",
            message.chat.id,
            progress.message_id,
            parse_mode="Markdown",
        )

# -------------------- Single Admin --------------------

def admin_menu():
    markup = types.InlineKeyboardMarkup(row_width=2)
    markup.add(
        types.InlineKeyboardButton("📊 Status", callback_data="adm_status"),
        types.InlineKeyboardButton("👥 Users", callback_data="adm_users"),
    )
    markup.add(
        types.InlineKeyboardButton("🔴 Live Activity", callback_data="adm_live"),
        types.InlineKeyboardButton("📢 Broadcast", callback_data="adm_broadcast"),
    )
    markup.add(types.InlineKeyboardButton("👥 Groups", callback_data="adm_groups"))
    markup.add(
        types.InlineKeyboardButton("➕ Add Current Group", callback_data="adm_add_group"),
        types.InlineKeyboardButton("➖ Remove Current Group", callback_data="adm_remove_group"),
    )
    markup.add(types.InlineKeyboardButton("📋 Admin Help", callback_data="adm_help"))
    return markup

@bot.message_handler(commands=["admin"])
def admin_panel(message):
    if not admin_only(message):
        return

    bot.send_message(
        message.chat.id,
        f"🛡 *{BOT_NAME} — Admin Panel*\n\n"
        f"👥 Runtime Users: {len(USERS)}\n"
        f"🔴 Active Scans: {len(ACTIVE_SCANS)}",
        reply_markup=admin_menu(),
        parse_mode="Markdown",
    )

@bot.message_handler(commands=["group_add"])
def group_add(message):
    if not admin_only(message):
        return

    if message.chat.type not in ("group", "supergroup"):
        bot.reply_to(message, "এই command group-এর ভিতরে ব্যবহার করুন.")
        return

    AUTHORIZED_GROUPS.add(message.chat.id)
    bot.reply_to(
        message,
        f"✅ Group authorized.\nChat ID: `{message.chat.id}`",
        parse_mode="Markdown",
    )

@bot.message_handler(commands=["group_remove"])
def group_remove(message):
    if not admin_only(message):
        return

    if message.chat.id in AUTHORIZED_GROUPS:
        AUTHORIZED_GROUPS.remove(message.chat.id)
        bot.reply_to(message, "✅ এই group-এর authorization removed.")
    else:
        bot.reply_to(message, "ℹ️ এই group authorized ছিল না.")

@bot.message_handler(commands=["group_list"])
def group_list(message):
    if not admin_only(message):
        return

    if not AUTHORIZED_GROUPS:
        bot.reply_to(message, "📋 কোনো authorized group নেই.")
        return

    text = "📋 *Authorized Groups*\n\n"
    text += "\n".join(
        f"• `{gid}`" for gid in sorted(AUTHORIZED_GROUPS)
    )
    bot.reply_to(message, text, parse_mode="Markdown")

@bot.message_handler(commands=["bot_status"])
def bot_status(message):
    if not admin_only(message):
        return

    bot.reply_to(
        message,
        f"🤖 *{BOT_NAME}*\n"
        f"Status: ONLINE\n"
        f"Admin ID: `{ADMIN_ID}`\n"
        f"Authorized groups: {len(AUTHORIZED_GROUPS)}",
        parse_mode="Markdown",
    )

@bot.message_handler(commands=["users"])
def users_command(message):
    if not admin_only(message):
        return
    if not USERS:
        bot.reply_to(message, "👥 এখনো কোনো user tracked হয়নি.")
        return
    lines = [f"👥 *Runtime Users: {len(USERS)}*", ""]
    for uid, u in list(USERS.items())[-50:][::-1]:
        lines.append(f"• {user_label(uid)} — `{uid}`")
    bot.reply_to(message, "\n".join(lines), parse_mode="Markdown")

@bot.message_handler(commands=["live"])
def live_command(message):
    if not admin_only(message):
        return
    if not ACTIVE_SCANS:
        bot.reply_to(message, "🟢 এখন কোনো active scan নেই.")
        return
    lines = ["🔴 *LIVE SCANS*", ""]
    for uid, data in ACTIVE_SCANS.items():
        elapsed = int(time.time() - data["started"])
        lines.append(f"👤 {user_label(uid)}\n🌐 `{data['domain']}`\n🔬 {data['mode'].upper()} • {elapsed}s\n")
    bot.reply_to(message, "\n".join(lines), parse_mode="Markdown")

@bot.message_handler(commands=["broadcast"])
def broadcast_command(message):
    if not admin_only(message):
        return
    BROADCAST_WAITING.add(message.from_user.id)
    bot.reply_to(message, "📢 যে message সবাইকে পাঠাতে চান সেটি এখন পাঠান.\n/cancel দিয়ে বাতিল করতে পারবেন.")

@bot.message_handler(commands=["admin_help"])
def admin_help(message):
    if not admin_only(message):
        return

    bot.reply_to(
        message,
        "🛡 *ADMIN COMMANDS*\n\n"
        "/admin — Admin panel\n"
        "/group_add — current group authorize\n"
        "/group_remove — current group disable\n"
        "/group_list — authorized groups\n"
        "/bot_status — bot status\n"
        "/users — runtime user list\n"
        "/live — live scan activity\n"
        "/broadcast — broadcast message\n"
        "/admin_help — commands\n\n"
        "শুধু configured ADMIN_ID এই commands চালাতে পারবে.",
        parse_mode="Markdown",
    )

@bot.callback_query_handler(func=lambda call: call.data.startswith("adm_"))
def admin_callbacks(call):
    if call.from_user.id != ADMIN_ID:
        bot.answer_callback_query(
            call.id,
            "⛔ Admin only.",
            show_alert=True,
        )
        return

    bot.answer_callback_query(call.id)

    if call.data == "adm_status":
        bot.send_message(
            ADMIN_ID,
            f"🤖 {BOT_NAME}\n"
            f"Status: ONLINE\n"
            f"👥 Runtime users: {len(USERS)}\n"
            f"🔴 Active scans: {len(ACTIVE_SCANS)}\n"
            f"Authorized groups: {len(AUTHORIZED_GROUPS)}",
            reply_markup=admin_menu(),
        )

    elif call.data == "adm_users":
        if not USERS:
            bot.send_message(ADMIN_ID, "👥 No users tracked yet.", reply_markup=admin_menu())
        else:
            lines = [f"👥 *Runtime Users: {len(USERS)}*", ""]
            for uid in list(USERS.keys())[-50:][::-1]:
                lines.append(f"• {user_label(uid)} — `{uid}`")
            bot.send_message(ADMIN_ID, "\n".join(lines), parse_mode="Markdown", reply_markup=admin_menu())

    elif call.data == "adm_live":
        if not ACTIVE_SCANS:
            bot.send_message(ADMIN_ID, "🟢 No active scans right now.", reply_markup=admin_menu())
        else:
            lines = ["🔴 *LIVE SCANS*", ""]
            for uid, data in ACTIVE_SCANS.items():
                elapsed = int(time.time() - data["started"])
                lines.append(f"👤 {user_label(uid)}\n🌐 `{data['domain']}`\n🔬 {data['mode'].upper()} • {elapsed}s\n")
            bot.send_message(ADMIN_ID, "\n".join(lines), parse_mode="Markdown", reply_markup=admin_menu())

    elif call.data == "adm_broadcast":
        BROADCAST_WAITING.add(ADMIN_ID)
        bot.send_message(ADMIN_ID, "📢 Broadcast mode ON. এখন যে message পাঠাবেন, tracked সব user-কে পাঠানো হবে.\n/cancel দিয়ে বাতিল করুন.", reply_markup=admin_menu())

    elif call.data == "adm_groups":
        if not AUTHORIZED_GROUPS:
            bot.send_message(ADMIN_ID, "📋 No authorized groups.")
        else:
            bot.send_message(
                ADMIN_ID,
                "📋 Authorized groups:\n"
                + "\n".join(
                    f"`{gid}`" for gid in sorted(AUTHORIZED_GROUPS)
                ),
                parse_mode="Markdown",
            )

    elif call.data == "adm_add_group":
        if call.message.chat.type not in ("group", "supergroup"):
            bot.send_message(
                ADMIN_ID,
                "➕ /group_add group-এর ভিতরে ব্যবহার করুন.",
            )
        else:
            AUTHORIZED_GROUPS.add(call.message.chat.id)
            bot.send_message(
                ADMIN_ID,
                f"✅ Group authorized: `{call.message.chat.id}`",
                parse_mode="Markdown",
            )

    elif call.data == "adm_remove_group":
        if call.message.chat.id in AUTHORIZED_GROUPS:
            AUTHORIZED_GROUPS.remove(call.message.chat.id)
            bot.send_message(ADMIN_ID, "✅ Group authorization removed.")
        else:
            bot.send_message(
                ADMIN_ID,
                "ℹ️ Current group authorized ছিল না.",
            )

    elif call.data == "adm_help":
        bot.send_message(
            ADMIN_ID,
            "/admin\n"
            "/group_add\n"
            "/group_remove\n"
            "/group_list\n"
            "/bot_status\n"
            "/admin_help",
        )

# -------------------- Start --------------------

if __name__ == "__main__":
    print(f"🚀 Starting {BOT_NAME}...")
    print(f"👑 ADMIN_ID: {ADMIN_ID}")

    # Same working deployment pattern as the reference bot:
    # HTTP/Flask server runs in a daemon thread,
    # Telegram polling stays in the main process.
    keep_alive()

    bot.infinity_polling(
        timeout=90,
        long_polling_timeout=60,
        skip_pending=True,
    )
