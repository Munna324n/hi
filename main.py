import os
import re
import ssl
import socket
import json
import time
import threading
import urllib.request
import urllib.parse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

import telebot
from telebot import types
from flask import Flask, jsonify

try:
    import dns.resolver
except ImportError:
    dns = None

# ============================================================
# Website Info Hunter Pro
# Deployment pattern intentionally follows the uploaded
# Premium Service Bot:
# Flask -> background Thread -> bot.infinity_polling()
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

# Only the single configured ADMIN_ID can manage the bot.
AUTHORIZED_GROUPS = set()
SCAN_MODE = {}
LAST_SCAN = {}
SCAN_COOLDOWN = 10

# -------------------- Render / keep alive --------------------

@app.route("/")
def home():
    return "Website Info Hunter Pro is Running Smoothly! 🚀"

@app.route("/health")
def health():
    return jsonify({
        "status": "ok",
        "bot": BOT_NAME,
        "time": datetime.utcnow().isoformat() + "Z"
    })

def run():
    # Same deployment style as the supplied reference project.
    app.run(host="0.0.0.0", port=PORT, use_reloader=False)

def keep_alive():
    t = threading.Thread(target=run)
    t.daemon = True
    t.start()

# -------------------- Security / permissions --------------------

def is_admin(message_or_call):
    uid = getattr(message_or_call.from_user, "id", 0)
    return uid == ADMIN_ID

def group_is_authorized(chat_id):
    return chat_id in AUTHORIZED_GROUPS

def group_allowed(message):
    return message.chat.type not in ("group", "supergroup") or group_is_authorized(message.chat.id)

# -------------------- Helpers --------------------

def normalize_domain(value):
    value = value.strip()
    value = re.sub(r"^https?://", "", value, flags=re.I)
    value = value.split("/")[0].split("?")[0].split("#")[0]
    if ":" in value:
        value = value.split(":")[0]
    value = value.lower().rstrip(".")
    if not re.fullmatch(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", value):
        raise ValueError("Invalid domain. Example: example.com")
    return value

def http_get(url, timeout=6):
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "Mozilla/5.0 Website-Info-Hunter-Pro/1.0"}
    )
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return response.read().decode("utf-8", errors="replace")

def resolve_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return None

# -------------------- Scanner --------------------

def get_dns_info(domain):
    result = {"A": [], "AAAA": [], "MX": [], "NS": [], "TXT": [], "CNAME": [], "PTR": []}

    if dns is None:
        ip = resolve_ip(domain)
        if ip:
            result["A"] = [ip]
        return result

    for record in ("A", "AAAA", "MX", "NS", "TXT", "CNAME"):
        try:
            answers = dns.resolver.resolve(domain, record, lifetime=3)
            result[record] = [str(x).rstrip(".") for x in answers]
        except Exception:
            pass

    ip = resolve_ip(domain)
    if ip:
        try:
            result["PTR"] = [socket.gethostbyaddr(ip)[0]]
        except Exception:
            pass

    return result

def get_headers(domain):
    for scheme in ("https", "http"):
        try:
            req = urllib.request.Request(
                f"{scheme}://{domain}/",
                method="HEAD",
                headers={"User-Agent": "Mozilla/5.0 Website-Info-Hunter-Pro"}
            )
            with urllib.request.urlopen(req, timeout=6) as response:
                return dict(response.headers.items()), scheme
        except Exception:
            continue
    return {}, None

def get_ssl(domain):
    result = {}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=6) as raw:
            with ctx.wrap_socket(raw, server_hostname=domain) as conn:
                cert = conn.getpeercert()
                result["issuer"] = cert.get("issuer")
                result["subject"] = cert.get("subject")
                result["notBefore"] = cert.get("notBefore")
                result["notAfter"] = cert.get("notAfter")
                if cert.get("notAfter"):
                    try:
                        expiry = datetime.strptime(
                            cert["notAfter"], "%b %d %H:%M:%S %Y %Z"
                        )
                        result["days_left"] = (expiry - datetime.utcnow()).days
                    except Exception:
                        pass
                result["SAN"] = [
                    value for typ, value in cert.get("subjectAltName", ())
                    if typ == "DNS"
                ][:30]
    except Exception as e:
        result["error"] = str(e)
    return result

def get_geo(ip):
    if not ip:
        return {}
    try:
        data = json.loads(http_get(
            f"https://ipapi.co/{urllib.parse.quote(ip)}/json/", 6
        ))
        return {
            "ip": ip,
            "city": data.get("city"),
            "region": data.get("region"),
            "country": data.get("country_name"),
            "org": data.get("org"),
            "asn": data.get("asn")
        }
    except Exception:
        return {"ip": ip}

def scan_ports(domain):
    # Selected common TCP ports. Use only on systems you own/are authorized to test.
    ports = [21, 22, 25, 80, 443, 3306, 8080]
    ip = resolve_ip(domain)
    if not ip:
        return {}

    def check(port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.7)
        try:
            return port, ("OPEN" if sock.connect_ex((ip, port)) == 0 else "closed")
        finally:
            sock.close()

    with ThreadPoolExecutor(max_workers=7) as executor:
        return dict(executor.map(check, ports))

def detect_hosting(ip, headers):
    try:
        rdns = socket.gethostbyaddr(ip)[0].lower() if ip else ""
    except Exception:
        rdns = ""

    text = " ".join([
        str(headers.get("Server", "")),
        str(headers.get("Via", "")),
        str(headers.get("X-Powered-By", ""))
    ]).lower()

    combined = f"{rdns} {text}"
    providers = [
        ("Cloudflare", ["cloudflare"]),
        ("Amazon Web Services", ["amazonaws", "aws"]),
        ("Google Cloud", ["googleusercontent", "google cloud"]),
        ("Microsoft Azure", ["azure"]),
        ("DigitalOcean", ["digitalocean"]),
        ("Linode/Akamai", ["linode"]),
        ("Hetzner", ["hetzner"]),
        ("OVH", ["ovh"]),
        ("Vultr", ["vultr"]),
        ("Hostinger", ["hostinger"]),
        ("Namecheap", ["namecheap"]),
        ("GoDaddy", ["godaddy"]),
        ("HostGator", ["hostgator"]),
        ("Bluehost", ["bluehost"]),
        ("SiteGround", ["siteground"]),
        ("DreamHost", ["dreamhost"]),
        ("Kinsta", ["kinsta"]),
    ]
    for name, needles in providers:
        if any(needle in combined for needle in needles):
            return name, rdns
    return "Unknown / Not confidently detected", rdns

def detect_technologies(headers):
    text = " ".join(f"{k}: {v}" for k, v in headers.items()).lower()
    checks = [
        ("Cloudflare", "cloudflare"),
        ("Nginx", "nginx"),
        ("Apache", "apache"),
        ("Microsoft IIS", "microsoft-iis"),
        ("PHP", "php"),
        ("ASP.NET", "asp.net"),
    ]
    found = [name for name, needle in checks if needle in text]
    return list(dict.fromkeys(found)) or ["Not detected from headers"]

def security_score(headers):
    lower = {key.lower(): value for key, value in headers.items()}
    checks = {
        "HSTS": "strict-transport-security",
        "CSP": "content-security-policy",
        "X-Frame-Options": "x-frame-options",
        "X-Content-Type-Options": "x-content-type-options",
        "Referrer-Policy": "referrer-policy",
    }
    found = {name: needle in lower for name, needle in checks.items()}
    return round(sum(found.values()) / len(found) * 100), found

def public_rdap(domain):
    suffix = domain.split(".")[-1]
    endpoints = {
        "com": "https://rdap.verisign.com/com/v1/domain/",
        "net": "https://rdap.verisign.com/net/v1/domain/",
        "org": "https://rdap.publicinterestregistry.org/rdap/domain/",
    }
    base = endpoints.get(suffix)
    if not base:
        return {"status": "RDAP endpoint not configured for this TLD"}

    try:
        data = json.loads(http_get(base + urllib.parse.quote(domain), 8))
        events = {}
        for event in data.get("events", []):
            if event.get("eventAction"):
                events[event["eventAction"]] = event.get("eventDate")

        nameservers = [
            item.get("ldhName")
            for item in data.get("nameservers", [])
            if item.get("ldhName")
        ]

        return {
            "status": data.get("status", []),
            "events": events,
            "nameservers": nameservers[:20]
        }
    except Exception as e:
        return {"status": "RDAP unavailable", "error": str(e)}

def run_scan(domain, deep=False):
    started = time.time()
    domain = normalize_domain(domain)
    ip = resolve_ip(domain)

    result = {
        "domain": domain,
        "scan_type": "DEEP" if deep else "FAST",
        "time": datetime.utcnow().isoformat() + "Z",
        "ip": ip,
    }

    jobs = {
        "dns": get_dns_info,
        "headers": get_headers,
        "ssl": get_ssl,
        "geo": lambda _: get_geo(ip),
    }

    if deep:
        jobs["ports"] = scan_ports
        jobs["rdap"] = public_rdap

    with ThreadPoolExecutor(max_workers=len(jobs)) as executor:
        futures = {
            executor.submit(function, domain): name
            for name, function in jobs.items()
        }
        for future, name in [(f, n) for f, n in futures.items()]:
            try:
                result[name] = future.result(timeout=20)
            except Exception as e:
                result[name] = {"error": str(e)}

    header_data = result.get("headers", ({}, None))
    headers = header_data[0] if isinstance(header_data, tuple) else {}
    result["scheme"] = header_data[1] if isinstance(header_data, tuple) else None
    result["hosting"] = detect_hosting(ip, headers)
    result["technologies"] = detect_technologies(headers)
    result["security"] = security_score(headers)
    result["elapsed"] = round(time.time() - started, 2)

    return result

def make_report(result):
    lines = [
        f"🔎 {BOT_NAME}",
        "=" * 42,
        f"Domain: {result['domain']}",
        f"Scan Type: {result['scan_type']}",
        f"Time: {result['time']}",
        f"Elapsed: {result['elapsed']}s",
        "",
        "🌐 IP / GEO",
        f"IP: {result.get('ip') or 'N/A'}",
    ]

    geo = result.get("geo") or {}
    for key in ("city", "region", "country", "org", "asn"):
        if geo.get(key):
            lines.append(f"{key.title()}: {geo[key]}")

    hosting = result.get("hosting")
    if hosting:
        lines += [
            "",
            "🏢 HOSTING",
            f"Provider: {hosting[0]}",
            f"Reverse DNS: {hosting[1] or 'N/A'}",
        ]

    dns_info = result.get("dns") or {}
    lines += ["", "📡 DNS"]
    for key in ("A", "AAAA", "MX", "NS", "CNAME", "PTR"):
        values = dns_info.get(key) or []
        if values:
            lines.append(f"{key}: {', '.join(values[:10])}")

    lines += [
        "",
        "🧩 TECHNOLOGIES",
        ", ".join(result.get("technologies", [])),
    ]

    score, checks = result.get("security", (0, {}))
    lines += ["", "🛡 SECURITY HEADERS", f"Score: {score}%"]
    for key, value in checks.items():
        lines.append(f"{'✅' if value else '❌'} {key}")

    ssl_info = result.get("ssl") or {}
    lines += ["", "🔐 SSL"]
    if ssl_info.get("error"):
        lines.append(f"Error: {ssl_info['error']}")
    else:
        lines.append(f"Expires: {ssl_info.get('notAfter', 'N/A')}")
        lines.append(f"Days left: {ssl_info.get('days_left', 'N/A')}")

    if result.get("ports") is not None:
        lines += ["", "🔌 SELECTED PORTS"]
        for port, state in result["ports"].items():
            lines.append(f"{port}: {state}")

    if result.get("rdap") is not None:
        rdap = result["rdap"]
        lines += ["", "📋 PUBLIC RDAP"]
        if rdap.get("status"):
            lines.append(f"Status: {rdap['status']}")
        if rdap.get("events"):
            for key, value in rdap["events"].items():
                lines.append(f"{key}: {value}")
        if rdap.get("nameservers"):
            lines.append("Nameservers: " + ", ".join(rdap["nameservers"][:10]))

    lines += [
        "",
        "⚠️ Public-information scan. WHOIS/RDAP privacy is not bypassed.",
        "Use Deep Scan only on systems you own or are authorized to test.",
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

@bot.message_handler(commands=["start"])
def start(message):
    if not group_allowed(message):
        return

    bot.send_message(
        message.chat.id,
        f"🔎 *{BOT_NAME}*\n\n"
        "Fast Scan অথবা Deep Scan নির্বাচন করুন, তারপর domain পাঠান.",
        reply_markup=main_menu(),
        parse_mode="Markdown"
    )

@bot.message_handler(commands=["help"])
def help_command(message):
    if not group_allowed(message):
        return
    bot.send_message(
        message.chat.id,
        "⚡ Fast Scan — IP/GEO, DNS, Headers, SSL, Hosting, Technologies\n"
        "🔬 Deep Scan — Fast Scan + selected TCP ports + public RDAP\n\n"
        "/id — আপনার Telegram ID\n"
        "/cancel — বর্তমান scan বাতিল\n\n"
        "⚠️ শুধু অনুমোদিত/নিজস্ব systems scan করুন।",
        reply_markup=main_menu()
    )

@bot.message_handler(commands=["id"])
def id_command(message):
    bot.send_message(
        message.chat.id,
        f"User ID: `{message.from_user.id}`\nChat ID: `{message.chat.id}`",
        parse_mode="Markdown"
    )

@bot.message_handler(commands=["cancel"])
def cancel_command(message):
    SCAN_MODE.pop(message.from_user.id, None)
    bot.send_message(message.chat.id, "❌ Scan cancelled.")

@bot.callback_query_handler(func=lambda call: call.data in ("scan_fast", "scan_deep", "help"))
def menu_callbacks(call):
    if call.data == "help":
        bot.answer_callback_query(call.id)
        bot.send_message(
            call.message.chat.id,
            "Fast Scan বা Deep Scan নির্বাচন করুন, তারপর domain পাঠান.",
            reply_markup=main_menu()
        )
        return

    if call.message.chat.type in ("group", "supergroup") and not group_is_authorized(call.message.chat.id):
        bot.answer_callback_query(call.id, "⛔ এই group authorized নয়।", show_alert=True)
        return

    mode = call.data.replace("scan_", "")
    SCAN_MODE[call.from_user.id] = mode
    bot.answer_callback_query(call.id)
    bot.send_message(
        call.message.chat.id,
        f"Send domain for *{mode.upper()} SCAN*.\nExample: `example.com`",
        parse_mode="Markdown"
    )

@bot.message_handler(func=lambda m: not m.text.startswith("/") and m.content_type == "text")
def domain_handler(message):
    if message.chat.type in ("group", "supergroup") and not group_is_authorized(message.chat.id):
        return

    mode = SCAN_MODE.get(message.from_user.id)
    if not mode:
        return

    now = time.time()
    last = LAST_SCAN.get(message.from_user.id, 0)
    if now - last < SCAN_COOLDOWN:
        bot.reply_to(message, f"⏳ {int(SCAN_COOLDOWN - (now-last))}s পরে আবার scan করুন।")
        return

    try:
        domain = normalize_domain(message.text)
    except ValueError as e:
        bot.reply_to(message, f"❌ {e}")
        return

    LAST_SCAN[message.from_user.id] = now
    SCAN_MODE.pop(message.from_user.id, None)

    progress = bot.reply_to(
        message,
        f"⏳ *{mode.upper()} SCAN* চলছে...\n🌐 `{domain}`",
        parse_mode="Markdown"
    )

    try:
        result = run_scan(domain, deep=(mode == "deep"))
        report = make_report(result)

        if len(report) <= 3900:
            bot.edit_message_text(
                report,
                message.chat.id,
                progress.message_id
            )
        else:
            bot.edit_message_text(
                f"✅ Scan completed — `{domain}`",
                message.chat.id,
                progress.message_id,
                parse_mode="Markdown"
            )
            bot.send_document(
                message.chat.id,
                report.encode("utf-8"),
                visible_file_name=f"{domain}_{mode}_report.txt",
                caption="📄 Full scan report"
            )
    except Exception as e:
        bot.edit_message_text(
            f"❌ Scan failed:\n`{e}`",
            message.chat.id,
            progress.message_id,
            parse_mode="Markdown"
        )

# -------------------- Single Admin Management --------------------

def admin_only(message):
    if message.from_user.id != ADMIN_ID:
        bot.reply_to(message, "⛔ Admin access denied.")
        return False
    return True

@bot.message_handler(commands=["admin"])
def admin_panel(message):
    if not admin_only(message):
        return

    markup = types.InlineKeyboardMarkup(row_width=2)
    markup.add(
        types.InlineKeyboardButton("📊 Status", callback_data="adm_status"),
        types.InlineKeyboardButton("👥 Groups", callback_data="adm_groups"),
    )
    markup.add(
        types.InlineKeyboardButton("➕ Add Current Group", callback_data="adm_add_group"),
        types.InlineKeyboardButton("➖ Remove Current Group", callback_data="adm_remove_group"),
    )
    markup.add(
        types.InlineKeyboardButton("📋 Admin Help", callback_data="adm_help"),
    )

    bot.send_message(
        message.chat.id,
        "🛡 *Website Info Hunter Pro — Admin Panel*",
        reply_markup=markup,
        parse_mode="Markdown"
    )

@bot.message_handler(commands=["group_add"])
def group_add(message):
    if not admin_only(message):
        return
    if message.chat.type not in ("group", "supergroup"):
        bot.reply_to(message, "এই command group-এর ভিতরে ব্যবহার করুন।")
        return

    AUTHORIZED_GROUPS.add(message.chat.id)
    bot.reply_to(
        message,
        f"✅ Group authorized.\nChat ID: `{message.chat.id}`",
        parse_mode="Markdown"
    )

@bot.message_handler(commands=["group_remove"])
def group_remove(message):
    if not admin_only(message):
        return
    if message.chat.id in AUTHORIZED_GROUPS:
        AUTHORIZED_GROUPS.remove(message.chat.id)
        bot.reply_to(message, "✅ এই group-এর authorization removed.")
    else:
        bot.reply_to(message, "ℹ️ এই group authorized ছিল না।")

@bot.message_handler(commands=["group_list"])
def group_list(message):
    if not admin_only(message):
        return
    if not AUTHORIZED_GROUPS:
        bot.reply_to(message, "📋 কোনো authorized group নেই।")
        return
    text = "📋 *Authorized Groups*\n\n"
    text += "\n".join(f"• `{gid}`" for gid in sorted(AUTHORIZED_GROUPS))
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
        parse_mode="Markdown"
    )

@bot.message_handler(commands=["admin_help"])
def admin_help(message):
    if not admin_only(message):
        return
    bot.reply_to(
        message,
        "🛡 *ADMIN COMMANDS*\n\n"
        "/admin — Admin panel\n"
        "/group_add — Current group authorize\n"
        "/group_remove — Current group disable\n"
        "/group_list — Authorized groups\n"
        "/bot_status — Bot status\n"
        "/admin_help — Commands\n\n"
        "⚠️ Telegram group admin হওয়া মানেই Bot Admin হওয়া নয়।\n"
        "শুধু configured ADMIN_ID এই commands চালাতে পারবে।",
        parse_mode="Markdown"
    )

@bot.callback_query_handler(func=lambda call: call.data.startswith("adm_"))
def admin_callbacks(call):
    if call.from_user.id != ADMIN_ID:
        bot.answer_callback_query(call.id, "⛔ Admin only.", show_alert=True)
        return

    bot.answer_callback_query(call.id)

    if call.data == "adm_status":
        bot.send_message(
            ADMIN_ID,
            f"🤖 {BOT_NAME}\n"
            f"Status: ONLINE\n"
            f"Authorized groups: {len(AUTHORIZED_GROUPS)}"
        )

    elif call.data == "adm_groups":
        if not AUTHORIZED_GROUPS:
            bot.send_message(ADMIN_ID, "📋 No authorized groups.")
        else:
            bot.send_message(
                ADMIN_ID,
                "📋 Authorized groups:\n" +
                "\n".join(f"`{gid}`" for gid in sorted(AUTHORIZED_GROUPS)),
                parse_mode="Markdown"
            )

    elif call.data == "adm_add_group":
        if call.message.chat.type not in ("group", "supergroup"):
            bot.send_message(ADMIN_ID, "➕ /group_add group-এর ভিতরে ব্যবহার করুন।")
        else:
            AUTHORIZED_GROUPS.add(call.message.chat.id)
            bot.send_message(
                ADMIN_ID,
                f"✅ Group authorized: `{call.message.chat.id}`",
                parse_mode="Markdown"
            )

    elif call.data == "adm_remove_group":
        if call.message.chat.id in AUTHORIZED_GROUPS:
            AUTHORIZED_GROUPS.remove(call.message.chat.id)
            bot.send_message(ADMIN_ID, "✅ Group authorization removed.")
        else:
            bot.send_message(ADMIN_ID, "ℹ️ Current group authorized ছিল না।")

    elif call.data == "adm_help":
        bot.send_message(
            ADMIN_ID,
            "/admin\n/group_add\n/group_remove\n/group_list\n/bot_status\n/admin_help"
        )

# -------------------- Start --------------------

if __name__ == "__main__":
    print(f"🚀 Starting {BOT_NAME}...")
    print(f"👑 ADMIN_ID: {ADMIN_ID}")
    keep_alive()
    # Same main-process polling pattern as the reference bot.
    bot.infinity_polling(timeout=90, long_polling_timeout=60, skip_pending=True)
