"""
╔══════════════════════════════════════════════════════╗
║         🛡️  VirusTotal Telegram Bot v2.0             ║
║     python-telegram-bot 22.7 + VT API v3             ║
║     Webhook Mode + Self-Ping (Render Free Web)       ║
╚══════════════════════════════════════════════════════╝
"""

import asyncio
import hashlib
import io
import logging
import os
import re
from base64 import urlsafe_b64encode

import aiohttp
from aiohttp import web
from telegram import (
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    Update,
)
from telegram.constants import ChatAction, ParseMode
from telegram.ext import (
    Application,
    ApplicationBuilder,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

# ─────────────────────────────────────────────
#  Logging
# ─────────────────────────────────────────────
logging.basicConfig(
    format="%(asctime)s | %(name)s | %(levelname)s | %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)
logging.getLogger("httpx").setLevel(logging.WARNING)

# ─────────────────────────────────────────────
#  Config from Environment
# ─────────────────────────────────────────────
BOT_TOKEN: str       = os.environ["BOT_TOKEN"]
VT_API_KEY: str      = os.environ["VT_API_KEY"]
RENDER_URL: str      = os.environ.get("RENDER_URL", "")   # e.g. https://my-bot.onrender.com
PORT: int            = int(os.getenv("PORT", "8080"))
MAX_FILE_SIZE_MB: int = int(os.getenv("MAX_FILE_SIZE_MB", "32"))

WEBHOOK_PATH  = f"/webhook/{BOT_TOKEN}"
WEBHOOK_URL   = f"{RENDER_URL}{WEBHOOK_PATH}"

# ─────────────────────────────────────────────
#  VirusTotal
# ─────────────────────────────────────────────
VT_BASE    = "https://www.virustotal.com/api/v3"
VT_HEADERS = {"x-apikey": VT_API_KEY, "Accept": "application/json"}
VT_GUI     = "https://www.virustotal.com/gui"

POLL_INTERVAL = 5
POLL_MAX_TRIES = 24

# ─────────────────────────────────────────────
#  Regex Patterns
# ─────────────────────────────────────────────
HASH_MD5    = re.compile(r"^[a-fA-F0-9]{32}$")
HASH_SHA1   = re.compile(r"^[a-fA-F0-9]{40}$")
HASH_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")
IP_PATTERN  = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
DOMAIN_RE   = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


# ─────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────
def threat_emoji(malicious: int, total: int) -> str:
    if total == 0:
        return "⚪"
    if malicious == 0:
        return "✅"
    r = malicious / total
    if r < 0.05 or malicious <= 2:
        return "🟡"
    elif r < 0.20 or malicious <= 5:
        return "🟠"
    return "🔴"


def verdict_text(malicious: int, suspicious: int) -> str:
    if malicious == 0 and suspicious == 0:
        return "✅ *CLEAN*"
    elif malicious == 0:
        return "🟡 *SUSPICIOUS*"
    elif malicious <= 3:
        return "🟠 *LOW THREAT*"
    elif malicious <= 10:
        return "🔴 *THREAT DETECTED*"
    return "🚨 *HIGH THREAT — MALWARE*"


def stats_bar(stats: dict) -> str:
    m = stats.get("malicious", 0)
    s = stats.get("suspicious", 0)
    h = stats.get("harmless", 0)
    u = stats.get("undetected", 0)
    total = m + s + h + u or 1
    filled = round((m + s) / total * 20)
    return f"`[{'█' * filled}{'░' * (20 - filled)}]`"


def human_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def top_detections(results: dict, limit: int = 6) -> str:
    lines = [
        f"  • `{eng}`: {info.get('result', 'malicious')}"
        for eng, info in results.items()
        if info.get("category") in ("malicious", "suspicious")
    ][:limit]
    return "\n\n🔬 *Top Detections:*\n" + "\n".join(lines) if lines else ""


# ─────────────────────────────────────────────
#  VT API Calls
# ─────────────────────────────────────────────
async def vt_get(session: aiohttp.ClientSession, endpoint: str):
    async with session.get(f"{VT_BASE}{endpoint}", headers=VT_HEADERS) as r:
        return await r.json(), r.status


async def vt_post(session: aiohttp.ClientSession, endpoint: str, data: dict):
    async with session.post(f"{VT_BASE}{endpoint}", headers=VT_HEADERS, data=data) as r:
        return await r.json(), r.status


async def vt_upload_file(session: aiohttp.ClientSession, file_bytes: bytes, filename: str):
    form = aiohttp.FormData()
    form.add_field("file", file_bytes, filename=filename, content_type="application/octet-stream")
    async with session.post(f"{VT_BASE}/files", headers=VT_HEADERS, data=form) as r:
        return await r.json(), r.status


async def vt_poll(session: aiohttp.ClientSession, analysis_id: str):
    for _ in range(POLL_MAX_TRIES):
        data, status = await vt_get(session, f"/analyses/{analysis_id}")
        if status == 200:
            if data.get("data", {}).get("attributes", {}).get("status") == "completed":
                return data
        await asyncio.sleep(POLL_INTERVAL)
    return None


# ─────────────────────────────────────────────
#  Report Formatters
# ─────────────────────────────────────────────
def fmt_file(attrs: dict, filename: str = "Unknown") -> str:
    s = attrs.get("last_analysis_stats", {})
    m, sus, h, u = s.get("malicious", 0), s.get("suspicious", 0), s.get("harmless", 0), s.get("undetected", 0)
    total = m + sus + h + u
    return (
        f"{threat_emoji(m, total)} *VirusTotal File Report*\n"
        f"{'─'*30}\n"
        f"📄 *File:* `{str(attrs.get('meaningful_name', filename))[:50]}`\n"
        f"📦 *Size:* `{human_bytes(attrs.get('size', 0))}`\n"
        f"🗂 *Type:* `{attrs.get('type_description', attrs.get('magic','Unknown'))}`\n\n"
        f"🏁 *Verdict:* {verdict_text(m, sus)}\n"
        f"📊 *Detection:* `{m}/{total}` engines\n"
        f"{stats_bar(s)}\n\n"
        f"🟥 Malicious:  `{m}`\n"
        f"🟧 Suspicious: `{sus}`\n"
        f"🟩 Harmless:   `{h}`\n"
        f"⬜ Undetected: `{u}`\n\n"
        f"🔐 *Hashes:*\n"
        f"  MD5:    `{attrs.get('md5','N/A')}`\n"
        f"  SHA1:   `{attrs.get('sha1','N/A')}`\n"
        f"  SHA256: `{attrs.get('sha256','N/A')[:32]}...`"
        f"{top_detections(attrs.get('last_analysis_results',{}))}"
    )


def fmt_url(attrs: dict, url: str) -> str:
    s = attrs.get("last_analysis_stats", {})
    m, sus, h, u = s.get("malicious", 0), s.get("suspicious", 0), s.get("harmless", 0), s.get("undetected", 0)
    total = m + sus + h + u
    cats = ", ".join(set(attrs.get("categories", {}).values()))[:80] or "N/A"
    return (
        f"{threat_emoji(m, total)} *VirusTotal URL Report*\n"
        f"{'─'*30}\n"
        f"🔗 *URL:* `{url[:60]}{'...' if len(url)>60 else ''}`\n"
        f"📌 *Title:* `{str(attrs.get('title','N/A'))[:60]}`\n"
        f"🏷 *Category:* `{cats}`\n\n"
        f"🏁 *Verdict:* {verdict_text(m, sus)}\n"
        f"📊 *Detection:* `{m}/{total}` engines\n"
        f"{stats_bar(s)}\n\n"
        f"🟥 Malicious:  `{m}`\n"
        f"🟧 Suspicious: `{sus}`\n"
        f"🟩 Harmless:   `{h}`\n"
        f"⬜ Undetected: `{u}`"
        f"{top_detections(attrs.get('last_analysis_results',{}))}"
    )


def fmt_domain(attrs: dict, domain: str) -> str:
    s = attrs.get("last_analysis_stats", {})
    m, sus, h, u = s.get("malicious", 0), s.get("suspicious", 0), s.get("harmless", 0), s.get("undetected", 0)
    total = m + sus + h + u
    cats = ", ".join(set(attrs.get("categories", {}).values()))[:80] or "N/A"
    return (
        f"{threat_emoji(m, total)} *VirusTotal Domain Report*\n"
        f"{'─'*30}\n"
        f"🌐 *Domain:* `{domain}`\n"
        f"🏢 *Registrar:* `{str(attrs.get('registrar','N/A'))[:40]}`\n"
        f"🗓 *Created:* `{attrs.get('creation_date','N/A')}`\n"
        f"🌍 *Country:* `{attrs.get('country','N/A')}`\n"
        f"⭐ *Reputation:* `{attrs.get('reputation','N/A')}`\n"
        f"🏷 *Category:* `{cats}`\n\n"
        f"🏁 *Verdict:* {verdict_text(m, sus)}\n"
        f"📊 *Detection:* `{m}/{total}` engines\n"
        f"{stats_bar(s)}\n\n"
        f"🟥 Malicious:  `{m}`\n"
        f"🟧 Suspicious: `{sus}`\n"
        f"🟩 Harmless:   `{h}`\n"
        f"⬜ Undetected: `{u}`"
        f"{top_detections(attrs.get('last_analysis_results',{}))}"
    )


def fmt_ip(attrs: dict, ip: str) -> str:
    s = attrs.get("last_analysis_stats", {})
    m, sus, h, u = s.get("malicious", 0), s.get("suspicious", 0), s.get("harmless", 0), s.get("undetected", 0)
    total = m + sus + h + u
    return (
        f"{threat_emoji(m, total)} *VirusTotal IP Report*\n"
        f"{'─'*30}\n"
        f"📡 *IP:* `{ip}`\n"
        f"🌍 *Country:* `{attrs.get('country','N/A')}` ({attrs.get('continent','N/A')})\n"
        f"🏢 *ASN:* `AS{attrs.get('asn','N/A')}` — `{str(attrs.get('as_owner','N/A'))[:40]}`\n"
        f"🕸 *Network:* `{attrs.get('network','N/A')}`\n"
        f"⭐ *Reputation:* `{attrs.get('reputation','N/A')}`\n\n"
        f"🏁 *Verdict:* {verdict_text(m, sus)}\n"
        f"📊 *Detection:* `{m}/{total}` engines\n"
        f"{stats_bar(s)}\n\n"
        f"🟥 Malicious:  `{m}`\n"
        f"🟧 Suspicious: `{sus}`\n"
        f"🟩 Harmless:   `{h}`\n"
        f"⬜ Undetected: `{u}`"
        f"{top_detections(attrs.get('last_analysis_results',{}))}"
    )


# ─────────────────────────────────────────────
#  Keyboards
# ─────────────────────────────────────────────
def vt_btn(link: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([[InlineKeyboardButton("🔗 Full Report on VirusTotal", url=link)]])


def menu_kb() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("📁 File", callback_data="h_file"),
         InlineKeyboardButton("🔗 URL",  callback_data="h_url")],
        [InlineKeyboardButton("🔐 Hash", callback_data="h_hash"),
         InlineKeyboardButton("🌐 Domain", callback_data="h_domain")],
        [InlineKeyboardButton("📡 IP",   callback_data="h_ip"),
         InlineKeyboardButton("ℹ️ About", callback_data="h_about")],
    ])


# ─────────────────────────────────────────────
#  Stat tracker
# ─────────────────────────────────────────────
def track(ctx: ContextTypes.DEFAULT_TYPE, scan_type: str, threat: bool = False):
    d = ctx.user_data
    d["total"]   = d.get("total", 0) + 1
    d[scan_type] = d.get(scan_type, 0) + 1
    if threat:
        d["threats"] = d.get("threats", 0) + 1


# ─────────────────────────────────────────────
#  Handlers
# ─────────────────────────────────────────────
async def cmd_start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    u = update.effective_user
    await update.message.reply_text(
        f"🛡️ *VirusTotal Scanner Bot*\n"
        f"{'━'*30}\n\n"
        f"Hey {u.first_name}! I scan everything against *70+ AV engines*.\n\n"
        f"*Just send me:*\n"
        f"  📁 Any file (APK, EXE, PDF, ZIP...)\n"
        f"  🔗 A URL or link\n"
        f"  🔐 An MD5 / SHA1 / SHA256 hash\n"
        f"  🌐 A domain name\n"
        f"  📡 An IP address\n\n"
        f"No commands needed — just send it!",
        parse_mode=ParseMode.MARKDOWN,
        reply_markup=menu_kb(),
    )


async def cmd_help(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "🛡️ *VirusTotal Bot — Help*\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
        "📁 *File* — Send any attachment (max 32MB)\n"
        "🔗 *URL* — `https://example.com`\n"
        "🔐 *Hash* — MD5 / SHA1 / SHA256 directly\n"
        "🌐 *Domain* — `google.com`, `evil.xyz`\n"
        "📡 *IP* — `1.1.1.1`\n\n"
        "⚡ *Commands:*\n"
        "  /start /help /stats /about\n\n"
        "⚠️ Free VT API: 4 req/min, 500 req/day",
        parse_mode=ParseMode.MARKDOWN,
        reply_markup=menu_kb(),
    )


async def cmd_about(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "ℹ️ *VirusTotal Bot v2.0*\n\n"
        "• `python-telegram-bot` v22.7\n"
        "• VirusTotal API v3\n"
        "• Fully async (aiohttp)\n"
        "• Webhook mode + keep-alive\n"
        "• Hosted on Render.com (free)\n\n"
        "Powered by [VirusTotal](https://virustotal.com)",
        parse_mode=ParseMode.MARKDOWN,
    )


async def cmd_stats(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    d = ctx.user_data
    await update.message.reply_text(
        f"📊 *Your Scan Stats*\n"
        f"{'━'*24}\n\n"
        f"🔢 Total:    `{d.get('total',0)}`\n"
        f"📁 Files:    `{d.get('files',0)}`\n"
        f"🔗 URLs:     `{d.get('urls',0)}`\n"
        f"🔐 Hashes:   `{d.get('hashes',0)}`\n"
        f"🌐 Domains:  `{d.get('domains',0)}`\n"
        f"📡 IPs:      `{d.get('ips',0)}`\n\n"
        f"🚨 Threats:  `{d.get('threats',0)}`",
        parse_mode=ParseMode.MARKDOWN,
    )


async def callback_handler(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    tips = {
        "h_file":  "📁 *File Scan*\n\nJust send any file attachment.\nSupported: APK, EXE, PDF, ZIP, JS, PY, etc.\nMax: `32 MB`",
        "h_url":   "🔗 *URL Scan*\n\nSend:\n`https://suspicious.com`\n`http://malware.xyz/payload`",
        "h_hash":  "🔐 *Hash Lookup*\n\nSend an MD5, SHA1, or SHA256 hash.\nPrivate — no file upload needed!",
        "h_domain":"🌐 *Domain Check*\n\nSend:\n`malicious.domain.com`\n`phishing.xyz`",
        "h_ip":    "📡 *IP Check*\n\nSend:\n`192.168.1.1`\n`8.8.8.8`",
        "h_about": "ℹ️ *VirusTotal Bot v2.0*\n\npython-telegram-bot `22.7` + VT API v3\nWebhook + async + Render free tier",
    }
    await q.message.reply_text(tips.get(q.data, "?"), parse_mode=ParseMode.MARKDOWN)


# ─────────────────────────────────────────────
#  File Handler
# ─────────────────────────────────────────────
async def handle_file(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    msg = update.message
    doc = msg.document or msg.audio or msg.video
    if msg.photo:
        doc      = msg.photo[-1]
        filename = "photo.jpg"
    else:
        filename = getattr(doc, "file_name", None) or "file"

    file_size = getattr(doc, "file_size", 0) or 0
    if file_size > MAX_FILE_SIZE_MB * 1024 * 1024:
        await msg.reply_text(
            f"❌ File too large! Max `{MAX_FILE_SIZE_MB}MB`.\n"
            f"Your file: `{human_bytes(file_size)}`\n\n"
            f"💡 Send the SHA256 hash instead for a private lookup.",
            parse_mode=ParseMode.MARKDOWN,
        )
        return

    await msg.chat.send_action(ChatAction.UPLOAD_DOCUMENT)
    status = await msg.reply_text("⏳ *Downloading file...*", parse_mode=ParseMode.MARKDOWN)

    try:
        tg_file = await ctx.bot.get_file(doc.file_id)
        buf = io.BytesIO()
        await tg_file.download_to_memory(buf)
        file_bytes = buf.getvalue()
        sha256 = hashlib.sha256(file_bytes).hexdigest()

        await status.edit_text("🔬 *Uploading to VirusTotal...*", parse_mode=ParseMode.MARKDOWN)

        async with aiohttp.ClientSession() as session:
            resp, code = await vt_upload_file(session, file_bytes, filename)
            if code not in (200, 201):
                err = resp.get("error", {}).get("message", "Unknown error")
                await status.edit_text(f"❌ *VT Upload Failed:* `{err}`", parse_mode=ParseMode.MARKDOWN)
                return

            analysis_id = resp["data"]["id"]
            await status.edit_text(
                "⚙️ *Scanning with 70+ AV engines...*\n_Up to 2 minutes..._",
                parse_mode=ParseMode.MARKDOWN,
            )
            await vt_poll(session, analysis_id)

            full, s2 = await vt_get(session, f"/files/{sha256}")
            if s2 != 200:
                await status.edit_text("⏰ *Scan timed out.* Try again.", parse_mode=ParseMode.MARKDOWN)
                return
            attrs = full["data"]["attributes"]

        st = attrs.get("last_analysis_stats", {})
        track(ctx, "files", st.get("malicious", 0) > 0)
        await status.edit_text(
            fmt_file(attrs, filename),
            parse_mode=ParseMode.MARKDOWN,
            reply_markup=vt_btn(f"{VT_GUI}/file/{sha256}"),
        )

    except Exception as e:
        logger.error(f"File error: {e}", exc_info=True)
        await status.edit_text(f"❌ *Error:* `{str(e)[:200]}`", parse_mode=ParseMode.MARKDOWN)


# ─────────────────────────────────────────────
#  Text Handler
# ─────────────────────────────────────────────
async def handle_text(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    text = update.message.text.strip()

    if HASH_MD5.match(text) or HASH_SHA1.match(text) or HASH_SHA256.match(text):
        await do_hash(update, ctx, text)
    elif IP_PATTERN.match(text):
        await do_ip(update, ctx, text)
    elif text.startswith(("http://", "https://")):
        await do_url(update, ctx, text)
    elif DOMAIN_RE.match(text) and "." in text:
        if "/" in text:
            await do_url(update, ctx, "https://" + text)
        else:
            await do_domain(update, ctx, text)
    else:
        await update.message.reply_text(
            "🤔 *Not sure what to scan!*\n\n"
            "Send me a *file*, *URL*, *hash*, *domain*, or *IP*.\n"
            "Use /help for details.",
            parse_mode=ParseMode.MARKDOWN,
        )


async def do_url(update: Update, ctx: ContextTypes.DEFAULT_TYPE, url: str):
    status = await update.message.reply_text("🔗 *Scanning URL...*", parse_mode=ParseMode.MARKDOWN)
    try:
        async with aiohttp.ClientSession() as session:
            resp, code = await vt_post(session, "/urls", {"url": url})
            if code not in (200, 201):
                err = resp.get("error", {}).get("message", "Unknown")
                await status.edit_text(f"❌ `{err}`", parse_mode=ParseMode.MARKDOWN)
                return
            analysis_id = resp["data"]["id"]
            await status.edit_text("⚙️ *Analyzing URL...*", parse_mode=ParseMode.MARKDOWN)
            await vt_poll(session, analysis_id)
            url_id = urlsafe_b64encode(url.encode()).decode().rstrip("=")
            full, s2 = await vt_get(session, f"/urls/{url_id}")
            if s2 != 200:
                await status.edit_text("⏰ Timed out. Try again.", parse_mode=ParseMode.MARKDOWN)
                return
            attrs = full["data"]["attributes"]

        st = attrs.get("last_analysis_stats", {})
        track(ctx, "urls", st.get("malicious", 0) > 0)
        url_id = urlsafe_b64encode(url.encode()).decode().rstrip("=")
        await status.edit_text(
            fmt_url(attrs, url),
            parse_mode=ParseMode.MARKDOWN,
            reply_markup=vt_btn(f"{VT_GUI}/url/{url_id}"),
        )
    except Exception as e:
        logger.error(f"URL error: {e}", exc_info=True)
        await status.edit_text(f"❌ `{str(e)[:200]}`", parse_mode=ParseMode.MARKDOWN)


async def do_hash(update: Update, ctx: ContextTypes.DEFAULT_TYPE, h: str):
    htype = "MD5" if len(h) == 32 else "SHA1" if len(h) == 40 else "SHA256"
    status = await update.message.reply_text(f"🔐 *Looking up {htype}...*", parse_mode=ParseMode.MARKDOWN)
    try:
        async with aiohttp.ClientSession() as session:
            data, code = await vt_get(session, f"/files/{h}")
        if code == 404:
            await status.edit_text(
                "🔍 *Hash not found in VT database.*\nNever been scanned. Upload the actual file.",
                parse_mode=ParseMode.MARKDOWN,
            )
            return
        if code != 200:
            await status.edit_text(f"❌ `{data.get('error',{}).get('message','Error')}`", parse_mode=ParseMode.MARKDOWN)
            return
        attrs = data["data"]["attributes"]
        st = attrs.get("last_analysis_stats", {})
        track(ctx, "hashes", st.get("malicious", 0) > 0)
        await status.edit_text(
            fmt_file(attrs, h[:16] + "..."),
            parse_mode=ParseMode.MARKDOWN,
            reply_markup=vt_btn(f"{VT_GUI}/file/{h}"),
        )
    except Exception as e:
        await status.edit_text(f"❌ `{str(e)[:200]}`", parse_mode=ParseMode.MARKDOWN)


async def do_domain(update: Update, ctx: ContextTypes.DEFAULT_TYPE, domain: str):
    status = await update.message.reply_text("🌐 *Checking domain...*", parse_mode=ParseMode.MARKDOWN)
    try:
        async with aiohttp.ClientSession() as session:
            data, code = await vt_get(session, f"/domains/{domain}")
        if code == 404:
            await status.edit_text("🔍 Domain not in VT database.", parse_mode=ParseMode.MARKDOWN)
            return
        if code != 200:
            await status.edit_text(f"❌ `{data.get('error',{}).get('message','Error')}`", parse_mode=ParseMode.MARKDOWN)
            return
        attrs = data["data"]["attributes"]
        st = attrs.get("last_analysis_stats", {})
        track(ctx, "domains", st.get("malicious", 0) > 0)
        await status.edit_text(
            fmt_domain(attrs, domain),
            parse_mode=ParseMode.MARKDOWN,
            reply_markup=vt_btn(f"{VT_GUI}/domain/{domain}"),
        )
    except Exception as e:
        await status.edit_text(f"❌ `{str(e)[:200]}`", parse_mode=ParseMode.MARKDOWN)


async def do_ip(update: Update, ctx: ContextTypes.DEFAULT_TYPE, ip: str):
    status = await update.message.reply_text("📡 *Checking IP...*", parse_mode=ParseMode.MARKDOWN)
    try:
        async with aiohttp.ClientSession() as session:
            data, code = await vt_get(session, f"/ip_addresses/{ip}")
        if code != 200:
            await status.edit_text(f"❌ `{data.get('error',{}).get('message','Error')}`", parse_mode=ParseMode.MARKDOWN)
            return
        attrs = data["data"]["attributes"]
        st = attrs.get("last_analysis_stats", {})
        track(ctx, "ips", st.get("malicious", 0) > 0)
        await status.edit_text(
            fmt_ip(attrs, ip),
            parse_mode=ParseMode.MARKDOWN,
            reply_markup=vt_btn(f"{VT_GUI}/ip-address/{ip}"),
        )
    except Exception as e:
        await status.edit_text(f"❌ `{str(e)[:200]}`", parse_mode=ParseMode.MARKDOWN)


# ─────────────────────────────────────────────
#  Error Handler
# ─────────────────────────────────────────────
async def error_handler(update: object, ctx: ContextTypes.DEFAULT_TYPE):
    logger.error("Update error:", exc_info=ctx.error)
    if isinstance(update, Update) and update.message:
        await update.message.reply_text("⚠️ Something went wrong. Please try again.")


# ─────────────────────────────────────────────
#  Self-Ping Keep-Alive (prevents Render sleep)
# ─────────────────────────────────────────────
async def self_ping_loop():
    """Pings own health endpoint every 13 minutes to prevent Render free tier sleep."""
    if not RENDER_URL:
        logger.info("No RENDER_URL set — skipping self-ping.")
        return
    await asyncio.sleep(60)  # initial delay
    async with aiohttp.ClientSession() as session:
        while True:
            try:
                async with session.get(f"{RENDER_URL}/health", timeout=aiohttp.ClientTimeout(total=10)) as r:
                    logger.info(f"Self-ping: {r.status}")
            except Exception as e:
                logger.warning(f"Self-ping failed: {e}")
            await asyncio.sleep(13 * 60)  # 13 minutes


# ─────────────────────────────────────────────
#  aiohttp Web App (health + webhook)
# ─────────────────────────────────────────────
async def build_app(ptb_app: Application) -> web.Application:
    async def health(request):
        return web.Response(text="🛡️ VT Bot is alive!", content_type="text/plain")

    async def webhook(request):
        try:
            data = await request.json()
            update = Update.de_json(data, ptb_app.bot)
            await ptb_app.process_update(update)
        except Exception as e:
            logger.error(f"Webhook error: {e}", exc_info=True)
        return web.Response(text="OK")

    app = web.Application()
    app.router.add_get("/",         health)
    app.router.add_get("/health",   health)
    app.router.add_post(WEBHOOK_PATH, webhook)
    return app


# ─────────────────────────────────────────────
#  Main
# ─────────────────────────────────────────────
async def main():
    logger.info("🛡️  VirusTotal Bot starting up...")

    # Build PTB app
    ptb_app = (
        ApplicationBuilder()
        .token(BOT_TOKEN)
        .concurrent_updates(True)
        .build()
    )

    # Register handlers
    ptb_app.add_handler(CommandHandler("start", cmd_start))
    ptb_app.add_handler(CommandHandler("help",  cmd_help))
    ptb_app.add_handler(CommandHandler("about", cmd_about))
    ptb_app.add_handler(CommandHandler("stats", cmd_stats))
    ptb_app.add_handler(CallbackQueryHandler(callback_handler))
    ptb_app.add_handler(MessageHandler(filters.Document.ALL | filters.AUDIO | filters.VIDEO | filters.PHOTO, handle_file))
    ptb_app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))
    ptb_app.add_error_handler(error_handler)

    await ptb_app.initialize()
    await ptb_app.start()

    # Set webhook
    if RENDER_URL:
        await ptb_app.bot.set_webhook(
            url=WEBHOOK_URL,
            allowed_updates=Update.ALL_TYPES,
            drop_pending_updates=True,
        )
        logger.info(f"Webhook set: {WEBHOOK_URL}")
    else:
        logger.warning("RENDER_URL not set — webhook NOT registered with Telegram!")

    # Start web server
    web_app  = await build_app(ptb_app)
    runner   = web.AppRunner(web_app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", PORT)
    await site.start()
    logger.info(f"Web server on port {PORT}")

    # Start keep-alive pinger
    asyncio.create_task(self_ping_loop())

    logger.info("✅ Bot is live!")
    try:
        await asyncio.Event().wait()
    finally:
        await ptb_app.bot.delete_webhook()
        await ptb_app.stop()
        await ptb_app.shutdown()
        await runner.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
