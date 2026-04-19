"""
╔══════════════════════════════════════════════════════╗
║         🛡️  VirusTotal Telegram Bot v1.0             ║
║     Built with python-telegram-bot 22.7 + VT API v3  ║
║         Async • Production-Ready • Render-Ready       ║
╚══════════════════════════════════════════════════════╝
"""

import asyncio
import hashlib
import io
import logging
import os
import re
import time
from base64 import urlsafe_b64encode
from typing import Optional

import aiohttp
from aiohttp import web
from telegram import (
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    Message,
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
#  Logging Setup
# ─────────────────────────────────────────────
logging.basicConfig(
    format="%(asctime)s | %(name)s | %(levelname)s | %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)
logging.getLogger("httpx").setLevel(logging.WARNING)

# ─────────────────────────────────────────────
#  Environment Variables
# ─────────────────────────────────────────────
BOT_TOKEN: str = os.environ["BOT_TOKEN"]
VT_API_KEY: str = os.environ["VT_API_KEY"]
PORT: int = int(os.getenv("PORT", "8080"))
MAX_FILE_SIZE_MB: int = int(os.getenv("MAX_FILE_SIZE_MB", "32"))

# ─────────────────────────────────────────────
#  VirusTotal API v3 Base
# ─────────────────────────────────────────────
VT_BASE = "https://www.virustotal.com/api/v3"
VT_HEADERS = {"x-apikey": VT_API_KEY, "Accept": "application/json"}
VT_GUI_BASE = "https://www.virustotal.com/gui"

# Rate limit: free tier = 4 requests/minute, 500/day
POLL_INTERVAL = 5      # seconds between analysis polls
POLL_MAX_TRIES = 24    # max 2 minutes wait


# ─────────────────────────────────────────────
#  Utility: Regex Patterns
# ─────────────────────────────────────────────
HASH_MD5    = re.compile(r"^[a-fA-F0-9]{32}$")
HASH_SHA1   = re.compile(r"^[a-fA-F0-9]{40}$")
HASH_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")
URL_PATTERN = re.compile(
    r"(https?://[^\s]+|[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(/[^\s]*)?)"
)
IP_PATTERN  = re.compile(
    r"^(\d{1,3}\.){3}\d{1,3}$"
)
DOMAIN_PATTERN = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


# ─────────────────────────────────────────────
#  Emoji Threat Indicators
# ─────────────────────────────────────────────
def threat_emoji(malicious: int, total: int) -> str:
    if total == 0:
        return "⚪"
    ratio = malicious / total
    if malicious == 0:
        return "✅"
    elif ratio < 0.05 or malicious <= 2:
        return "🟡"
    elif ratio < 0.20 or malicious <= 5:
        return "🟠"
    else:
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
    else:
        return "🚨 *HIGH THREAT — MALWARE*"


def format_stats_bar(stats: dict) -> str:
    malicious   = stats.get("malicious", 0)
    suspicious  = stats.get("suspicious", 0)
    harmless    = stats.get("harmless", 0)
    undetected  = stats.get("undetected", 0)
    timeout     = stats.get("timeout", 0)
    total = malicious + suspicious + harmless + undetected + timeout or 1
    bar_len = 20
    filled = round((malicious + suspicious) / total * bar_len)
    bar = "█" * filled + "░" * (bar_len - filled)
    return f"`[{bar}]`"


def bytes_to_human(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


# ─────────────────────────────────────────────
#  VirusTotal API Calls (async)
# ─────────────────────────────────────────────
async def vt_get(session: aiohttp.ClientSession, endpoint: str) -> dict:
    async with session.get(f"{VT_BASE}{endpoint}", headers=VT_HEADERS) as r:
        return await r.json(), r.status


async def vt_post_json(session: aiohttp.ClientSession, endpoint: str, data: dict) -> dict:
    async with session.post(
        f"{VT_BASE}{endpoint}", headers=VT_HEADERS, data=data
    ) as r:
        return await r.json(), r.status


async def vt_post_file(
    session: aiohttp.ClientSession, file_bytes: bytes, filename: str
) -> dict:
    form = aiohttp.FormData()
    form.add_field("file", file_bytes, filename=filename, content_type="application/octet-stream")
    async with session.post(
        f"{VT_BASE}/files", headers=VT_HEADERS, data=form
    ) as r:
        return await r.json(), r.status


async def vt_poll_analysis(
    session: aiohttp.ClientSession, analysis_id: str
) -> Optional[dict]:
    """Poll /analyses/{id} until completed or timeout."""
    for _ in range(POLL_MAX_TRIES):
        data, status = await vt_get(session, f"/analyses/{analysis_id}")
        if status == 200:
            attrs = data.get("data", {}).get("attributes", {})
            if attrs.get("status") == "completed":
                return data
        await asyncio.sleep(POLL_INTERVAL)
    return None


# ─────────────────────────────────────────────
#  Result Formatters
# ─────────────────────────────────────────────
def format_file_report(attrs: dict, filename: str = "Unknown") -> str:
    stats       = attrs.get("last_analysis_stats", {})
    malicious   = stats.get("malicious", 0)
    suspicious  = stats.get("suspicious", 0)
    harmless    = stats.get("harmless", 0)
    undetected  = stats.get("undetected", 0)
    total       = malicious + suspicious + harmless + undetected

    md5    = attrs.get("md5", "N/A")
    sha1   = attrs.get("sha1", "N/A")
    sha256 = attrs.get("sha256", "N/A")
    size   = attrs.get("size", 0)
    ftype  = attrs.get("type_description", attrs.get("magic", "Unknown"))
    names  = attrs.get("meaningful_name", filename)

    # Top detected threats
    results      = attrs.get("last_analysis_results", {})
    detections   = [
        f"  • `{engine}`: {info.get('result', 'malicious')}"
        for engine, info in results.items()
        if info.get("category") in ("malicious", "suspicious")
    ][:8]  # cap at 8

    detection_block = ""
    if detections:
        detection_block = "\n\n🔬 *Top Detections:*\n" + "\n".join(detections)

    verdict = verdict_text(malicious, suspicious)
    bar     = format_stats_bar(stats)
    emoji   = threat_emoji(malicious, total)

    return (
        f"{emoji} *VirusTotal File Report*\n"
        f"{'─' * 30}\n"
        f"📄 *File:* `{names[:50]}`\n"
        f"📦 *Size:* `{bytes_to_human(size)}`\n"
        f"🗂 *Type:* `{ftype}`\n\n"
        f"🏁 *Verdict:* {verdict}\n"
        f"📊 *Detection:* `{malicious}/{total}` engines\n"
        f"{bar}\n\n"
        f"🟥 Malicious:  `{malicious}`\n"
        f"🟧 Suspicious: `{suspicious}`\n"
        f"🟩 Harmless:   `{harmless}`\n"
        f"⬜ Undetected: `{undetected}`\n\n"
        f"🔐 *Hashes:*\n"
        f"  MD5:    `{md5}`\n"
        f"  SHA1:   `{sha1}`\n"
        f"  SHA256: `{sha256[:32]}...`"
        f"{detection_block}"
    )


def format_url_report(attrs: dict, url: str) -> str:
    stats       = attrs.get("last_analysis_stats", {})
    malicious   = stats.get("malicious", 0)
    suspicious  = stats.get("suspicious", 0)
    harmless    = stats.get("harmless", 0)
    undetected  = stats.get("undetected", 0)
    total       = malicious + suspicious + harmless + undetected

    categories  = attrs.get("categories", {})
    cat_str     = ", ".join(set(categories.values()))[:80] if categories else "N/A"
    final_url   = attrs.get("last_final_url", url)[:80]
    title       = attrs.get("title", "N/A")[:60]

    results     = attrs.get("last_analysis_results", {})
    detections  = [
        f"  • `{engine}`: {info.get('result', 'malicious')}"
        for engine, info in results.items()
        if info.get("category") in ("malicious", "suspicious")
    ][:6]

    detection_block = ""
    if detections:
        detection_block = "\n\n🔬 *Flagged By:*\n" + "\n".join(detections)

    verdict = verdict_text(malicious, suspicious)
    bar     = format_stats_bar(stats)
    emoji   = threat_emoji(malicious, total)

    return (
        f"{emoji} *VirusTotal URL Report*\n"
        f"{'─' * 30}\n"
        f"🔗 *URL:* `{url[:60]}{'...' if len(url)>60 else ''}`\n"
        f"📌 *Title:* `{title}`\n"
        f"🏷 *Category:* `{cat_str}`\n\n"
        f"🏁 *Verdict:* {verdict}\n"
        f"📊 *Detection:* `{malicious}/{total}` engines\n"
        f"{bar}\n\n"
        f"🟥 Malicious:  `{malicious}`\n"
        f"🟧 Suspicious: `{suspicious}`\n"
        f"🟩 Harmless:   `{harmless}`\n"
        f"⬜ Undetected: `{undetected}`"
        f"{detection_block}"
    )


def format_domain_report(attrs: dict, domain: str) -> str:
    stats       = attrs.get("last_analysis_stats", {})
    malicious   = stats.get("malicious", 0)
    suspicious  = stats.get("suspicious", 0)
    harmless    = stats.get("harmless", 0)
    undetected  = stats.get("undetected", 0)
    total       = malicious + suspicious + harmless + undetected

    registrar   = attrs.get("registrar", "N/A")
    creation    = attrs.get("creation_date", "N/A")
    categories  = attrs.get("categories", {})
    cat_str     = ", ".join(set(categories.values()))[:80] if categories else "N/A"
    country     = attrs.get("country", "N/A")
    rep_score   = attrs.get("reputation", "N/A")

    results     = attrs.get("last_analysis_results", {})
    detections  = [
        f"  • `{engine}`: {info.get('result','malicious')}"
        for engine, info in results.items()
        if info.get("category") in ("malicious", "suspicious")
    ][:6]

    detection_block = ""
    if detections:
        detection_block = "\n\n🔬 *Flagged By:*\n" + "\n".join(detections)

    verdict = verdict_text(malicious, suspicious)
    bar     = format_stats_bar(stats)
    emoji   = threat_emoji(malicious, total)

    return (
        f"{emoji} *VirusTotal Domain Report*\n"
        f"{'─' * 30}\n"
        f"🌐 *Domain:* `{domain}`\n"
        f"🏢 *Registrar:* `{str(registrar)[:40]}`\n"
        f"🗓 *Created:* `{creation}`\n"
        f"🌍 *Country:* `{country}`\n"
        f"⭐ *Reputation:* `{rep_score}`\n"
        f"🏷 *Category:* `{cat_str}`\n\n"
        f"🏁 *Verdict:* {verdict}\n"
        f"📊 *Detection:* `{malicious}/{total}` engines\n"
        f"{bar}\n\n"
        f"🟥 Malicious:  `{malicious}`\n"
        f"🟧 Suspicious: `{suspicious}`\n"
        f"🟩 Harmless:   `{harmless}`\n"
        f"⬜ Undetected: `{undetected}`"
        f"{detection_block}"
    )


def format_ip_report(attrs: dict, ip: str) -> str:
    stats       = attrs.get("last_analysis_stats", {})
    malicious   = stats.get("malicious", 0)
    suspicious  = stats.get("suspicious", 0)
    harmless    = stats.get("harmless", 0)
    undetected  = stats.get("undetected", 0)
    total       = malicious + suspicious + harmless + undetected

    country     = attrs.get("country", "N/A")
    asn         = attrs.get("asn", "N/A")
    as_owner    = attrs.get("as_owner", "N/A")[:40]
    network     = attrs.get("network", "N/A")
    rep_score   = attrs.get("reputation", "N/A")
    continent   = attrs.get("continent", "N/A")

    results     = attrs.get("last_analysis_results", {})
    detections  = [
        f"  • `{engine}`: {info.get('result','malicious')}"
        for engine, info in results.items()
        if info.get("category") in ("malicious", "suspicious")
    ][:6]

    detection_block = ""
    if detections:
        detection_block = "\n\n🔬 *Flagged By:*\n" + "\n".join(detections)

    verdict = verdict_text(malicious, suspicious)
    bar     = format_stats_bar(stats)
    emoji   = threat_emoji(malicious, total)

    return (
        f"{emoji} *VirusTotal IP Report*\n"
        f"{'─' * 30}\n"
        f"📡 *IP Address:* `{ip}`\n"
        f"🌍 *Country:* `{country}` ({continent})\n"
        f"🏢 *ASN:* `AS{asn}` — `{as_owner}`\n"
        f"🕸 *Network:* `{network}`\n"
        f"⭐ *Reputation:* `{rep_score}`\n\n"
        f"🏁 *Verdict:* {verdict}\n"
        f"📊 *Detection:* `{malicious}/{total}` engines\n"
        f"{bar}\n\n"
        f"🟥 Malicious:  `{malicious}`\n"
        f"🟧 Suspicious: `{suspicious}`\n"
        f"🟩 Harmless:   `{harmless}`\n"
        f"⬜ Undetected: `{undetected}`"
        f"{detection_block}"
    )


def format_hash_report(attrs: dict, hash_val: str) -> str:
    return format_file_report(attrs, filename=hash_val[:16] + "...")


# ─────────────────────────────────────────────
#  Keyboards
# ─────────────────────────────────────────────
def vt_link_keyboard(link: str, label: str = "🔗 View Full Report on VT") -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([[InlineKeyboardButton(label, url=link)]])


def main_menu_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("📁 Scan File",   callback_data="help_file"),
            InlineKeyboardButton("🔗 Scan URL",    callback_data="help_url"),
        ],
        [
            InlineKeyboardButton("🔐 Check Hash",  callback_data="help_hash"),
            InlineKeyboardButton("🌐 Check Domain",callback_data="help_domain"),
        ],
        [
            InlineKeyboardButton("📡 Check IP",    callback_data="help_ip"),
            InlineKeyboardButton("ℹ️ About",        callback_data="about"),
        ],
    ])


# ─────────────────────────────────────────────
#  /start Handler
# ─────────────────────────────────────────────
async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user = update.effective_user
    text = (
        f"🛡️ *VirusTotal Scanner Bot*\n"
        f"{'━' * 32}\n\n"
        f"Hey {user.mention_markdown_v2()}\\!\n\n"
        f"I scan *files, URLs, hashes, domains & IPs* against\n"
        f"**70\\+ antivirus engines** powered by VirusTotal API v3\\.\n\n"
        f"📌 *What I can do:*\n"
        f"  📁 Upload any file \\(APK, EXE, PDF, ZIP\\.\\.\\.\\)\n"
        f"  🔗 Paste a URL or link\n"
        f"  🔐 Send an MD5/SHA1/SHA256 hash\n"
        f"  🌐 Enter a domain name\n"
        f"  📡 Enter an IP address\n\n"
        f"Just send it — no commands needed\\!\n"
        f"Or tap a button below to learn more\\."
    )
    await update.message.reply_text(
        text,
        parse_mode=ParseMode.MARKDOWN_V2,
        reply_markup=main_menu_keyboard(),
    )


# ─────────────────────────────────────────────
#  /help Handler
# ─────────────────────────────────────────────
async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    text = (
        "🛡️ *VirusTotal Bot — Help*\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
        "📁 *Scan a File*\n"
        "  Just send any file\\. Max 32MB for free tier\\.\n\n"
        "🔗 *Scan a URL*\n"
        "  Send: `https://example.com` or just `example.com`\n\n"
        "🔐 *Check a Hash*\n"
        "  Send MD5, SHA1, or SHA256 hash directly\\.\n\n"
        "🌐 *Check a Domain*\n"
        "  Send: `google.com` or `suspicious.xyz`\n\n"
        "📡 *Check an IP*\n"
        "  Send: `1.1.1.1` or any IPv4 address\n\n"
        "⚡ *Commands:*\n"
        "  /start — Welcome screen\n"
        "  /help — This menu\n"
        "  /stats — Your scan stats\n"
        "  /about — About this bot\n\n"
        "⚠️ *Note:* Free VT API = 4 req/min & 500 req/day\\."
    )
    await update.message.reply_text(
        text,
        parse_mode=ParseMode.MARKDOWN_V2,
        reply_markup=main_menu_keyboard(),
    )


# ─────────────────────────────────────────────
#  /about Handler
# ─────────────────────────────────────────────
async def cmd_about(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    text = (
        "ℹ️ *About VirusTotal Bot*\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
        "🔧 *Stack:*\n"
        "  • python\\-telegram\\-bot `v22.7`\n"
        "  • VirusTotal API `v3`\n"
        "  • Python `3.11+`\n"
        "  • aiohttp \\(fully async\\)\n\n"
        "🚀 *Hosted on:* Render\\.com \\(free tier\\)\n\n"
        "📊 *Coverage:* 70\\+ AV engines\n"
        "🔒 *Privacy:* Files are shared with VT partners\\.\n"
        "  Use hashes for private lookups\\.\n\n"
        "🛡 Powered by [VirusTotal](https://virustotal.com)"
    )
    await update.message.reply_text(
        text,
        parse_mode=ParseMode.MARKDOWN_V2,
    )


# ─────────────────────────────────────────────
#  /stats Handler
# ─────────────────────────────────────────────
async def cmd_stats(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    data = context.user_data
    total    = data.get("scans_total", 0)
    files    = data.get("scans_files", 0)
    urls     = data.get("scans_urls", 0)
    hashes   = data.get("scans_hashes", 0)
    domains  = data.get("scans_domains", 0)
    ips      = data.get("scans_ips", 0)
    threats  = data.get("threats_found", 0)

    text = (
        f"📊 *Your Scan Statistics*\n"
        f"{'━' * 28}\n\n"
        f"🔢 *Total Scans:* `{total}`\n\n"
        f"📁 Files:    `{files}`\n"
        f"🔗 URLs:     `{urls}`\n"
        f"🔐 Hashes:   `{hashes}`\n"
        f"🌐 Domains:  `{domains}`\n"
        f"📡 IPs:      `{ips}`\n\n"
        f"🚨 *Threats Found:* `{threats}`\n"
    )
    await update.message.reply_text(text, parse_mode=ParseMode.MARKDOWN)


# ─────────────────────────────────────────────
#  Callback Query Handler (inline buttons)
# ─────────────────────────────────────────────
async def callback_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    await query.answer()

    help_texts = {
        "help_file": (
            "📁 *How to Scan a File*\n\n"
            "Just send or forward any file to this chat\\.\n"
            "Supported: APK, EXE, PDF, ZIP, DOCX, JS, PY\\.\\.\\.\n"
            "Max size: `32 MB` \\(free API limit\\)\n\n"
            "I'll upload it to VirusTotal and return a full report\\."
        ),
        "help_url": (
            "🔗 *How to Scan a URL*\n\n"
            "Send a URL like:\n"
            "`https://suspicious\\-site\\.com`\n"
            "`http://malware\\.example\\.org/payload`\n\n"
            "Or even bare domains like `phishing\\.xyz`"
        ),
        "help_hash": (
            "🔐 *How to Check a Hash*\n\n"
            "Send a file hash directly:\n"
            "`d41d8cd98f00b204e9800998ecf8427e` \\(MD5\\)\n"
            "`da39a3ee5e6b4b0d3255bfef95601890afd80709` \\(SHA1\\)\n"
            "`e3b0c44298fc1c149afb...` \\(SHA256\\)\n\n"
            "This is the most private way — no file upload needed\\!"
        ),
        "help_domain": (
            "🌐 *How to Check a Domain*\n\n"
            "Send a domain name:\n"
            "`malicious\\.domain\\.com`\n"
            "`suspicious\\.xyz`\n\n"
            "Returns registrar info, reputation, and AV verdicts\\."
        ),
        "help_ip": (
            "📡 *How to Check an IP*\n\n"
            "Send an IPv4 address:\n"
            "`192\\.168\\.1\\.1`\n"
            "`8\\.8\\.8\\.8`\n\n"
            "Returns ASN, country, reputation, and AV verdicts\\."
        ),
        "about": (
            "ℹ️ *VirusTotal Bot*\n\n"
            "Built with `python\\-telegram\\-bot 22\\.7` \\+ VT API v3\\.\n"
            "Async • Production\\-grade • Hosted on Render\\."
        ),
    }

    msg = help_texts.get(query.data, "Unknown action")
    await query.message.reply_text(msg, parse_mode=ParseMode.MARKDOWN_V2)


# ─────────────────────────────────────────────
#  Scan stat tracker
# ─────────────────────────────────────────────
def track_scan(context: ContextTypes.DEFAULT_TYPE, scan_type: str, threat: bool = False):
    d = context.user_data
    d["scans_total"]    = d.get("scans_total", 0) + 1
    d[f"scans_{scan_type}"] = d.get(f"scans_{scan_type}", 0) + 1
    if threat:
        d["threats_found"] = d.get("threats_found", 0) + 1


# ─────────────────────────────────────────────
#  File Handler
# ─────────────────────────────────────────────
async def handle_file(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    message = update.message
    doc = message.document or message.audio or message.video or message.photo

    # Resolve correct file object
    if message.photo:
        doc = message.photo[-1]
        filename = "photo.jpg"
    else:
        filename = getattr(doc, "file_name", None) or "unknown_file"

    file_size = getattr(doc, "file_size", 0) or 0
    max_bytes = MAX_FILE_SIZE_MB * 1024 * 1024

    if file_size > max_bytes:
        await message.reply_text(
            f"❌ File too large\\! Max `{MAX_FILE_SIZE_MB}MB` for free VT API\\.\n"
            f"Your file: `{bytes_to_human(file_size)}`\n\n"
            f"💡 Tip: Send the file's SHA256 hash instead for a lookup\\.",
            parse_mode=ParseMode.MARKDOWN_V2,
        )
        return

    await message.chat.send_action(ChatAction.UPLOAD_DOCUMENT)
    status_msg = await message.reply_text(
        "⏳ *Downloading file\\.\\.\\.*", parse_mode=ParseMode.MARKDOWN_V2
    )

    try:
        tg_file = await context.bot.get_file(doc.file_id)
        buf = io.BytesIO()
        await tg_file.download_to_memory(buf)
        file_bytes = buf.getvalue()

        # Compute hash for VT GUI link
        sha256 = hashlib.sha256(file_bytes).hexdigest()
        vt_link = f"{VT_GUI_BASE}/file/{sha256}"

        await status_msg.edit_text(
            "🔬 *Uploading to VirusTotal\\.\\.\\.*", parse_mode=ParseMode.MARKDOWN_V2
        )

        async with aiohttp.ClientSession() as session:
            resp, status = await vt_post_file(session, file_bytes, filename)

            if status not in (200, 201):
                err = resp.get("error", {}).get("message", "Unknown error")
                await status_msg.edit_text(
                    f"❌ *VT Upload Failed:* `{err}`", parse_mode=ParseMode.MARKDOWN_V2
                )
                return

            analysis_id = resp["data"]["id"]

            await status_msg.edit_text(
                "⚙️ *Scanning with 70\\+ AV engines\\.\\.\\.*\n"
                "_This may take up to 2 minutes\\._",
                parse_mode=ParseMode.MARKDOWN_V2,
            )

            result = await vt_poll_analysis(session, analysis_id)

            if not result:
                # Try fetching by hash directly
                result, s2 = await vt_get(session, f"/files/{sha256}")
                if s2 != 200:
                    await status_msg.edit_text(
                        "⏰ *Scan timed out\\.* Try again in a minute\\.",
                        parse_mode=ParseMode.MARKDOWN_V2,
                    )
                    return
                attrs = result["data"]["attributes"]
            else:
                # Get full file report by hash
                full, _ = await vt_get(session, f"/files/{sha256}")
                attrs = full.get("data", {}).get("attributes", result["data"]["attributes"])

        report  = format_file_report(attrs, filename)
        stats   = attrs.get("last_analysis_stats", {})
        threat  = stats.get("malicious", 0) > 0 or stats.get("suspicious", 0) > 0

        track_scan(context, "files", threat)

        await status_msg.edit_text(
            report,
            parse_mode=ParseMode.MARKDOWN,
            reply_markup=vt_link_keyboard(vt_link),
        )

    except Exception as e:
        logger.error(f"File scan error: {e}", exc_info=True)
        await status_msg.edit_text(
            f"❌ *Error:* `{str(e)[:200]}`", parse_mode=ParseMode.MARKDOWN_V2
        )


# ─────────────────────────────────────────────
#  Text Handler — detects URL / Hash / IP / Domain
# ─────────────────────────────────────────────
async def handle_text(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    text = update.message.text.strip()

    # ── Hash ──
    if HASH_MD5.match(text) or HASH_SHA1.match(text) or HASH_SHA256.match(text):
        await scan_hash(update, context, text)
        return

    # ── IP ──
    if IP_PATTERN.match(text):
        await scan_ip(update, context, text)
        return

    # ── URL (with scheme) ──
    if text.startswith(("http://", "https://")):
        await scan_url(update, context, text)
        return

    # ── Domain ──
    if DOMAIN_PATTERN.match(text) and "." in text:
        # Heuristic: if it looks like a URL without scheme
        if "/" in text or text.count(".") >= 1:
            # Could be domain or URL — check for path
            if re.match(r"^[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$", text):
                await scan_domain(update, context, text)
            else:
                await scan_url(update, context, "https://" + text)
            return

    # ── Fallback ──
    await update.message.reply_text(
        "🤔 *I couldn't identify what to scan\\!*\n\n"
        "Send me:\n"
        "• A *file* attachment\n"
        "• A *URL*: `https://example.com`\n"
        "• A *hash*: MD5 / SHA1 / SHA256\n"
        "• A *domain*: `google.com`\n"
        "• An *IP*: `1.1.1.1`\n\n"
        "Use /help for details\\.",
        parse_mode=ParseMode.MARKDOWN_V2,
    )


# ─────────────────────────────────────────────
#  Scan: URL
# ─────────────────────────────────────────────
async def scan_url(update: Update, context: ContextTypes.DEFAULT_TYPE, url: str) -> None:
    status_msg = await update.message.reply_text(
        "🔗 *Scanning URL\\.\\.\\.*", parse_mode=ParseMode.MARKDOWN_V2
    )
    try:
        async with aiohttp.ClientSession() as session:
            # Submit URL
            resp, status = await vt_post_json(session, "/urls", {"url": url})
            if status not in (200, 201):
                err = resp.get("error", {}).get("message", "Unknown error")
                await status_msg.edit_text(
                    f"❌ *Error:* `{err}`", parse_mode=ParseMode.MARKDOWN_V2
                )
                return

            analysis_id = resp["data"]["id"]
            await status_msg.edit_text(
                "⚙️ *Analyzing URL\\.\\.\\.*", parse_mode=ParseMode.MARKDOWN_V2
            )

            result = await vt_poll_analysis(session, analysis_id)

            # Get full URL report using URL ID
            url_id = urlsafe_b64encode(url.encode()).decode().rstrip("=")
            full, s2 = await vt_get(session, f"/urls/{url_id}")

            if s2 == 200:
                attrs = full["data"]["attributes"]
            elif result:
                attrs = result["data"]["attributes"]
            else:
                await status_msg.edit_text(
                    "⏰ *Scan timed out\\.* Try again\\.", parse_mode=ParseMode.MARKDOWN_V2
                )
                return

        report  = format_url_report(attrs, url)
        stats   = attrs.get("last_analysis_stats", {})
        threat  = stats.get("malicious", 0) > 0

        track_scan(context, "urls", threat)
        vt_link = f"{VT_GUI_BASE}/url/{url_id}"

        await status_msg.edit_text(
            report,
            parse_mode=ParseMode.MARKDOWN,
            reply_markup=vt_link_keyboard(vt_link),
        )

    except Exception as e:
        logger.error(f"URL scan error: {e}", exc_info=True)
        await status_msg.edit_text(
            f"❌ *Error:* `{str(e)[:200]}`", parse_mode=ParseMode.MARKDOWN_V2
        )


# ─────────────────────────────────────────────
#  Scan: Hash
# ─────────────────────────────────────────────
async def scan_hash(update: Update, context: ContextTypes.DEFAULT_TYPE, hash_val: str) -> None:
    hash_type = (
        "MD5"    if len(hash_val) == 32 else
        "SHA1"   if len(hash_val) == 40 else
        "SHA256"
    )
    status_msg = await update.message.reply_text(
        f"🔐 *Looking up {hash_type} hash\\.\\.\\.*",
        parse_mode=ParseMode.MARKDOWN_V2,
    )
    try:
        async with aiohttp.ClientSession() as session:
            data, status = await vt_get(session, f"/files/{hash_val}")

        if status == 404:
            await status_msg.edit_text(
                f"🔍 *Hash not in VirusTotal database\\.* \n\n"
                f"This file has never been scanned before\\.\n"
                f"Upload the actual file for a fresh scan\\.",
                parse_mode=ParseMode.MARKDOWN_V2,
            )
            return

        if status != 200:
            err = data.get("error", {}).get("message", "Unknown error")
            await status_msg.edit_text(
                f"❌ *Error:* `{err}`", parse_mode=ParseMode.MARKDOWN_V2
            )
            return

        attrs   = data["data"]["attributes"]
        report  = format_hash_report(attrs, hash_val)
        stats   = attrs.get("last_analysis_stats", {})
        threat  = stats.get("malicious", 0) > 0

        track_scan(context, "hashes", threat)
        vt_link = f"{VT_GUI_BASE}/file/{hash_val}"

        await status_msg.edit_text(
            report,
            parse_mode=ParseMode.MARKDOWN,
            reply_markup=vt_link_keyboard(vt_link),
        )

    except Exception as e:
        logger.error(f"Hash scan error: {e}", exc_info=True)
        await status_msg.edit_text(
            f"❌ *Error:* `{str(e)[:200]}`", parse_mode=ParseMode.MARKDOWN_V2
        )


# ─────────────────────────────────────────────
#  Scan: Domain
# ─────────────────────────────────────────────
async def scan_domain(update: Update, context: ContextTypes.DEFAULT_TYPE, domain: str) -> None:
    status_msg = await update.message.reply_text(
        "🌐 *Checking domain\\.\\.\\.*", parse_mode=ParseMode.MARKDOWN_V2
    )
    try:
        async with aiohttp.ClientSession() as session:
            data, status = await vt_get(session, f"/domains/{domain}")

        if status == 404:
            await status_msg.edit_text(
                "🔍 *Domain not found in VT database\\.* Try a URL scan instead\\.",
                parse_mode=ParseMode.MARKDOWN_V2,
            )
            return

        if status != 200:
            err = data.get("error", {}).get("message", "Unknown error")
            await status_msg.edit_text(
                f"❌ *Error:* `{err}`", parse_mode=ParseMode.MARKDOWN_V2
            )
            return

        attrs   = data["data"]["attributes"]
        report  = format_domain_report(attrs, domain)
        stats   = attrs.get("last_analysis_stats", {})
        threat  = stats.get("malicious", 0) > 0

        track_scan(context, "domains", threat)
        vt_link = f"{VT_GUI_BASE}/domain/{domain}"

        await status_msg.edit_text(
            report,
            parse_mode=ParseMode.MARKDOWN,
            reply_markup=vt_link_keyboard(vt_link),
        )

    except Exception as e:
        logger.error(f"Domain scan error: {e}", exc_info=True)
        await status_msg.edit_text(
            f"❌ *Error:* `{str(e)[:200]}`", parse_mode=ParseMode.MARKDOWN_V2
        )


# ─────────────────────────────────────────────
#  Scan: IP Address
# ─────────────────────────────────────────────
async def scan_ip(update: Update, context: ContextTypes.DEFAULT_TYPE, ip: str) -> None:
    status_msg = await update.message.reply_text(
        "📡 *Checking IP address\\.\\.\\.*", parse_mode=ParseMode.MARKDOWN_V2
    )
    try:
        async with aiohttp.ClientSession() as session:
            data, status = await vt_get(session, f"/ip_addresses/{ip}")

        if status != 200:
            err = data.get("error", {}).get("message", "Unknown error")
            await status_msg.edit_text(
                f"❌ *Error:* `{err}`", parse_mode=ParseMode.MARKDOWN_V2
            )
            return

        attrs   = data["data"]["attributes"]
        report  = format_ip_report(attrs, ip)
        stats   = attrs.get("last_analysis_stats", {})
        threat  = stats.get("malicious", 0) > 0

        track_scan(context, "ips", threat)
        vt_link = f"{VT_GUI_BASE}/ip-address/{ip}"

        await status_msg.edit_text(
            report,
            parse_mode=ParseMode.MARKDOWN,
            reply_markup=vt_link_keyboard(vt_link),
        )

    except Exception as e:
        logger.error(f"IP scan error: {e}", exc_info=True)
        await status_msg.edit_text(
            f"❌ *Error:* `{str(e)[:200]}`", parse_mode=ParseMode.MARKDOWN_V2
        )


# ─────────────────────────────────────────────
#  Error Handler
# ─────────────────────────────────────────────
async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    logger.error("Exception while handling update:", exc_info=context.error)
    if isinstance(update, Update) and update.message:
        await update.message.reply_text(
            "⚠️ Something went wrong\\. Please try again later\\.",
            parse_mode=ParseMode.MARKDOWN_V2,
        )


# ─────────────────────────────────────────────
#  Minimal HTTP server for Render health checks
# ─────────────────────────────────────────────
async def health_handler(request: web.Request) -> web.Response:
    return web.Response(text="🛡️ VT Bot is alive!", content_type="text/plain")


async def run_web_server() -> None:
    app = web.Application()
    app.router.add_get("/", health_handler)
    app.router.add_get("/health", health_handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", PORT)
    await site.start()
    logger.info(f"Health server running on port {PORT}")


# ─────────────────────────────────────────────
#  Main
# ─────────────────────────────────────────────
async def main() -> None:
    logger.info("🛡️  Starting VirusTotal Telegram Bot...")

    # Start health check server
    await run_web_server()

    # Build Telegram application
    app = (
        ApplicationBuilder()
        .token(BOT_TOKEN)
        .concurrent_updates(True)
        .build()
    )

    # ── Register handlers ──
    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("help",  cmd_help))
    app.add_handler(CommandHandler("about", cmd_about))
    app.add_handler(CommandHandler("stats", cmd_stats))
    app.add_handler(CallbackQueryHandler(callback_handler))

    # File handlers
    app.add_handler(MessageHandler(filters.Document.ALL, handle_file))
    app.add_handler(MessageHandler(filters.AUDIO,        handle_file))
    app.add_handler(MessageHandler(filters.VIDEO,        handle_file))
    app.add_handler(MessageHandler(filters.PHOTO,        handle_file))

    # Text handler (URLs, hashes, IPs, domains)
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))

    # Error handler
    app.add_error_handler(error_handler)

    logger.info("🤖 Bot polling started. Press Ctrl+C to stop.")
    await app.initialize()
    await app.start()
    await app.updater.start_polling(
        allowed_updates=Update.ALL_TYPES,
        drop_pending_updates=True,
    )

    # Run forever
    try:
        await asyncio.Event().wait()
    finally:
        await app.updater.stop()
        await app.stop()
        await app.shutdown()


if __name__ == "__main__":
    asyncio.run(main())
