"""
╔══════════════════════════════════════════════════════════════╗
║            🛡️  VirusTotal Telegram Bot  v3.0                 ║
║      python-telegram-bot 22.7  ·  VirusTotal API v3          ║
║      Webhook · Async · Hash-First · Rate-Limit Safe           ║
╚══════════════════════════════════════════════════════════════╝

  Architecture:
    • Hash-first lookup  → no redundant uploads, instant cached results
    • In-memory scan cache → deduplicates concurrent requests
    • Exponential backoff → handles VT rate limits gracefully
    • Structured logging  → emoji-prefixed, level-tagged, timestamped
    • Self-ping loop      → keeps Render free tier awake
    • Webhook + aiohttp   → production-grade async HTTP server
"""

from __future__ import annotations

import asyncio
import hashlib
import io
import logging
import os
import re
import time
from base64 import urlsafe_b64encode
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

import aiohttp
from aiohttp import web
from telegram import (
    BotCommand,
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

# ══════════════════════════════════════════════════════════════
#  LOGGING — Structured, emoji-prefixed, production-grade
# ══════════════════════════════════════════════════════════════

class EmojiFormatter(logging.Formatter):
    EMOJIS = {
        logging.DEBUG:    "🔍 DEBUG  ",
        logging.INFO:     "✅ INFO   ",
        logging.WARNING:  "⚠️  WARN   ",
        logging.ERROR:    "❌ ERROR  ",
        logging.CRITICAL: "🚨 CRITICAL",
    }
    def format(self, record: logging.LogRecord) -> str:
        record.emoji_level = self.EMOJIS.get(record.levelno, "   ")
        return super().format(record)


def setup_logging() -> logging.Logger:
    handler = logging.StreamHandler()
    handler.setFormatter(EmojiFormatter(
        fmt="%(asctime)s | %(emoji_level)s | %(name)-20s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    root.handlers.clear()
    root.addHandler(handler)
    for noisy in ("httpx", "httpcore", "telegram.ext.Updater",
                  "telegram.ext.Application", "aiohttp.access"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    return logging.getLogger("vtbot")


log = setup_logging()


# ══════════════════════════════════════════════════════════════
#  CONFIGURATION
# ══════════════════════════════════════════════════════════════

BOT_TOKEN       = os.environ["BOT_TOKEN"]
VT_API_KEY      = os.environ["VT_API_KEY"]
RENDER_URL      = os.getenv("RENDER_URL", "")
PORT            = int(os.getenv("PORT", "8080"))
MAX_FILE_MB     = int(os.getenv("MAX_FILE_SIZE_MB", "32"))
MAX_FILE_BYTES  = MAX_FILE_MB * 1024 * 1024

VT_BASE         = "https://www.virustotal.com/api/v3"
VT_GUI          = "https://www.virustotal.com/gui"
VT_HEADERS      = {"x-apikey": VT_API_KEY, "Accept": "application/json"}

POLL_INTERVAL   = 5
POLL_MAX_TRIES  = 24
RETRY_MAX       = 3
RETRY_BACKOFF   = 2.0
PING_INTERVAL   = 13 * 60
CACHE_TTL       = 3600

WEBHOOK_PATH    = f"/webhook/{BOT_TOKEN}"
WEBHOOK_URL     = f"{RENDER_URL}{WEBHOOK_PATH}"

log.info(f"Config | PORT={PORT} | MAX_FILE={MAX_FILE_MB}MB | WEBHOOK={'yes' if RENDER_URL else 'NO (set RENDER_URL!)'}")


# ══════════════════════════════════════════════════════════════
#  IN-MEMORY CACHE
# ══════════════════════════════════════════════════════════════

@dataclass
class CacheEntry:
    attrs:     dict
    scan_type: str
    cached_at: float = field(default_factory=time.time)
    hits:      int   = 0

    @property
    def age_str(self) -> str:
        s = int(time.time() - self.cached_at)
        if s < 60:   return f"{s}s ago"
        if s < 3600: return f"{s//60}m ago"
        return f"{s//3600}h ago"


class ScanCache:
    def __init__(self):
        self._store: dict[str, CacheEntry] = {}
        self._lock  = asyncio.Lock()

    async def get(self, key: str) -> Optional[CacheEntry]:
        async with self._lock:
            e = self._store.get(key)
            if e and (time.time() - e.cached_at) < CACHE_TTL:
                e.hits += 1
                log.info(f"💾 Cache HIT | key={key[:20]}... | hits={e.hits} | age={e.age_str}")
                return e
            if e:
                del self._store[key]
            return None

    async def set(self, key: str, attrs: dict, scan_type: str):
        async with self._lock:
            self._store[key] = CacheEntry(attrs=attrs, scan_type=scan_type)
            log.info(f"💾 Cache SET  | key={key[:20]}... | type={scan_type} | store_size={len(self._store)}")

    def size(self) -> int:
        return len(self._store)


# Prevents duplicate concurrent scans of same target
class ScanLock:
    def __init__(self):
        self._locks: dict[str, asyncio.Lock] = {}
        self._meta  = asyncio.Lock()

    async def acquire(self, key: str) -> asyncio.Lock:
        async with self._meta:
            if key not in self._locks:
                self._locks[key] = asyncio.Lock()
            return self._locks[key]

    async def cleanup(self, key: str):
        async with self._meta:
            self._locks.pop(key, None)


CACHE     = ScanCache()
SCAN_LOCK = ScanLock()


# ══════════════════════════════════════════════════════════════
#  GLOBAL STATS
# ══════════════════════════════════════════════════════════════

@dataclass
class Stats:
    start:       float = field(default_factory=time.time)
    scans:       int   = 0
    cache_hits:  int   = 0
    uploads:     int   = 0
    threats:     int   = 0
    errors:      int   = 0
    users:       set   = field(default_factory=set)

    def uptime(self) -> str:
        s = int(time.time() - self.start)
        return f"{s//3600}h {(s%3600)//60}m {s%60}s"


G = Stats()


# ══════════════════════════════════════════════════════════════
#  VT API CLIENT — async, retry, rate-limit aware
# ══════════════════════════════════════════════════════════════

class VTError(Exception):
    def __init__(self, msg: str, code: int = 0):
        self.message, self.code = msg, code
        super().__init__(msg)


async def _vt_req(session: aiohttp.ClientSession, method: str, endpoint: str, **kw) -> tuple[dict, int]:
    url = f"{VT_BASE}{endpoint}"
    for attempt in range(1, RETRY_MAX + 1):
        try:
            async with session.request(method, url, headers=VT_HEADERS, **kw) as r:
                status = r.status
                try:
                    data = await r.json()
                except Exception:
                    data = {}
                if status == 429:
                    wait = RETRY_BACKOFF ** attempt * 15
                    log.warning(f"⏳ VT Rate Limited | attempt={attempt}/{RETRY_MAX} | sleeping={wait:.0f}s")
                    await asyncio.sleep(wait)
                    continue
                if status == 401:
                    raise VTError("Invalid API key — check VT_API_KEY.", 401)
                log.debug(f"VT {method} {endpoint} → {status}")
                return data, status
        except aiohttp.ClientError as e:
            wait = RETRY_BACKOFF ** attempt * 3
            log.warning(f"Network error | attempt={attempt} | err={e} | retry in {wait:.1f}s")
            if attempt < RETRY_MAX:
                await asyncio.sleep(wait)
            else:
                raise VTError(f"Network error after {RETRY_MAX} retries: {e}")
    raise VTError("Max retries exceeded")


async def vt_get(s: aiohttp.ClientSession, ep: str):
    return await _vt_req(s, "GET", ep)

async def vt_post(s: aiohttp.ClientSession, ep: str, data: dict):
    return await _vt_req(s, "POST", ep, data=data)

async def vt_upload(s: aiohttp.ClientSession, fb: bytes, fn: str):
    form = aiohttp.FormData()
    form.add_field("file", fb, filename=fn, content_type="application/octet-stream")
    return await _vt_req(s, "POST", "/files", data=form)


async def vt_poll(s: aiohttp.ClientSession, aid: str, status_msg=None) -> Optional[dict]:
    log.info(f"🔄 Polling | id={aid[:24]}...")
    t0 = time.time()
    for i in range(1, POLL_MAX_TRIES + 1):
        data, code = await vt_get(s, f"/analyses/{aid}")
        if code == 200:
            attrs = data.get("data", {}).get("attributes", {})
            state = attrs.get("status", "?")
            stats = attrs.get("stats", {})
            log.debug(f"Poll {i:02}/{POLL_MAX_TRIES} | state={state} | mal={stats.get('malicious',0)} | {time.time()-t0:.1f}s")
            if state == "completed":
                log.info(f"✅ Analysis done | mal={stats.get('malicious',0)} | sus={stats.get('suspicious',0)} | {time.time()-t0:.1f}s")
                return data
            if status_msg and i % 3 == 0:
                scanned = sum(stats.values())
                try:
                    await status_msg.edit_text(
                        f"⚙️ *Scanning... ({i * POLL_INTERVAL}s elapsed)*\n"
                        f"Engines done: `{scanned}` | Detections: `{stats.get('malicious',0)}`",
                        parse_mode=ParseMode.MARKDOWN,
                    )
                except Exception:
                    pass
        await asyncio.sleep(POLL_INTERVAL)
    log.warning(f"⏰ Poll timeout | id={aid[:24]}... | elapsed={time.time()-t0:.1f}s")
    return None


# ══════════════════════════════════════════════════════════════
#  FORMATTERS
# ══════════════════════════════════════════════════════════════

def _emoji(m: int, tot: int) -> str:
    if tot == 0 or m == 0: return "✅" if tot > 0 else "⚪"
    r = m / tot
    return "🟡" if (m<=2 or r<0.05) else "🟠" if (m<=5 or r<0.20) else "🔴"

def _verdict(m: int, s: int) -> str:
    if m==0 and s==0: return "✅ *CLEAN*"
    if m==0:          return "🟡 *SUSPICIOUS*"
    if m<=3:          return "🟠 *LOW THREAT*"
    if m<=10:         return "🔴 *THREAT DETECTED*"
    return "🚨 *MALWARE — HIGH CONFIDENCE*"

def _bar(st: dict) -> str:
    m, s, h, u = st.get("malicious",0), st.get("suspicious",0), st.get("harmless",0), st.get("undetected",0)
    tot = m+s+h+u or 1
    f = round((m+s)/tot*24)
    pct = round((m+s)/tot*100, 1)
    return f"`[{'█'*f}{'░'*(24-f)}]` {pct}%"

def _human(n: int) -> str:
    for u in ("B","KB","MB","GB"):
        if n < 1024: return f"{n:.1f} {u}"
        n /= 1024
    return f"{n:.1f} TB"

def _detections(results: dict, limit: int = 8) -> str:
    lines = [
        f"  `{e[:22]:<22}` → `{i.get('result','?')[:28]}`"
        for e, i in results.items()
        if i.get("category") in ("malicious","suspicious")
    ][:limit]
    return ("\n\n🔬 *Top Detections:*\n" + "\n".join(lines)) if lines else ""

def _cache_badge(c: bool) -> str:
    return "  _(⚡ cached)_" if c else ""


def fmt_file(a: dict, fn: str, cached: bool = False) -> str:
    s = a.get("last_analysis_stats", {})
    m, sus, h, u = s.get("malicious",0), s.get("suspicious",0), s.get("harmless",0), s.get("undetected",0)
    tot = m+sus+h+u
    names = a.get("meaningful_name") or fn
    if isinstance(names, list): names = names[0] if names else fn
    first = a.get("first_submission_date")
    first_s = datetime.fromtimestamp(first, tz=timezone.utc).strftime("%Y-%m-%d") if first else "N/A"
    tags = " ".join(f"`{t}`" for t in a.get("tags",[])[:5]) or "—"
    sha256 = a.get("sha256","N/A")
    return (
        f"{_emoji(m,tot)} *VirusTotal File Report*{_cache_badge(cached)}\n"
        f"{'─'*34}\n"
        f"📄 *Name:*     `{str(names)[:50]}`\n"
        f"📦 *Size:*     `{_human(a.get('size',0))}`\n"
        f"🗂 *Type:*     `{a.get('type_description',a.get('magic','?'))[:40]}`\n"
        f"🏷 *Tags:*     {tags}\n"
        f"📅 *1st seen:* `{first_s}`\n"
        f"🔁 *Submitted:* `{a.get('times_submitted','N/A')}×`\n\n"
        f"🏁 *Verdict:* {_verdict(m,sus)}\n"
        f"📊 `{m}/{tot}` engines flagged\n"
        f"{_bar(s)}\n\n"
        f"🟥 Malicious:  `{m}`\n"
        f"🟧 Suspicious: `{sus}`\n"
        f"🟩 Harmless:   `{h}`\n"
        f"⬜ Undetected: `{u}`\n\n"
        f"🔐 *Hashes:*\n"
        f"  `MD5   ` `{a.get('md5','N/A')}`\n"
        f"  `SHA1  ` `{a.get('sha1','N/A')}`\n"
        f"  `SHA256` `{sha256[:40]}...`"
        f"{_detections(a.get('last_analysis_results',{}))}"
    )

def fmt_url(a: dict, url: str, cached: bool = False) -> str:
    s = a.get("last_analysis_stats", {})
    m, sus, h, u = s.get("malicious",0), s.get("suspicious",0), s.get("harmless",0), s.get("undetected",0)
    tot = m+sus+h+u
    cats = ", ".join(set(a.get("categories",{}).values()))[:80] or "N/A"
    cert = a.get("last_https_certificate",{})
    issuer = cert.get("issuer",{}).get("O","N/A") if cert else "N/A"
    redir = a.get("redirection_chain",[])
    redir_str = f"\n🔀 *Redirects:* `{len(redir)} hops`" if redir else ""
    return (
        f"{_emoji(m,tot)} *VirusTotal URL Report*{_cache_badge(cached)}\n"
        f"{'─'*34}\n"
        f"🔗 *URL:*      `{url[:55]}{'...' if len(url)>55 else ''}`\n"
        f"📌 *Title:*    `{str(a.get('title','N/A'))[:55]}`\n"
        f"🏷 *Category:* `{cats}`\n"
        f"🔒 *TLS:*      `{str(issuer)[:38]}`"
        f"{redir_str}\n\n"
        f"🏁 *Verdict:* {_verdict(m,sus)}\n"
        f"📊 `{m}/{tot}` engines flagged\n"
        f"{_bar(s)}\n\n"
        f"🟥 Malicious:  `{m}`\n"
        f"🟧 Suspicious: `{sus}`\n"
        f"🟩 Harmless:   `{h}`\n"
        f"⬜ Undetected: `{u}`"
        f"{_detections(a.get('last_analysis_results',{}))}"
    )

def fmt_domain(a: dict, domain: str, cached: bool = False) -> str:
    s = a.get("last_analysis_stats", {})
    m, sus, h, u = s.get("malicious",0), s.get("suspicious",0), s.get("harmless",0), s.get("undetected",0)
    tot = m+sus+h+u
    cats = ", ".join(set(a.get("categories",{}).values()))[:80] or "N/A"
    dns  = a.get("last_dns_records",[])
    a_records = [r["value"] for r in dns if r.get("type")=="A"][:3]
    a_str = ", ".join(f"`{ip}`" for ip in a_records) if a_records else "N/A"
    return (
        f"{_emoji(m,tot)} *VirusTotal Domain Report*{_cache_badge(cached)}\n"
        f"{'─'*34}\n"
        f"🌐 *Domain:*     `{domain}`\n"
        f"🏢 *Registrar:*  `{str(a.get('registrar','N/A'))[:38]}`\n"
        f"🗓 *Created:*    `{a.get('creation_date','N/A')}`\n"
        f"🌍 *Country:*    `{a.get('country','N/A')}`\n"
        f"⭐ *Reputation:* `{a.get('reputation','N/A')}`\n"
        f"🏷 *Category:*   `{cats}`\n"
        f"🔗 *DNS (A):*    {a_str}\n\n"
        f"🏁 *Verdict:* {_verdict(m,sus)}\n"
        f"📊 `{m}/{tot}` engines flagged\n"
        f"{_bar(s)}\n\n"
        f"🟥 Malicious:  `{m}`\n"
        f"🟧 Suspicious: `{sus}`\n"
        f"🟩 Harmless:   `{h}`\n"
        f"⬜ Undetected: `{u}`"
        f"{_detections(a.get('last_analysis_results',{}))}"
    )

def fmt_ip(a: dict, ip: str, cached: bool = False) -> str:
    s = a.get("last_analysis_stats", {})
    m, sus, h, u = s.get("malicious",0), s.get("suspicious",0), s.get("harmless",0), s.get("undetected",0)
    tot = m+sus+h+u
    return (
        f"{_emoji(m,tot)} *VirusTotal IP Report*{_cache_badge(cached)}\n"
        f"{'─'*34}\n"
        f"📡 *IP:*         `{ip}`\n"
        f"🌍 *Country:*    `{a.get('country','N/A')}` ({a.get('continent','N/A')})\n"
        f"🏢 *Owner:*      `{str(a.get('as_owner','N/A'))[:38]}`\n"
        f"🔢 *ASN:*        `AS{a.get('asn','N/A')}`\n"
        f"🕸 *Network:*    `{a.get('network','N/A')}`\n"
        f"⭐ *Reputation:* `{a.get('reputation','N/A')}`\n\n"
        f"🏁 *Verdict:* {_verdict(m,sus)}\n"
        f"📊 `{m}/{tot}` engines flagged\n"
        f"{_bar(s)}\n\n"
        f"🟥 Malicious:  `{m}`\n"
        f"🟧 Suspicious: `{sus}`\n"
        f"🟩 Harmless:   `{h}`\n"
        f"⬜ Undetected: `{u}`"
        f"{_detections(a.get('last_analysis_results',{}))}"
    )


# ══════════════════════════════════════════════════════════════
#  UI
# ══════════════════════════════════════════════════════════════

def vt_kb(link: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([[InlineKeyboardButton("🔗 Full Report on VirusTotal", url=link)]])

def menu_kb() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("📁 Scan File",    callback_data="h_file"),
         InlineKeyboardButton("🔗 Scan URL",     callback_data="h_url")],
        [InlineKeyboardButton("🔐 Hash Lookup",  callback_data="h_hash"),
         InlineKeyboardButton("🌐 Domain Check", callback_data="h_domain")],
        [InlineKeyboardButton("📡 IP Check",     callback_data="h_ip"),
         InlineKeyboardButton("ℹ️ About",         callback_data="h_about")],
    ])


# ══════════════════════════════════════════════════════════════
#  STAT TRACKER
# ══════════════════════════════════════════════════════════════

def track(ctx: ContextTypes.DEFAULT_TYPE, kind: str, threat: bool, cached: bool):
    d = ctx.user_data
    d["total"]   = d.get("total",0) + 1
    d[kind]      = d.get(kind,0) + 1
    d["cached"]  = d.get("cached",0) + (1 if cached else 0)
    d["threats"] = d.get("threats",0) + (1 if threat else 0)
    G.scans     += 1
    G.threats   += (1 if threat else 0)
    G.cache_hits+= (1 if cached else 0)
    if uid := ctx.user_data.get("_uid"):
        G.users.add(uid)


# ══════════════════════════════════════════════════════════════
#  COMMAND HANDLERS
# ══════════════════════════════════════════════════════════════

async def cmd_start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    u = update.effective_user
    ctx.user_data["_uid"] = u.id
    G.users.add(u.id)
    log.info(f"👤 /start | user={u.id} | name={u.first_name}")
    await update.message.reply_text(
        f"🛡️ *VirusTotal Scanner Bot v3.0*\n"
        f"{'━'*32}\n\n"
        f"Hey *{u.first_name}*! I scan everything against *70+ AV engines*.\n\n"
        f"*What I can scan:*\n"
        f"  📁 Files — APK, EXE, PDF, ZIP, JS...\n"
        f"  🔗 URLs — paste any link\n"
        f"  🔐 Hashes — MD5 / SHA1 / SHA256\n"
        f"  🌐 Domains — `evil.xyz`, `google.com`\n"
        f"  📡 IPs — `1.1.1.1`, `8.8.8.8`\n\n"
        f"⚡ *Smart cache* — same file scanned twice? Instant result, zero API calls!\n\n"
        f"Just send it — no commands needed!",
        parse_mode=ParseMode.MARKDOWN,
        reply_markup=menu_kb(),
    )


async def cmd_help(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    log.info(f"👤 /help | user={update.effective_user.id}")
    await update.message.reply_text(
        "🛡️ *Help — VirusTotal Bot*\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
        "📁 *File* — send any attachment (max 32MB)\n"
        "🔗 *URL* — `https://example.com`\n"
        "🔐 *Hash* — MD5 / SHA1 / SHA256\n"
        "🌐 *Domain* — `malicious.xyz`\n"
        "📡 *IP* — `192.168.1.1`\n\n"
        "⚡ *Smart Cache* — already scanned? Instant results.\n"
        "🔐 *Privacy tip* — send a hash, no file upload needed.\n\n"
        "*Commands:* /start · /help · /stats · /about\n\n"
        "⚠️ Free VT API: 4 req/min, 500 req/day",
        parse_mode=ParseMode.MARKDOWN,
        reply_markup=menu_kb(),
    )


async def cmd_about(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        f"ℹ️ *VirusTotal Bot v3.0*\n"
        f"{'━'*24}\n\n"
        f"*Stack:*\n"
        f"  • `python-telegram-bot` 22.7\n"
        f"  • VirusTotal API v3\n"
        f"  • aiohttp (fully async)\n"
        f"  • Webhook + in-memory cache\n\n"
        f"*Features:*\n"
        f"  ⚡ Hash-first — no redundant uploads\n"
        f"  🔄 Exponential backoff on rate limits\n"
        f"  💾 1-hour result cache\n"
        f"  🔒 Concurrent scan deduplication\n"
        f"  📡 Self-ping keep-alive (13 min)\n\n"
        f"⏱ Uptime: `{G.uptime()}`\n"
        f"🔍 Global scans: `{G.scans}`\n"
        f"🚨 Threats found: `{G.threats}`\n\n"
        f"Powered by [VirusTotal](https://virustotal.com)",
        parse_mode=ParseMode.MARKDOWN,
    )


async def cmd_stats(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    d   = ctx.user_data
    uid = update.effective_user.id
    log.info(f"📊 /stats | user={uid} | total={d.get('total',0)}")
    await update.message.reply_text(
        f"📊 *Your Scan Stats*\n"
        f"{'━'*26}\n\n"
        f"🔢 Total:   `{d.get('total',0)}`\n"
        f"⚡ Cached:  `{d.get('cached',0)}`\n\n"
        f"📁 Files:   `{d.get('files',0)}`\n"
        f"🔗 URLs:    `{d.get('urls',0)}`\n"
        f"🔐 Hashes:  `{d.get('hashes',0)}`\n"
        f"🌐 Domains: `{d.get('domains',0)}`\n"
        f"📡 IPs:     `{d.get('ips',0)}`\n\n"
        f"🚨 Threats: `{d.get('threats',0)}`\n\n"
        f"{'─'*22}\n"
        f"🌍 *Global Stats*\n"
        f"  Scans:    `{G.scans}`\n"
        f"  Uploads:  `{G.uploads}`\n"
        f"  Cache hits: `{G.cache_hits}`\n"
        f"  Threats:  `{G.threats}`\n"
        f"  Users:    `{len(G.users)}`\n"
        f"  Errors:   `{G.errors}`\n"
        f"  Uptime:   `{G.uptime()}`",
        parse_mode=ParseMode.MARKDOWN,
    )


async def callback_handler(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    tips = {
        "h_file":   "📁 *File Scan*\n\nSend any file attachment.\nAPK, EXE, PDF, ZIP, JS, etc.\nMax: `32MB` (VT free API hard limit)\n\n⚡ Same file again? Instant cached result!",
        "h_url":    "🔗 *URL Scan*\n\nSend:\n`https://suspicious.com/payload`\n`http://malware.xyz`",
        "h_hash":   "🔐 *Hash Lookup*\n\nSend an MD5, SHA1, or SHA256.\nNo upload — 100% private!\n\n`d41d8cd98f00b204e9800998ecf8427e`",
        "h_domain": "🌐 *Domain Check*\n\nSend:\n`malicious.domain.com`\n`suspicious.xyz`",
        "h_ip":     "📡 *IP Check*\n\nSend:\n`192.168.1.1`\n`8.8.8.8`",
        "h_about":  f"ℹ️ *Bot Info*\n\npython-telegram-bot `22.7` + VT API v3\nWebhook · Async · Smart Cache\nUptime: `{G.uptime()}`",
    }
    if text := tips.get(q.data):
        await q.message.reply_text(text, parse_mode=ParseMode.MARKDOWN)


# ══════════════════════════════════════════════════════════════
#  FILE HANDLER — hash-first, no redundant uploads
# ══════════════════════════════════════════════════════════════

async def handle_file(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    msg = update.message
    doc = msg.document or msg.audio or msg.video
    if msg.photo:
        doc, filename = msg.photo[-1], "photo.jpg"
    else:
        filename = getattr(doc, "file_name", None) or "file"

    file_size = getattr(doc, "file_size", 0) or 0
    uid = update.effective_user.id
    ctx.user_data["_uid"] = uid
    log.info(f"📁 File recv | user={uid} | name={filename} | size={_human(file_size)}")

    if file_size > MAX_FILE_BYTES:
        log.warning(f"File too large | user={uid} | size={_human(file_size)}")
        await msg.reply_text(
            f"❌ *File too large!*\n\n"
            f"Your file: `{_human(file_size)}`\n"
            f"VT free API limit: `{MAX_FILE_MB} MB`\n\n"
            f"*Why 32MB?*\nVirusTotal's free public API rejects anything over 32MB.\n"
            f"Larger files need a premium upload endpoint.\n\n"
            f"💡 *Workaround:* Compute the SHA256 hash and send that!\n"
            f"Linux/Mac: `sha256sum yourfile`\n"
            f"Windows:   `certutil -hashfile yourfile SHA256`",
            parse_mode=ParseMode.MARKDOWN,
        )
        return

    await msg.chat.send_action(ChatAction.UPLOAD_DOCUMENT)
    status = await msg.reply_text("⏳ *Downloading file...*", parse_mode=ParseMode.MARKDOWN)
    sha256 = None

    try:
        tg_file    = await ctx.bot.get_file(doc.file_id)
        buf        = io.BytesIO()
        await tg_file.download_to_memory(buf)
        file_bytes = buf.getvalue()
        sha256     = hashlib.sha256(file_bytes).hexdigest()
        md5        = hashlib.md5(file_bytes).hexdigest()
        log.info(f"📥 Downloaded | sha256={sha256[:16]}... | md5={md5[:16]}... | user={uid}")

        # ── 1. Check memory cache ──
        cached = await CACHE.get(sha256)
        if cached:
            log.info(f"⚡ Cache hit | sha256={sha256[:16]}... | user={uid}")
            await status.edit_text(
                fmt_file(cached.attrs, filename, cached=True),
                parse_mode=ParseMode.MARKDOWN,
                reply_markup=vt_kb(f"{VT_GUI}/file/{sha256}"),
            )
            st = cached.attrs.get("last_analysis_stats",{})
            track(ctx, "files", st.get("malicious",0)>0, cached=True)
            return

        # ── 2. Acquire per-hash lock (prevent duplicate concurrent uploads) ──
        lock = await SCAN_LOCK.acquire(sha256)
        async with lock:
            # Re-check cache after acquiring lock
            cached = await CACHE.get(sha256)
            if cached:
                await status.edit_text(
                    fmt_file(cached.attrs, filename, cached=True),
                    parse_mode=ParseMode.MARKDOWN,
                    reply_markup=vt_kb(f"{VT_GUI}/file/{sha256}"),
                )
                track(ctx, "files", cached.attrs.get("last_analysis_stats",{}).get("malicious",0)>0, cached=True)
                return

            async with aiohttp.ClientSession() as session:

                # ── 3. Check VT by hash — no upload if already known ──
                await status.edit_text("🔍 *Checking if VirusTotal already knows this file...*", parse_mode=ParseMode.MARKDOWN)
                existing, code = await vt_get(session, f"/files/{sha256}")

                if code == 200:
                    attrs = existing["data"]["attributes"]
                    log.info(f"✅ Hash known to VT | sha256={sha256[:16]}... | no upload needed")
                    await CACHE.set(sha256, attrs, "files")
                    st = attrs.get("last_analysis_stats",{})
                    track(ctx, "files", st.get("malicious",0)>0, cached=False)
                    await status.edit_text(
                        fmt_file(attrs, filename),
                        parse_mode=ParseMode.MARKDOWN,
                        reply_markup=vt_kb(f"{VT_GUI}/file/{sha256}"),
                    )
                    return

                # ── 4. Unknown — must upload ──
                log.info(f"📤 Uploading to VT | sha256={sha256[:16]}... | size={_human(file_size)} | user={uid}")
                await status.edit_text(
                    f"📤 *Uploading to VirusTotal...*\n`{_human(file_size)}`",
                    parse_mode=ParseMode.MARKDOWN,
                )
                resp, ucode = await vt_upload(session, file_bytes, filename)
                if ucode not in (200, 201):
                    err = resp.get("error",{}).get("message","Upload failed")
                    log.error(f"Upload failed | code={ucode} | err={err}")
                    G.errors += 1
                    await status.edit_text(f"❌ *Upload Failed:* `{err}`", parse_mode=ParseMode.MARKDOWN)
                    return

                G.uploads += 1
                aid = resp["data"]["id"]
                log.info(f"📤 Uploaded | analysis_id={aid[:24]}...")

                await status.edit_text(
                    "⚙️ *Scanning with 70+ AV engines...*\n_Up to ~2 minutes for first scan_",
                    parse_mode=ParseMode.MARKDOWN,
                )
                await vt_poll(session, aid, status_msg=status)

                # ── 5. Fetch full report by hash ──
                full, fcode = await vt_get(session, f"/files/{sha256}")
                if fcode != 200:
                    await status.edit_text("⏰ *Scan timed out.* Try again in a minute.", parse_mode=ParseMode.MARKDOWN)
                    return

                attrs = full["data"]["attributes"]

        await CACHE.set(sha256, attrs, "files")
        st = attrs.get("last_analysis_stats",{})
        log.info(f"📊 Scan done | sha256={sha256[:16]}... | mal={st.get('malicious',0)} | sus={st.get('suspicious',0)}")
        track(ctx, "files", st.get("malicious",0)>0, cached=False)
        await status.edit_text(
            fmt_file(attrs, filename),
            parse_mode=ParseMode.MARKDOWN,
            reply_markup=vt_kb(f"{VT_GUI}/file/{sha256}"),
        )

    except VTError as e:
        G.errors += 1
        log.error(f"VTError | user={uid} | {e.message}")
        await status.edit_text(f"❌ *VT Error:* `{e.message}`", parse_mode=ParseMode.MARKDOWN)
    except Exception as e:
        G.errors += 1
        log.error(f"File handler error | user={uid}", exc_info=True)
        await status.edit_text(f"❌ *Error:* `{str(e)[:200]}`", parse_mode=ParseMode.MARKDOWN)
    finally:
        if sha256:
            await SCAN_LOCK.cleanup(sha256)


# ══════════════════════════════════════════════════════════════
#  TEXT HANDLER — smart routing
# ══════════════════════════════════════════════════════════════

RE_MD5    = re.compile(r"^[a-fA-F0-9]{32}$")
RE_SHA1   = re.compile(r"^[a-fA-F0-9]{40}$")
RE_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")
RE_IP     = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$")
RE_DOMAIN = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")
RE_URL    = re.compile(r"^https?://", re.IGNORECASE)


async def handle_text(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    text = update.message.text.strip()
    uid  = update.effective_user.id
    ctx.user_data["_uid"] = uid
    log.info(f"💬 Text | user={uid} | input={text[:60]}")

    if RE_MD5.match(text) or RE_SHA1.match(text) or RE_SHA256.match(text):
        await do_hash(update, ctx, text)
    elif RE_IP.match(text):
        await do_ip(update, ctx, text)
    elif RE_URL.match(text):
        await do_url(update, ctx, text)
    elif RE_DOMAIN.match(text) and "." in text:
        await do_url(update, ctx, "https://"+text) if "/" in text else await do_domain(update, ctx, text)
    else:
        await update.message.reply_text(
            "🤔 *Couldn't identify what to scan.*\n\n"
            "Send a *file*, *URL*, *hash*, *domain*, or *IP*.\n"
            "Use /help for examples.",
            parse_mode=ParseMode.MARKDOWN,
        )


# ══════════════════════════════════════════════════════════════
#  INDIVIDUAL SCAN FUNCTIONS
# ══════════════════════════════════════════════════════════════

async def do_url(update: Update, ctx: ContextTypes.DEFAULT_TYPE, url: str):
    uid    = update.effective_user.id
    url_id = urlsafe_b64encode(url.encode()).decode().rstrip("=")
    log.info(f"🔗 URL scan | user={uid} | url={url[:60]}")
    status = await update.message.reply_text("🔗 *Scanning URL...*", parse_mode=ParseMode.MARKDOWN)
    try:
        cached = await CACHE.get(url_id)
        if cached:
            await status.edit_text(fmt_url(cached.attrs, url, cached=True), parse_mode=ParseMode.MARKDOWN,
                                   reply_markup=vt_kb(f"{VT_GUI}/url/{url_id}"))
            track(ctx, "urls", cached.attrs.get("last_analysis_stats",{}).get("malicious",0)>0, cached=True)
            return
        async with aiohttp.ClientSession() as session:
            resp, code = await vt_post(session, "/urls", {"url": url})
            if code not in (200, 201):
                await status.edit_text(f"❌ `{resp.get('error',{}).get('message','Error')}`", parse_mode=ParseMode.MARKDOWN)
                return
            await status.edit_text("⚙️ *Analyzing URL...*", parse_mode=ParseMode.MARKDOWN)
            await vt_poll(session, resp["data"]["id"])
            full, s2 = await vt_get(session, f"/urls/{url_id}")
            if s2 != 200:
                await status.edit_text("⏰ Timed out. Try again.", parse_mode=ParseMode.MARKDOWN)
                return
            attrs = full["data"]["attributes"]
        await CACHE.set(url_id, attrs, "urls")
        st = attrs.get("last_analysis_stats",{})
        log.info(f"📊 URL done | url={url[:40]} | mal={st.get('malicious',0)}")
        track(ctx, "urls", st.get("malicious",0)>0, cached=False)
        await status.edit_text(fmt_url(attrs, url), parse_mode=ParseMode.MARKDOWN,
                               reply_markup=vt_kb(f"{VT_GUI}/url/{url_id}"))
    except VTError as e:
        G.errors += 1
        await status.edit_text(f"❌ `{e.message}`", parse_mode=ParseMode.MARKDOWN)
    except Exception:
        G.errors += 1
        log.error("URL scan error", exc_info=True)
        await status.edit_text("❌ Unexpected error. Try again.", parse_mode=ParseMode.MARKDOWN)


async def do_hash(update: Update, ctx: ContextTypes.DEFAULT_TYPE, h: str):
    htype  = "MD5" if len(h)==32 else "SHA1" if len(h)==40 else "SHA256"
    uid    = update.effective_user.id
    log.info(f"🔐 Hash | user={uid} | type={htype} | hash={h[:16]}...")
    status = await update.message.reply_text(f"🔐 *Looking up {htype}...*", parse_mode=ParseMode.MARKDOWN)
    try:
        cached = await CACHE.get(h)
        if cached:
            await status.edit_text(fmt_file(cached.attrs, h[:16]+"...", cached=True), parse_mode=ParseMode.MARKDOWN,
                                   reply_markup=vt_kb(f"{VT_GUI}/file/{h}"))
            track(ctx, "hashes", cached.attrs.get("last_analysis_stats",{}).get("malicious",0)>0, cached=True)
            return
        async with aiohttp.ClientSession() as session:
            data, code = await vt_get(session, f"/files/{h}")
        if code == 404:
            log.info(f"Hash not found | {h[:16]}...")
            await status.edit_text(
                "🔍 *Hash not in VirusTotal database.*\n\nNever been scanned before.\nUpload the actual file for a fresh scan.",
                parse_mode=ParseMode.MARKDOWN)
            return
        if code != 200:
            await status.edit_text(f"❌ `{data.get('error',{}).get('message','Error')}`", parse_mode=ParseMode.MARKDOWN)
            return
        attrs = data["data"]["attributes"]
        await CACHE.set(h, attrs, "hashes")
        st = attrs.get("last_analysis_stats",{})
        log.info(f"📊 Hash done | {h[:16]}... | mal={st.get('malicious',0)}")
        track(ctx, "hashes", st.get("malicious",0)>0, cached=False)
        await status.edit_text(fmt_file(attrs, h[:16]+"..."), parse_mode=ParseMode.MARKDOWN,
                               reply_markup=vt_kb(f"{VT_GUI}/file/{h}"))
    except VTError as e:
        G.errors += 1
        await status.edit_text(f"❌ `{e.message}`", parse_mode=ParseMode.MARKDOWN)
    except Exception:
        G.errors += 1
        log.error("Hash lookup error", exc_info=True)
        await status.edit_text("❌ Unexpected error.", parse_mode=ParseMode.MARKDOWN)


async def do_domain(update: Update, ctx: ContextTypes.DEFAULT_TYPE, domain: str):
    uid    = update.effective_user.id
    log.info(f"🌐 Domain | user={uid} | domain={domain}")
    status = await update.message.reply_text("🌐 *Checking domain...*", parse_mode=ParseMode.MARKDOWN)
    try:
        cached = await CACHE.get(domain)
        if cached:
            await status.edit_text(fmt_domain(cached.attrs, domain, cached=True), parse_mode=ParseMode.MARKDOWN,
                                   reply_markup=vt_kb(f"{VT_GUI}/domain/{domain}"))
            track(ctx, "domains", cached.attrs.get("last_analysis_stats",{}).get("malicious",0)>0, cached=True)
            return
        async with aiohttp.ClientSession() as session:
            data, code = await vt_get(session, f"/domains/{domain}")
        if code == 404:
            await status.edit_text("🔍 Domain not found in VT database.", parse_mode=ParseMode.MARKDOWN)
            return
        if code != 200:
            await status.edit_text(f"❌ `{data.get('error',{}).get('message','Error')}`", parse_mode=ParseMode.MARKDOWN)
            return
        attrs = data["data"]["attributes"]
        await CACHE.set(domain, attrs, "domains")
        st = attrs.get("last_analysis_stats",{})
        track(ctx, "domains", st.get("malicious",0)>0, cached=False)
        await status.edit_text(fmt_domain(attrs, domain), parse_mode=ParseMode.MARKDOWN,
                               reply_markup=vt_kb(f"{VT_GUI}/domain/{domain}"))
    except VTError as e:
        G.errors += 1
        await status.edit_text(f"❌ `{e.message}`", parse_mode=ParseMode.MARKDOWN)
    except Exception:
        G.errors += 1
        log.error("Domain error", exc_info=True)
        await status.edit_text("❌ Unexpected error.", parse_mode=ParseMode.MARKDOWN)


async def do_ip(update: Update, ctx: ContextTypes.DEFAULT_TYPE, ip: str):
    uid    = update.effective_user.id
    log.info(f"📡 IP | user={uid} | ip={ip}")
    status = await update.message.reply_text("📡 *Checking IP...*", parse_mode=ParseMode.MARKDOWN)
    try:
        cached = await CACHE.get(ip)
        if cached:
            await status.edit_text(fmt_ip(cached.attrs, ip, cached=True), parse_mode=ParseMode.MARKDOWN,
                                   reply_markup=vt_kb(f"{VT_GUI}/ip-address/{ip}"))
            track(ctx, "ips", cached.attrs.get("last_analysis_stats",{}).get("malicious",0)>0, cached=True)
            return
        async with aiohttp.ClientSession() as session:
            data, code = await vt_get(session, f"/ip_addresses/{ip}")
        if code != 200:
            await status.edit_text(f"❌ `{data.get('error',{}).get('message','Error')}`", parse_mode=ParseMode.MARKDOWN)
            return
        attrs = data["data"]["attributes"]
        await CACHE.set(ip, attrs, "ips")
        st = attrs.get("last_analysis_stats",{})
        track(ctx, "ips", st.get("malicious",0)>0, cached=False)
        await status.edit_text(fmt_ip(attrs, ip), parse_mode=ParseMode.MARKDOWN,
                               reply_markup=vt_kb(f"{VT_GUI}/ip-address/{ip}"))
    except VTError as e:
        G.errors += 1
        await status.edit_text(f"❌ `{e.message}`", parse_mode=ParseMode.MARKDOWN)
    except Exception:
        G.errors += 1
        log.error("IP error", exc_info=True)
        await status.edit_text("❌ Unexpected error.", parse_mode=ParseMode.MARKDOWN)


# ══════════════════════════════════════════════════════════════
#  ERROR HANDLER
# ══════════════════════════════════════════════════════════════

async def error_handler(update: object, ctx: ContextTypes.DEFAULT_TYPE):
    G.errors += 1
    log.error(f"Unhandled | {ctx.error}", exc_info=ctx.error)
    if isinstance(update, Update) and update.message:
        await update.message.reply_text("⚠️ Something went wrong. Please try again.")


# ══════════════════════════════════════════════════════════════
#  SELF-PING KEEP-ALIVE
# ══════════════════════════════════════════════════════════════

async def self_ping_loop():
    if not RENDER_URL:
        log.info("Self-ping disabled (RENDER_URL not set)")
        return
    log.info(f"🏓 Self-ping active | every {PING_INTERVAL}s | target={RENDER_URL}/health")
    await asyncio.sleep(60)
    n = 0
    async with aiohttp.ClientSession() as session:
        while True:
            try:
                t0 = time.time()
                async with session.get(f"{RENDER_URL}/health", timeout=aiohttp.ClientTimeout(total=15)) as r:
                    n += 1
                    log.info(f"🏓 Ping #{n} | status={r.status} | latency={int((time.time()-t0)*1000)}ms")
            except Exception as e:
                log.warning(f"🏓 Ping failed | {e}")
            await asyncio.sleep(PING_INTERVAL)


# ══════════════════════════════════════════════════════════════
#  WEB SERVER
# ══════════════════════════════════════════════════════════════

async def build_web_app(ptb_app: Application) -> web.Application:
    async def health(req: web.Request) -> web.Response:
        return web.Response(
            text=(
                f"🛡️ VT Bot v3.0 | uptime={G.uptime()} | "
                f"scans={G.scans} | threats={G.threats} | "
                f"uploads={G.uploads} | cache_hits={G.cache_hits} | "
                f"errors={G.errors} | users={len(G.users)} | "
                f"cache_size={CACHE.size()}"
            ),
            content_type="text/plain",
        )

    async def webhook(req: web.Request) -> web.Response:
        try:
            data   = await req.json()
            update = Update.de_json(data, ptb_app.bot)
            asyncio.create_task(ptb_app.process_update(update))
        except Exception as e:
            log.error(f"Webhook error: {e}", exc_info=True)
        return web.Response(text="OK")

    app = web.Application()
    app.router.add_get("/",             health)
    app.router.add_get("/health",       health)
    app.router.add_post(WEBHOOK_PATH,   webhook)
    return app


# ══════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════

async def main():
    log.info("━" * 56)
    log.info("🛡️  VirusTotal Telegram Bot v3.0 — Starting up")
    log.info("━" * 56)

    ptb_app = (
        ApplicationBuilder()
        .token(BOT_TOKEN)
        .concurrent_updates(True)
        .build()
    )

    await ptb_app.bot.set_my_commands([
        BotCommand("start", "Welcome & quick menu"),
        BotCommand("help",  "How to use the bot"),
        BotCommand("stats", "Your scan statistics"),
        BotCommand("about", "Bot info & uptime"),
    ])
    log.info("📋 Bot commands registered")

    ptb_app.add_handler(CommandHandler("start", cmd_start))
    ptb_app.add_handler(CommandHandler("help",  cmd_help))
    ptb_app.add_handler(CommandHandler("about", cmd_about))
    ptb_app.add_handler(CommandHandler("stats", cmd_stats))
    ptb_app.add_handler(CallbackQueryHandler(callback_handler))
    ptb_app.add_handler(MessageHandler(
        filters.Document.ALL | filters.AUDIO | filters.VIDEO | filters.PHOTO,
        handle_file,
    ))
    ptb_app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))
    ptb_app.add_error_handler(error_handler)
    log.info("📡 Handlers registered")

    await ptb_app.initialize()
    await ptb_app.start()

    if RENDER_URL:
        await ptb_app.bot.set_webhook(
            url=WEBHOOK_URL,
            allowed_updates=Update.ALL_TYPES,
            drop_pending_updates=True,
        )
        log.info(f"🔗 Webhook set | {WEBHOOK_URL}")
    else:
        log.warning("⚠️  RENDER_URL not set — bot won't receive Telegram updates!")

    web_app = await build_web_app(ptb_app)
    runner  = web.AppRunner(web_app)
    await runner.setup()
    await web.TCPSite(runner, "0.0.0.0", PORT).start()
    log.info(f"🌐 Web server listening | port={PORT}")

    asyncio.create_task(self_ping_loop())

    log.info("✅ Bot fully live and ready!")
    log.info("━" * 56)

    try:
        await asyncio.Event().wait()
    finally:
        log.info("🛑 Shutting down...")
        await ptb_app.bot.delete_webhook()
        await ptb_app.stop()
        await ptb_app.shutdown()
        await runner.cleanup()
        log.info("👋 Clean shutdown complete.")


if __name__ == "__main__":
    asyncio.run(main())
