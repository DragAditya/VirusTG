# 🛡️ VirusTotal Telegram Bot

> Scan files, URLs, hashes, domains & IPs against 70+ antivirus engines — right from Telegram.

Built with **python-telegram-bot v22.7** + **VirusTotal API v3** + **aiohttp** — fully async, production-ready, and deployable on Render.com for free 24/7.

---

## ✨ Features

| Feature | Description |
|---|---|
| 📁 File Scan | Upload any file (APK, EXE, PDF, ZIP, etc.) up to 32MB |
| 🔗 URL Scan | Paste any URL — scanned against 70+ blocklists |
| 🔐 Hash Lookup | MD5, SHA1, SHA256 — no upload needed, fully private |
| 🌐 Domain Check | Reputation, registrar, categories, AV verdicts |
| 📡 IP Check | ASN, country, network, reputation, AV verdicts |
| 📊 Stats | Track your personal scan history |
| 🔘 Inline Keyboards | One-tap VT full report links |
| ⚡ Async | Fully async — handles multiple users simultaneously |

---

## 🚀 Deploy to Render (Free, 24/7)

### Step 1 — Get your API keys

1. **Telegram Bot Token:**
   - Open Telegram → search `@BotFather`
   - Send `/newbot`, follow prompts
   - Copy the token

2. **VirusTotal API Key:**
   - Sign up at [virustotal.com](https://www.virustotal.com)
   - Go to your profile → API Key
   - Copy the free API key

### Step 2 — Deploy on Render

1. Push this project to a GitHub repo
2. Go to [render.com](https://render.com) → **New** → **Background Worker**
3. Connect your GitHub repo
4. Set these Environment Variables in the Render dashboard:

   | Key | Value |
   |---|---|
   | `BOT_TOKEN` | Your Telegram bot token |
   | `VT_API_KEY` | Your VirusTotal API key |

5. **Build Command:** `pip install -r requirements.txt`
6. **Start Command:** `python bot.py`
7. Click **Deploy** 🚀

> **Why Background Worker?** Unlike Web Services, Background Workers on Render's free tier don't spin down after inactivity — your bot stays alive 24/7!

---

## 💻 Run Locally

```bash
# Clone & enter dir
git clone https://github.com/yourusername/vt-telegram-bot
cd vt-telegram-bot

# Create virtual env
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Set environment variables
cp .env.example .env
# Edit .env and fill in BOT_TOKEN and VT_API_KEY

# Run (load .env manually or use python-dotenv)
export $(cat .env | xargs)
python bot.py
```

---

## 📱 How to Use the Bot

Just send anything to your bot — no slash commands needed for scanning:

```
# Scan a file
[Send any file attachment]

# Scan a URL
https://suspicious-site.com

# Check a hash
d41d8cd98f00b204e9800998ecf8427e

# Check a domain
malicious.xyz

# Check an IP
192.168.1.100
```

### Commands
| Command | Description |
|---|---|
| `/start` | Welcome screen with quick menu |
| `/help` | Full help with examples |
| `/stats` | Your personal scan statistics |
| `/about` | Bot info & tech stack |

---

## ⚠️ VirusTotal Free API Limits

| Limit | Value |
|---|---|
| Requests per minute | 4 |
| Requests per day | 500 |
| Max file size | 32 MB |

The bot handles rate limits gracefully. For higher limits, upgrade to VT Premium.

---

## 🔧 Tech Stack

- **python-telegram-bot** `22.7` — Latest PTB with Bot API 9.5 support
- **VirusTotal API** `v3` — REST API with JSON responses
- **aiohttp** `3.11.18` — Async HTTP client for VT API calls
- **Python** `3.11+` — Full async/await support
- **Render.com** — Free 24/7 hosting as Background Worker

---

## 📝 Notes

- Files you upload are shared with VirusTotal and its partners
- Use **hash lookups** for privacy-sensitive files
- The bot uses **polling** mode (not webhooks) — simplest for Render
- `context.user_data` stores stats in-memory (resets on bot restart)

---

Made with ❤️ + ☕

