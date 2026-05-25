# Flipper Telegram

Browse and send Telegram messages from a **Flipper Zero** via a self-hosted Raspberry Pi server.

```
Telegram ──► Bot ──► Pi server (FastAPI + SQLite)
                          │  HTTPS :8888
                    ESP32 WiFi board (FlipperHTTP)
                          │  UART
                    Flipper Zero FAP
```

A Telegram bot collects incoming messages into a local SQLite database. A FastAPI server exposes them over HTTPS. The Flipper Zero FAP talks to an ESP32 WiFi board (FlipperHTTP) over UART; the ESP32 makes the actual HTTPS requests to the Pi.

**Why HTTPS?** The FlipperHTTP ESP32 firmware always initiates TLS regardless of the URL scheme, so the server must speak HTTPS. A self-signed certificate works because the board skips verification.

---

## Features

- Browse Telegram chats and messages on the Flipper Zero 128×64 display
- Send messages from the Flipper using the built-in on-screen keyboard
- Web UI at `https://<pi-ip>:8888` — browse, send, and delete messages from a browser
- Start a new chat by entering any public Telegram @username
- Cyrillic → Latin transliteration for the Flipper display
- Paginated message list (5 per page on device, 30 in browser)

---

## Hardware

| Part | Notes |
|---|---|
| Raspberry Pi | Any model |
| Flipper Zero | Any firmware |
| ESP32 WiFi board | Must have [FlipperHTTP](https://github.com/jblanked/FlipperHTTP) firmware |

---

## Repository layout

```
flipper-tg/               ← Pi server (this repo)
├── main.py               # FastAPI app + Flipper API endpoints
├── bot.py                # Telegram bot (collects messages)
├── database.py           # SQLite helpers
├── requirements.txt
├── .env.example          # Config template — copy to .env
├── gen_cert.sh           # One-time TLS cert generator
├── static/
│   ├── style.css
│   └── telegram_reader.fap   # Pre-built Flipper FAP (not committed)
└── templates/
    ├── base.html
    ├── index.html
    └── chat.html

telegram-flipper-app/     ← Flipper Zero FAP source (separate folder)
├── telegram_reader.c
├── application.fam
└── flipper_http/         # FlipperHTTP C library
```

---

## Server setup (Raspberry Pi)

### 1. Create a Telegram bot

1. Message [@BotFather](https://t.me/BotFather) on Telegram.
2. Send `/newbot` and follow the prompts.
3. Copy the **API token**.
4. Add the bot to the chats you want to monitor, or just message it directly.

### 2. Clone and configure

```bash
git clone https://github.com/yourname/flipper-tg.git
cd flipper-tg
cp .env.example .env
nano .env   # fill in your values
```

`.env` variables:

| Variable | Required | Description |
|---|---|---|
| `BOT_TOKEN` | Yes | Telegram API token from BotFather |
| `SOCKS_PROXY` | No | SOCKS5 proxy, e.g. `socks5://127.0.0.1:1080`. Leave empty if unused. |
| `HOST` | No | Bind address (default `0.0.0.0`) |
| `PORT` | No | Port (default `8888`) |

### 3. Install dependencies

```bash
python3 -m venv venv
venv/bin/pip install -r requirements.txt
```

### 4. Generate a self-signed TLS certificate

Run once — valid for 10 years.

```bash
# Edit gen_cert.sh first: replace 192.168.0.102 with your Pi's actual IP
bash gen_cert.sh
sudo chown $USER:$USER cert.pem key.pem
chmod 640 key.pem
```

### 5. Install the systemd service

Create `/etc/systemd/system/flipper-telegram.service`:

```ini
[Unit]
Description=Flipper Telegram server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=pi
WorkingDirectory=/home/pi/flipper-tg
ExecStart=/home/pi/flipper-tg/venv/bin/python main.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now flipper-telegram
sudo systemctl status flipper-telegram
```

---

## Flipper Zero FAP

### Prerequisites

```bash
pip install ufbt
ufbt update   # downloads the SDK matching your Flipper firmware
```

Place the [FlipperHTTP](https://github.com/jblanked/FlipperHTTP) C library at `telegram-flipper-app/flipper_http/`.

### Configure before building

Edit `telegram-flipper-app/telegram_reader.c`:

```c
#define API_BASE  "https://192.168.0.102:8888"   // ← your Pi's IP
```

Find `flipper_http_save_wifi` in `worker_thread()` and set your WiFi credentials:

```c
flipper_http_save_wifi(app->fhttp, "YourSSID", "YourPassword");
```

### Build and deploy

```bash
cd telegram-flipper-app
ufbt
cp dist/telegram_reader.fap ../flipper-tg/static/telegram_reader.fap
```

Download the FAP from the server (accept the cert warning):

```
https://<pi-ip>:8888/static/telegram_reader.fap
```

Copy it to the Flipper's SD card at `/ext/apps/Tools/telegram_reader.fap` using [qFlipper](https://flipperzero.one/update) or directly to the SD card.

---

## Usage

### Flipper Zero

1. **Apps → Tools → Telegram Reader**
2. Debug screen shows connection progress (PING / WiFi / HTTP / Resp / Chts).
3. Press **OK** when loaded to open the chat list.
4. **Up/Down** to navigate, **OK** to open a chat.
5. In a chat: **Up/Down** scrolls messages, **Left/Right** changes pages.
6. **Hold OK** opens the on-screen keyboard to write and send a message.
7. **Back** returns to the previous screen.

### Browser

Open `https://<pi-ip>:8888` and accept the self-signed cert warning.

- Click a chat to view its messages.
- **Hover** over a message to reveal the **✕** delete button.
- Use the **compose bar** at the bottom to send a message from the browser.
- Press **+** in the top bar to start a new chat by @username.

> The bot can only message users who have previously started a conversation with it (Telegram restriction). For groups, the bot must be a member.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| "No WiFi board response" | FlipperHTTP board not connected | Check UART wiring; reflash board firmware |
| WiFi step hangs | Wrong SSID/password | Edit `flipper_http_save_wifi()`, rebuild FAP |
| HTTP timeout on Flipper | Pi IP changed or server stopped | Update `API_BASE`, check `systemctl status flipper-telegram` |
| "Invalid HTTP request" in logs | Server not serving HTTPS | Ensure `cert.pem`/`key.pem` exist and are readable |
| 0 chats on Flipper | No messages in database | Send a message to your bot on Telegram first |
| New chat fails | User hasn't started the bot | Ask them to send `/start` to your bot |

```bash
# Live server logs
sudo journalctl -u flipper-telegram -f
```

---

## Security notes

- `.env`, `*.pem`, and `*.key` are in `.gitignore` — never commit them.
- The self-signed cert will trigger browser warnings; add a permanent exception.
- The server binds to all interfaces by default. Use a firewall to restrict access if needed.

---

## License

MIT
