"""Point the Telegram bot at the live API. Run once after deploy:
python api/scripts/telegram_webhook.py https://checkam.me
Reads TELEGRAM_BOT_TOKEN and TELEGRAM_WEBHOOK_SECRET from the environment or .env."""
import sys

import httpx

sys.path.insert(0, "api")
from checkam import telegram  # noqa: E402

base = sys.argv[1].rstrip("/")
r = httpx.post(f"{telegram.API}/setWebhook", timeout=20, json={
    "url": f"{base}/telegram/{telegram.SECRET}", "secret_token": telegram.SECRET,
    "allowed_updates": ["message", "edited_message"], "drop_pending_updates": True})
print(r.json().get("description", r.text))
httpx.post(f"{telegram.API}/setMyCommands", timeout=20, json={"commands": [{"command": "start", "description": "How to check a message"}]})
