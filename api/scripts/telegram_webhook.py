"""Point the Telegram bot at the live API and set its profile. Run once after deploy:
python api/scripts/telegram_webhook.py https://checkam.me
Reads TELEGRAM_BOT_TOKEN and TELEGRAM_WEBHOOK_SECRET from the environment or .env."""
import sys

import httpx

sys.path.insert(0, "api")
from checkam import telegram  # noqa: E402

base = sys.argv[1].rstrip("/")


def call(method: str, **body) -> str:
    r = httpx.post(f"{telegram.API}/{method}", timeout=20, json=body).json()
    return f"{method}: {'ok' if r.get('ok') else r.get('description')}"


print(call("setWebhook", url=f"{base}/telegram/{telegram.SECRET}", secret_token=telegram.SECRET,
           allowed_updates=["message"], drop_pending_updates=True, max_connections=20))
for lang, (about, desc, start, check) in {
    "": ("Forward a suspicious money message. Five AI agents check it and tell you why. Free, English and French.",
         "CheckAm checks suspicious mobile money, job, scholarship and prize messages against real scam reports in Cameroon. "
         "Forward the message or send a screenshot: you get what it is, why, and what to do. Every answer is signed, so nobody can fake one.",
         "How to check a message", "Check the message you reply to (in groups)"),
    "fr": ("Transférez un message d'argent suspect : 5 agents IA le vérifient et disent pourquoi. Gratuit, FR et EN.",
           "CheckAm vérifie les messages suspects (mobile money, emploi, bourse, gain) avec de vrais signalements d'arnaques au Cameroun. "
           "Transférez le message ou envoyez une capture : vous saurez ce que c'est, pourquoi, et quoi faire. Chaque réponse est signée, personne ne peut en inventer une.",
           "Comment vérifier un message", "Vérifier le message auquel vous répondez (en groupe)"),
}.items():
    extra = {"language_code": lang} if lang else {}
    print(call("setMyShortDescription", short_description=about, **extra))
    print(call("setMyDescription", description=desc, **extra))
    print(call("setMyCommands", commands=[{"command": "start", "description": start}, {"command": "check", "description": check}], **extra))
