"""Telegram bot: forward a message or a screenshot to the bot, get the same verdict card as the app.
Webhook mode, so it runs inside the API process on Render with no extra worker."""
import base64
import html
import threading

import httpx

from . import agents, config, security

TOKEN = config.env("TELEGRAM_BOT_TOKEN")
SECRET = config.env("TELEGRAM_WEBHOOK_SECRET")
API = f"https://api.telegram.org/bot{TOKEN}"
_client = httpx.Client(timeout=30)
SITE = config.env("CHECKAM_PUBLIC_URL", "https://checkam.me")

LABEL = {
    "en": {"scam": "SCAM", "suspicious": "BE CAREFUL", "looks_genuine": "LOOKS GENUINE", "cant_tell": "CAN'T TELL YET"},
    "fr": {"scam": "ARNAQUE", "suspicious": "PRUDENCE", "looks_genuine": "SEMBLE AUTHENTIQUE", "cant_tell": "IMPOSSIBLE DE TRANCHER"},
}
TEXT = {
    "en": {"start": "Forward me a suspicious mobile money message, or send a screenshot of it. I check it against real reports and tell you why.",
           "wait": "Checking. The agents are looking at the evidence...", "busy": "Too many checks from this chat. Try again in {s} s.",
           "why": "Why", "do": "What to do", "dont": "Never", "error": "The check failed. Please try again in a minute.",
           "trace": "Check on the web, with every piece of evidence"},
    "fr": {"start": "Transférez-moi un message mobile money suspect, ou une capture d'écran. Je le vérifie avec de vrais signalements et je vous explique pourquoi.",
           "wait": "Vérification en cours. Les agents examinent les preuves...", "busy": "Trop de vérifications depuis ce chat. Réessayez dans {s} s.",
           "why": "Pourquoi", "do": "Que faire", "dont": "Jamais", "error": "La vérification a échoué. Réessayez dans une minute.",
           "trace": "Vérifiez sur le web, avec toutes les preuves"},
}


def enabled() -> bool:
    return bool(TOKEN and SECRET)


def _lang(code: str) -> str:
    return "fr" if (code or "").lower().startswith("fr") else "en"


def _send(chat_id: int, text: str) -> None:
    _client.post(f"{API}/sendMessage", json={"chat_id": chat_id, "text": text, "parse_mode": "HTML",
                                                        "disable_web_page_preview": True})


def render(card: dict, ui: str) -> str:
    lang = card.get("language") if card.get("language") in TEXT else ui
    t, e = TEXT[lang], html.escape
    out = [f"<b>{LABEL[lang].get(card['verdict'], card['verdict'])}</b>  ({round(card.get('confidence', 0) * 100)}%)",
           e(card.get("headline", ""))]
    if card.get("why"):
        out += ["", f"<b>{t['why']}</b>"] + [f"- {e(w['text'])}" for w in card["why"][:4]]
    if card.get("do_now"):
        out += ["", f"<b>{t['do']}</b>"] + [f"- {e(d)}" for d in card["do_now"]]
    if card.get("dont"):
        out += ["", f"<b>{t['dont']}</b>"] + [f"- {e(d)}" for d in card["dont"][:3]]
    out += ["", f"{t['trace']}: {SITE}"]
    return "\n".join(out)[:4000]


def _photo(file_id: str) -> tuple[str, str] | None:
    meta = _client.get(f"{API}/getFile", params={"file_id": file_id}).json()
    path = (meta.get("result") or {}).get("file_path")
    if not path or (meta["result"].get("file_size") or 0) > 6_000_000:
        return None
    raw = _client.get(f"https://api.telegram.org/file/bot{TOKEN}/{path}").content
    return base64.b64encode(raw).decode(), "image/jpeg"


def _check(chat_id: int, ui: str, text: str, photo_id: str) -> None:
    try:
        image = _photo(photo_id) if photo_id else None
        card = agents.run_check(text, image=image, echo=False)
        _send(chat_id, render(card, ui) if "verdict" in card else html.escape(card.get("error", TEXT[ui]["error"])))
    except Exception:
        _send(chat_id, TEXT[ui]["error"])


def handle(update: dict) -> None:
    msg = update.get("message") or update.get("edited_message") or {}
    chat_id = (msg.get("chat") or {}).get("id")
    if not chat_id:
        return
    ui = _lang((msg.get("from") or {}).get("language_code", ""))
    text = (msg.get("text") or msg.get("caption") or "")[:4000]
    photo_id = msg["photo"][-1]["file_id"] if msg.get("photo") else ""
    if text.startswith("/start") or text.startswith("/help") or (not text and not photo_id):
        _send(chat_id, TEXT[ui]["start"])
        return
    ok, wait = security.allowed(f"tg:{chat_id}", "check")  # per chat, since every update comes from Telegram's own IPs
    if not ok:
        _send(chat_id, TEXT[ui]["busy"].format(s=wait))
        return
    _send(chat_id, TEXT[ui]["wait"])
    threading.Thread(target=_check, args=(chat_id, ui, text, photo_id), daemon=True).start()
