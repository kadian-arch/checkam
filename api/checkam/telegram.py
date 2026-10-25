"""Telegram bot: forward a message or a screenshot and get the same verdict as the app; talk to it and it
answers like a person would. Webhook mode, so it runs inside the API process on Render with no extra worker."""
import base64
import html
import re
import threading
import time
from urllib.parse import quote

import httpx

from . import agents, assistant, config, security

TOKEN = config.env("TELEGRAM_BOT_TOKEN")
SECRET = config.env("TELEGRAM_WEBHOOK_SECRET")
API = f"https://api.telegram.org/bot{TOKEN}"
_client = httpx.Client(timeout=30)
SITE = config.env("CHECKAM_PUBLIC_URL", "https://checkam.me")

LABEL = {
    "en": {"scam": "🔴 SCAM", "suspicious": "🟠 BE CAREFUL", "looks_genuine": "🟢 LOOKS GENUINE", "cant_tell": "⚪ CAN'T TELL YET"},
    "fr": {"scam": "🔴 ARNAQUE", "suspicious": "🟠 PRUDENCE", "looks_genuine": "🟢 SEMBLE AUTHENTIQUE", "cant_tell": "⚪ IMPOSSIBLE DE TRANCHER"},
}
TEXT = {
    "en": {"start": "Hi, I'm CheckAm 🛡️\n\nForward me any message about money that feels off (SMS, WhatsApp, a job, a scholarship, a prize), or send a screenshot. "
                    "Five agents check it against real scam reports and official messages, then tell you what it is, why, and what to do.\n\nTry it: forward the last suspicious message you got.",
           "wait": "🔎 Checking…", "busy": "Too many checks from this chat. Try again in {s} s.",
           "why": "Why", "do": "What to do", "dont": "Don't", "error": "The check failed. Please try again in a minute.",
           "web": "🌐 Full evidence", "warn": "📣 Warn a friend", "share": "I checked this message with CheckAm: {v}. Check yours before you send money:",
           "who": "Who sent it? Reply with the name or number shown at the top of the message on your phone, and I'll check again.",
           "seconds": "checked in {s} s", "again": "Seen before: same answer as {n} earlier check(s)",
           "stage": {"Intake": "📖 Reading the message", "Planner": "🧭 Planning the checks", "Investigator": "🔍 Searching scam reports and real operator messages",
                     "Critic": "⚖️ The critic is arguing the other side", "Reporter": "✍️ Writing your answer"}},
    "fr": {"start": "Bonjour, je suis CheckAm 🛡️\n\nTransférez-moi un message d'argent qui vous paraît louche (SMS, WhatsApp, emploi, bourse, gain), ou une capture d'écran. "
                    "Cinq agents le vérifient avec de vrais signalements et de vrais messages officiels, puis vous disent ce que c'est, pourquoi, et quoi faire.\n\nEssayez : transférez le dernier message suspect que vous avez reçu.",
           "wait": "🔎 Vérification…", "busy": "Trop de vérifications depuis ce chat. Réessayez dans {s} s.",
           "why": "Pourquoi", "do": "Que faire", "dont": "À ne pas faire", "error": "La vérification a échoué. Réessayez dans une minute.",
           "web": "🌐 Toutes les preuves", "warn": "📣 Prévenir un proche", "share": "J'ai vérifié ce message avec CheckAm : {v}. Vérifiez les vôtres avant d'envoyer de l'argent :",
           "who": "Qui l'a envoyé ? Répondez avec le nom ou le numéro affiché en haut du message sur votre téléphone, et je vérifie à nouveau.",
           "seconds": "vérifié en {s} s", "again": "Déjà vu : même réponse que {n} vérification(s) précédente(s)",
           "stage": {"Intake": "📖 Lecture du message", "Planner": "🧭 Choix des vérifications", "Investigator": "🔍 Recherche dans les signalements et les vrais messages",
                     "Critic": "⚖️ Le critique défend l'autre hypothèse", "Reporter": "✍️ Rédaction de votre réponse"}},
}
# a message worth checking carries something that can cost money: a link, a number, an amount, a code, a demand
SIGNALS = re.compile(r"(?i)https?://|www\.|\b[a-z0-9-]+\.(com|cm|net|org|me|xyz|top|online|site|link|info|app)\b|[*#]\d{2,4}|\b[26]\d{8}\b|\d[\d .,]*\s*(f|fcfa|xaf|frs?|francs?)\b|"
                     r"\b(pin|otp|code|momo|mobile money|orange money|transf|envoy|send|pay|pai|gagn|won|prize|visa|bourse|scholarship|recrut|job|emploi|loan|pr[êe]t|invest|bonus|cadeau|promo)\b")
_pending: dict[int, tuple[float, str]] = {}  # chat -> (when, message waiting for its sender)


def enabled() -> bool:
    return bool(TOKEN and SECRET)


def _lang(code: str) -> str:
    return "fr" if (code or "").lower().startswith("fr") else "en"


def _call(method: str, **body) -> dict:
    try:
        return _client.post(f"{API}/{method}", json=body).json()
    except (httpx.HTTPError, ValueError):
        return {}


def _send(chat_id: int, text: str, buttons: list | None = None) -> int | None:
    body = {"chat_id": chat_id, "text": text, "parse_mode": "HTML", "disable_web_page_preview": True}
    if buttons:
        body["reply_markup"] = {"inline_keyboard": buttons}
    return ((_call("sendMessage", **body)).get("result") or {}).get("message_id")


def _edit(chat_id: int, message_id: int | None, text: str, buttons: list | None = None) -> None:
    if not message_id:
        _send(chat_id, text, buttons)
        return
    body = {"chat_id": chat_id, "message_id": message_id, "text": text, "parse_mode": "HTML", "disable_web_page_preview": True}
    if buttons:
        body["reply_markup"] = {"inline_keyboard": buttons}
    _call("editMessageText", **body)


def render(card: dict, ui: str, seconds: float | None = None) -> str:
    lang = card.get("language") if card.get("language") in TEXT else ui
    t, e = TEXT[lang], html.escape
    out = [f"<b>{LABEL[lang].get(card['verdict'], card['verdict'])}</b>  · {round(card.get('confidence', 0) * 100)}%", f"<b>{e(card.get('headline', ''))}</b>"]
    if card.get("explain"):
        out.append(e(card["explain"]))
    if card.get("why"):
        out += ["", f"<b>{t['why']}</b>"] + [f"• {e(w['text'])}" for w in card["why"][:4]]
    if card.get("do_now"):
        out += ["", f"<b>{t['do']}</b>"] + [f"✅ {e(d)}" for d in card["do_now"]]
    if card.get("dont"):
        out += ["", f"<b>{t['dont']}</b>"] + [f"⛔ {e(d)}" for d in card["dont"][:3]]
    foot = []
    if card.get("cached"):
        foot.append(t["again"].format(n=card["cached"]))
    if seconds is not None:
        foot.append(t["seconds"].format(s=round(seconds)))
    if foot:
        out += ["", "<i>" + " · ".join(foot) + "</i>"]
    return "\n".join(out)[:4000]


def buttons(card: dict, ui: str) -> list:
    lang = card.get("language") if card.get("language") in TEXT else ui
    t = TEXT[lang]
    verdict = LABEL[lang].get(card["verdict"], "").split(" ", 1)[-1]
    share = f"https://t.me/share/url?url={quote(SITE)}&text={quote(t['share'].format(v=verdict))}"
    return [[{"text": t["web"], "url": SITE}, {"text": t["warn"], "url": share}]]


def _photo(file_id: str) -> tuple[str, str] | None:
    meta = _call("getFile", file_id=file_id)
    path = (meta.get("result") or {}).get("file_path")
    if not path or (meta["result"].get("file_size") or 0) > 6_000_000:
        return None
    raw = _client.get(f"https://api.telegram.org/file/bot{TOKEN}/{path}").content
    return base64.b64encode(raw).decode(), "image/jpeg"


def wants_check(msg: dict, text: str) -> bool:
    """Forwarded messages and screenshots are always checked; a sentence typed to the bot is a conversation
    unless it carries something that can cost money."""
    if msg.get("photo") or any(k in msg for k in ("forward_origin", "forward_from", "forward_sender_name", "forward_date")):
        return True
    words = len(text.split())
    if SIGNALS.search(text) and words >= 4:
        return True
    if words >= 25:
        return True
    if words <= 8:
        return False
    kind = assistant.classify(text)
    return kind == "check"


def _progress(chat_id: int, message_id: int | None, lang: str):
    seen, last = set(), [0.0]

    def on_line(line: dict) -> None:
        agent = line.get("agent_name")
        if agent in seen or agent not in TEXT[lang]["stage"] or time.monotonic() - last[0] < 2.5:
            return
        seen.add(agent)
        last[0] = time.monotonic()
        _edit(chat_id, message_id, f"{TEXT[lang]['wait']}\n{TEXT[lang]['stage'][agent]}…")
    return on_line


def _check(chat_id: int, ui: str, text: str, photo_id: str, sender: str = "") -> None:
    lang = ui if not text else ("fr" if agents._guess_lang(text) == "fr" else ui)
    mid = _send(chat_id, TEXT[lang]["wait"])
    _call("sendChatAction", chat_id=chat_id, action="typing")
    started = time.monotonic()
    try:
        image = _photo(photo_id) if photo_id else None
        card = agents.run_check(text, image=image, sender=sender, echo=False, on_line=_progress(chat_id, mid, lang))
        if "verdict" not in card:
            _edit(chat_id, mid, html.escape(card.get("error", TEXT[lang]["error"])))
            return
        _edit(chat_id, mid, render(card, ui, time.monotonic() - started), buttons(card, ui))
        if card["verdict"] == "cant_tell" and not sender and text:
            _pending[chat_id] = (time.monotonic(), text)
            _send(chat_id, TEXT[card.get("language") if card.get("language") in TEXT else ui]["who"])
    except Exception:
        _edit(chat_id, mid, TEXT[lang]["error"])


def _chat(chat_id: int, ui: str, text: str) -> None:
    _call("sendChatAction", chat_id=chat_id, action="typing")
    lang = "fr" if agents._guess_lang(text) == "fr" else ui
    _send(chat_id, html.escape(assistant.reply(text, lang) or TEXT[lang]["start"]))


def handle(update: dict) -> None:
    msg = update.get("message") or {}  # edits are ignored: a corrected message is not checked twice
    chat_id = (msg.get("chat") or {}).get("id")
    if not chat_id:
        return
    ui = _lang((msg.get("from") or {}).get("language_code", ""))
    text = (msg.get("text") or msg.get("caption") or "")[:4000]
    photo_id = msg["photo"][-1]["file_id"] if msg.get("photo") else ""
    if text.startswith("/start") or text.startswith("/help") or (not text and not photo_id):
        _send(chat_id, TEXT[ui]["start"])
        return
    # a short reply right after "who sent it?" is the sender of the message waiting for a second check
    waiting = _pending.pop(chat_id, None)
    if waiting and time.monotonic() - waiting[0] < 900 and not photo_id and len(text.split()) <= 5 and "forward_origin" not in msg:
        sender = text.strip()
        target, args = _check, (chat_id, ui, waiting[1], "", sender)
    elif wants_check(msg, text):
        target, args = _check, (chat_id, ui, text, photo_id)
    else:
        ok, wait = security.allowed(f"tgchat:{chat_id}", "default")
        if ok:
            threading.Thread(target=_chat, args=(chat_id, ui, text), daemon=True).start()
        return
    ok, wait = security.allowed(f"tg:{chat_id}", "check")  # per chat, since every update comes from Telegram's own IPs
    if not ok:
        _send(chat_id, TEXT[ui]["busy"].format(s=wait))
        return
    threading.Thread(target=target, args=args, daemon=True).start()

