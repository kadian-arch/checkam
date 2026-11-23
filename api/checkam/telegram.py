"""Telegram bot: forward a message or a screenshot and get the same verdict as the app; talk to it and it
answers like a person would. Webhook mode, so it runs inside the API process on Render with no extra worker."""
import base64
import html
import re
import threading
import time
from urllib.parse import quote

import httpx

from . import agents, assistant, claims, config, security

TOKEN = config.env("TELEGRAM_BOT_TOKEN")
SECRET = config.env("TELEGRAM_WEBHOOK_SECRET")
API = f"https://api.telegram.org/bot{TOKEN}"
_client = httpx.Client(timeout=30)
SITE = config.env("CHECKAM_PUBLIC_URL", "https://checkam.me")

LABEL = {
    "en": {"scam": "🔴 SCAM", "suspicious": "🟠 BE CAREFUL", "looks_genuine": "🟢 LOOKS GENUINE", "cant_tell": "⚪ NEED MORE DETAILS", "quiet": "⚪ NOTHING TO CHECK YET"},
    "fr": {"scam": "🔴 ARNAQUE", "suspicious": "🟠 PRUDENCE", "looks_genuine": "🟢 SEMBLE AUTHENTIQUE", "cant_tell": "⚪ IL FAUT PLUS DE DÉTAILS", "quiet": "⚪ RIEN À VÉRIFIER POUR L'INSTANT"},
}
EVIDENCE = {
    "en": {"strong": "strong evidence", "positive": "positive signs", "limited": "limited evidence, confirm at the source", "none": "not enough to judge", "quiet": "nothing risky in it"},
    "fr": {"strong": "preuves solides", "positive": "signes positifs", "limited": "preuves limitées, confirmez à la source", "none": "pas assez d'éléments", "quiet": "rien de risqué dedans"},
}
TEXT = {
    "en": {"start": "Hi, I'm CheckAm 🛡️\n\nForward me anything that feels off (a message, a job or scholarship offer, a prize, a seller, a romance, a threat), or send screenshots. "
                    "I compare it with real scam reports and official messages, then tell you what it is, why, and what to do. There is no sign-up and I do not keep your number.\n\nTry it: forward the last suspicious message you got.",
           "wait": "🔎 Checking…", "busy": "Too many checks from this chat. Try again in {s} s.",
           "why": "Why", "do": "What to do", "dont": "Don't", "error": "The check failed. Please try again in a minute.",
           "web": "🔏 Signed answer", "warn": "📣 Warn a friend", "share": "I checked this message with CheckAm: {v}. Check yours before you send money:",
           "who": "Who sent it? Reply with the name or number shown at the top of the message on your phone, and I'll check again.",
           "ask": "To decide, I need to know:", "reply": "Just reply here in your own words and I'll check again with your answer.",
           "seconds": "checked in {s} s", "more": "(What I can add:", "unsupported": "I cannot listen to voice notes or open files yet. Type or paste what was said, or send a screenshot of the message, and I will check it.", "again": "Seen before: same answer as {n} earlier check(s)",
           "stage": {"Intake": "📖 Reading your message", "Planner": "🧭 Choosing what to check", "Investigator": "🔍 Checking it against known scams",
                     "Critic": "⚖️ Weighing the evidence", "Reporter": "✍️ Writing your answer"},
           "after_title": "What to do now, since you already {did}", "thanks": "Thank you. An analyst will look at this.", "gone": "I no longer have that check.",
           "did": {"money": "sent money", "code": "gave a code", "documents": "sent your ID", "clicked": "opened the link", "installed": "installed an app"},
           "paid": "💸 I paid", "gavecode": "🔑 I gave a code", "sentid": "🪪 I sent my ID", "right": "👍 Right answer", "wrong": "👎 Wrong answer"},
    "fr": {"start": "Bonjour, je suis CheckAm 🛡️\n\nTransférez-moi tout ce qui vous paraît louche (message, offre d'emploi ou de bourse, gain, vendeur, relation, menace), ou des captures d'écran. "
                    "Je le compare à de vrais signalements et de vrais messages officiels, puis je vous dis ce que c'est, pourquoi, et quoi faire. Aucune inscription, et je ne garde pas votre numéro.\n\nEssayez : transférez le dernier message suspect que vous avez reçu.",
           "wait": "🔎 Vérification…", "busy": "Trop de vérifications depuis ce chat. Réessayez dans {s} s.",
           "why": "Pourquoi", "do": "Que faire", "dont": "À ne pas faire", "error": "La vérification a échoué. Réessayez dans une minute.",
           "web": "🔏 Réponse signée", "warn": "📣 Prévenir un proche", "share": "J'ai vérifié ce message avec CheckAm : {v}. Vérifiez les vôtres avant d'envoyer de l'argent :",
           "who": "Qui l'a envoyé ? Répondez avec le nom ou le numéro affiché en haut du message sur votre téléphone, et je vérifie à nouveau.",
           "ask": "Pour trancher, j'ai besoin de savoir :", "reply": "Répondez simplement ici avec vos mots et je vérifie à nouveau avec votre réponse.",
           "more": "(Ce que je peux ajouter :",
           "seconds": "vérifié en {s} s", "unsupported": "Je ne peux pas encore écouter les messages vocaux ni ouvrir les fichiers. Écrivez ou collez ce qui a été dit, ou envoyez des captures d'écran du message, et je vérifie.", "again": "Déjà vu : même réponse que {n} vérification(s) précédente(s)",
           "stage": {"Intake": "📖 Lecture de votre message", "Planner": "🧭 Choix des vérifications", "Investigator": "🔍 Comparaison avec les arnaques connues",
                     "Critic": "⚖️ Pesée des preuves", "Reporter": "✍️ Rédaction de votre réponse"},
           "after_title": "Que faire maintenant, puisque vous avez déjà {did}", "thanks": "Merci. Un analyste va regarder cela.", "gone": "Je n'ai plus cette vérification.",
           "did": {"money": "envoyé de l'argent", "code": "donné un code", "documents": "envoyé votre pièce d'identité", "clicked": "ouvert le lien", "installed": "installé une application"},
           "paid": "💸 J'ai payé", "gavecode": "🔑 J'ai donné un code", "sentid": "🪪 J'ai envoyé ma pièce", "right": "👍 Bonne réponse", "wrong": "👎 Mauvaise réponse"},
}
# a message worth checking carries something that can cost money: a link, a number, an amount, a code, a demand
SIGNALS = re.compile(r"(?i)https?://|www\.|\b[a-z0-9-]+\.(com|cm|net|org|me|xyz|top|online|site|link|info|app)\b|[*#]\d{2,4}|\b[26]\d{8}\b|\d[\d .,]*\s*(f|fcfa|xaf|frs?|francs?)\b|"
                     r"\b(pin|otp|code|momo|mobile money|orange money|transf|envoy|send|pay|pai|gagn|won|prize|visa|bourse|scholarship|recrut|job|emploi|loan|pr[êe]t|invest|bonus|cadeau|promo)\b")
_pending: dict[int, tuple[float, str, str]] = {}  # chat -> (when, message waiting for more, sender known so far)


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
    t, e = TEXT[lang], (lambda s: html.escape(s, quote=False))  # Telegram needs only & < > escaped
    out = [f"<b>{LABEL[lang]['quiet'] if card.get('quiet') else LABEL[lang].get(card['verdict'], card['verdict'])}</b>  · {EVIDENCE[lang].get(card.get('evidence_level', 'limited'), '')}", f"<b>{e(card.get('headline', ''))}</b>"]
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
    # the signed answer travels with the warning, so whoever receives it can check it is real
    link = (card.get("receipt") or {}).get("url") or SITE
    share = f"https://t.me/share/url?url={quote(link)}&text={quote(t['share'].format(v=verdict))}"
    rows = [[{"text": t["web"], "url": link}, {"text": t["warn"], "url": share}]]
    cid = card.get("check_id")
    if cid and re.fullmatch(r"C-[0-9a-f]{8}", cid):
        if card["verdict"] != "looks_genuine" and not card.get("quiet"):
            rows.append([{"text": t["paid"], "callback_data": f"a:money:{cid}"}, {"text": t["gavecode"], "callback_data": f"a:code:{cid}"},
                         {"text": t["sentid"], "callback_data": f"a:documents:{cid}"}])
        rows.append([{"text": t["right"], "callback_data": f"f:right:{cid}"}, {"text": t["wrong"], "callback_data": f"f:wrong:{cid}"}])
    return rows


def _photo(file_id: str) -> tuple[str, str] | None:
    meta = _call("getFile", file_id=file_id)
    path = (meta.get("result") or {}).get("file_path")
    if not path or (meta["result"].get("file_size") or 0) > 6_000_000:
        return None
    raw = _client.get(f"https://api.telegram.org/file/bot{TOKEN}/{path}").content
    return base64.b64encode(raw).decode(), "image/jpeg"


def is_sender(text: str) -> bool:
    """A phone number, or a short name like "MTN" or "Customer Care": what the top of a message shows."""
    s = text.strip()
    return bool(re.fullmatch(r"[+\d\s().-]{6,20}", s)) or (len(s.split()) <= 3 and not re.search(r"(?i)\b(yes|no|oui|non|il|elle|he|she|they|asked|demand\w*|pay|code)\b", s))


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


def _check(chat_id: int, ui: str, text: str, photo_id: str | list[str], sender: str = "") -> None:
    lang = ui if not text else ("fr" if agents._guess_lang(text) == "fr" else ui)
    mid = _send(chat_id, TEXT[lang]["wait"])
    _call("sendChatAction", chat_id=chat_id, action="typing")
    started = time.monotonic()
    try:
        ids = [photo_id] if isinstance(photo_id, str) else list(photo_id)
        images = [p for p in (_photo(i) for i in ids[:agents.MAX_SHOTS] if i) if p]
        card = agents.run_check(text, images=images, sender=sender, echo=False, on_line=_progress(chat_id, mid, lang))
        if "verdict" not in card:
            _edit(chat_id, mid, html.escape(card.get("error", TEXT[lang]["error"]), quote=False))
            return
        _edit(chat_id, mid, render(card, ui, time.monotonic() - started), buttons(card, ui))
        if card["verdict"] in ("cant_tell", "suspicious") and text and (card.get("questions") or card.get("ask_sender")):
            # the agents ask what they need to decide; the next reply goes back to them with the message
            lang_ = card.get("language") if card.get("language") in TEXT else ui
            t = TEXT[lang_]
            asked = ([claims.GENERAL["sender"][1 if lang_ == "fr" else 0]] if card.get("ask_sender") else []) + card.get("questions", [])
            _pending[chat_id] = (time.monotonic(), text, sender)
            _send(chat_id, "\n".join([t["ask"]] + [f"❓ {html.escape(q, quote=False)}" for q in asked[:3]] + ["", t["reply"]]))
    except Exception:
        _edit(chat_id, mid, TEXT[lang]["error"])


def _chat(chat_id: int, ui: str, text: str) -> None:
    _call("sendChatAction", chat_id=chat_id, action="typing")
    lang = "fr" if agents._guess_lang(text) == "fr" else ui
    _send(chat_id, html.escape(assistant.reply(text, lang) or TEXT[lang]["start"], quote=False))


ALBUM_WAIT = 1.5  # seconds: Telegram delivers an album as one update per photo, a moment apart
_albums: dict[tuple[int, str], dict] = {}
_albums_lock = threading.Lock()


def _album_add(chat_id: int, ui: str, msg: dict, text: str) -> None:
    """Screenshots sent together are one conversation: gather them, then check them once, in order."""
    key = (chat_id, str(msg["media_group_id"]))
    with _albums_lock:
        first = key not in _albums
        album = _albums.setdefault(key, {"shots": [], "text": ""})
        album["shots"].append((msg.get("message_id", 0), msg["photo"][-1]["file_id"]))
        album["text"] = album["text"] or text
    if first:
        threading.Timer(ALBUM_WAIT, _album_done, args=(key, ui)).start()


def _album_done(key: tuple[int, str], ui: str) -> None:
    with _albums_lock:
        album = _albums.pop(key, None)
    if not album:
        return
    chat_id = key[0]
    ok, wait = security.allowed(f"tg:{chat_id}", "check")  # an album is one check, not one per photo
    if not ok:
        _send(chat_id, TEXT[ui]["busy"].format(s=wait))
        return
    _check(chat_id, ui, album["text"], [fid for _, fid in sorted(album["shots"])])


def _callback(cq: dict) -> None:
    """A press on one of the answer's buttons: what to do after what you already did, or whether the answer was right."""
    from . import advice, store
    chat_id = ((cq.get("message") or {}).get("chat") or {}).get("id")
    ui = _lang((cq.get("from") or {}).get("language_code", ""))
    t = TEXT[ui]
    m = re.fullmatch(r"([af]):([a-z_]+):(C-[0-9a-f]{8})", cq.get("data") or "")
    if not chat_id or not m:
        _call("answerCallbackQuery", callback_query_id=cq.get("id"))
        return
    ok, _ = security.allowed(f"tgcb:{chat_id}", "default")
    if not ok:
        _call("answerCallbackQuery", callback_query_id=cq.get("id"))
        return
    kind, what, check_id = m.groups()
    row = store.get_check(check_id)
    if not row:
        _call("answerCallbackQuery", callback_query_id=cq.get("id"), text=t["gone"])
        return
    lang = row.get("language") if row.get("language") in TEXT else ui
    t = TEXT[lang]
    if kind == "a" and what in advice.ACTED:
        steps = advice.after_action(what, [row.get("operator") or ""], lang)
        _call("answerCallbackQuery", callback_query_id=cq.get("id"))
        _send(chat_id, f"<b>{html.escape(t['after_title'].format(did=t['did'].get(what, what)), quote=False)}</b>\n" + "\n".join(f"✅ {html.escape(x, quote=False)}" for x in steps))
    elif kind == "f" and what in ("right", "wrong"):
        if what == "wrong":
            store.add_flag(check_id, "", "via Telegram: the person says this answer is wrong")
        _call("answerCallbackQuery", callback_query_id=cq.get("id"), text=t["thanks"])
    else:
        _call("answerCallbackQuery", callback_query_id=cq.get("id"))


def handle(update: dict) -> None:
    if update.get("callback_query"):
        _callback(update["callback_query"])
        return
    msg = update.get("message") or {}  # edits are ignored: a corrected message is not checked twice
    chat_id = (msg.get("chat") or {}).get("id")
    if not chat_id:
        return
    ui = _lang((msg.get("from") or {}).get("language_code", ""))
    text = (msg.get("text") or msg.get("caption") or "")[:4000]
    if (msg.get("chat") or {}).get("type") in ("group", "supergroup"):
        # in a group the bot speaks only when someone calls it: a mention, a reply to it, or /check
        me = config.env("TELEGRAM_BOT_USERNAME", "checkam_bot").lower()
        replied = ((msg.get("reply_to_message") or {}).get("from") or {}).get("username", "").lower() == me
        called = f"@{me}" in text.lower() or text.startswith("/check")
        if not (called or replied):
            return
        target = msg.get("reply_to_message") if called and msg.get("reply_to_message") else None
        if target:  # "@checkam_bot" in reply to a suspicious message: check that message
            msg, text = target, (target.get("text") or target.get("caption") or "")[:4000]
        text = re.sub(rf"(?i)@{re.escape(me)}|^/check\S*", "", text).strip()
    if text.startswith("/check"):
        text = re.sub(r"^/check(@\w+)?", "", text).strip()  # "/check <message>" works anywhere
        if not text and not msg.get("photo"):
            _send(chat_id, TEXT[ui]["start"])
            return
    doc = msg.get("document") or {}
    if str(doc.get("mime_type", "")).startswith("image/"):
        msg = {**msg, "photo": [{"file_id": doc["file_id"]}]}  # a screenshot sent "as a file"
    if not text and not msg.get("photo") and not msg.get("text"):
        # stickers, voice notes, files, locations: say what works instead of guessing
        _send(chat_id, TEXT[ui]["unsupported"])
        return
    if msg.get("media_group_id") and msg.get("photo"):
        _album_add(chat_id, ui, msg, text)
        return
    photo_id = msg["photo"][-1]["file_id"] if msg.get("photo") else ""
    if text.startswith("/start") or text.startswith("/help") or (not text and not photo_id):
        _send(chat_id, TEXT[ui]["start"])
        return
    # a reply right after the agents' questions answers them: a bare name or number is the sender,
    # anything longer is what the person adds, checked together with the message
    waiting = _pending.pop(chat_id, None)
    if waiting and time.monotonic() - waiting[0] < 900 and not photo_id and "forward_origin" not in msg and len(text.split()) < 40:
        when, held, known = waiting
        if not known and is_sender(text):
            target, args = _check, (chat_id, ui, held, "", text.strip())
        else:
            more = f"{held}\n\n{TEXT['fr' if agents._guess_lang(held) == 'fr' else ui]['more']} {text.strip()})"
            target, args = _check, (chat_id, ui, more, "", known)
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

