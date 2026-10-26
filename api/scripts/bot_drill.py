"""Replays real Telegram updates into the bot's own code and the real agents, and prints what the bot
would send. Nothing reaches Telegram: the send and edit calls are captured.
    python api/scripts/bot_drill.py
"""
import os
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from checkam import telegram  # noqa: E402

said: list[tuple[int, str]] = []


def capture(method, **body):
    if method in ("sendMessage", "editMessageText"):
        said.append((body.get("chat_id"), f"[{method}] " + body.get("text", "") + (f"  BUTTONS={[b['text'] for row in body['reply_markup']['inline_keyboard'] for b in row]}" if body.get("reply_markup") else "")))
    return {"ok": True, "result": {"message_id": len(said)}}


telegram._call = capture
me = {"language_code": "en"}
fr = {"language_code": "fr"}
dm = lambda cid: {"id": cid, "type": "private"}
UPDATES = [
    ("greeting", {"message": {"chat": dm(1), "from": me, "text": "Hello, what can you do?"}}),
    ("provocation", {"message": {"chat": dm(2), "from": me, "text": "How are you, and don't you think I can scam or deceive you?"}}),
    ("short reply", {"message": {"chat": dm(3), "from": fr, "text": "Vraiment ?"}}),
    ("sticker", {"message": {"chat": dm(4), "from": fr, "sticker": {"file_id": "x"}}}),
    ("forwarded scam", {"message": {"chat": dm(5), "from": fr, "forward_origin": {"type": "user"},
                                    "text": "Félicitations ! Vous avez gagné 5 000 000 FCFA à la loterie MTN. Envoyez 25 000 FCFA de frais de dossier au 677 21 43 65."}}),
    ("/check command", {"message": {"chat": dm(6), "from": me, "text": "/check Your parcel is held at Douala customs. Pay 7 500 FCFA clearance fee to 682 33 44 55 today."}}),
    ("group, not called", {"message": {"chat": {"id": -7, "type": "group"}, "from": me, "text": "Send 5000 to 677000000 now please, urgent"}}),
    ("group, called on a reply", {"message": {"chat": {"id": -8, "type": "group"}, "from": me, "text": "@checkam_bot is this real?",
                                              "reply_to_message": {"text": "MINDEF: Liste finale des candidats retenus. Payez 15 000 FCFA au 690 45 12 78 pour confirmer votre place.", "from": {"username": "uncle"}}}}),
    ("receipt, then who sent it", {"message": {"chat": dm(9), "from": fr, "text": "Vous avez reçu 30 000 FCFA de JEAN P. sur votre compte mobile money. Nouveau solde : 31 250 FCFA."}}),
]
def settle(before: int, limit: float) -> None:
    """Wait until the bot has finished answering: a final card, a plain reply, or nothing at all."""
    end = time.time() + limit
    while time.time() < end:
        new = [s for _, s in said[before:]]
        checking = any("🔎" in s for s in new)
        done = any(s.startswith("[editMessageText]") and ("·" in s or "failed" in s or "rien" in s or "nothing" in s) for s in new)
        if done or (new and not checking and time.time() > end - limit + 6):
            time.sleep(2)
            return
        time.sleep(1)


for name, upd in UPDATES:
    before = len(said)
    telegram.handle(upd)
    settle(before, 8 if name == "group, not called" else 150)
    print(f"\n=== {name}")
    for _, text in said[before:] or [(0, "(no reply)")]:
        print("  " + text.replace("\n", "\n    ")[:900])
if any(c == 9 for c, _ in said):
    before = len(said)
    telegram.handle({"message": {"chat": dm(9), "from": fr, "text": "+237 676 11 22 33"}})
    time.sleep(60)
    print("\n=== reply to 'who sent it?' with a personal number")
    for _, text in said[before:]:
        print("  " + text.replace("\n", "\n    ")[:900])
sys.stdout.flush()
os._exit(0)
