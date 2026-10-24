# Times real checks against a running server: python api/scripts/smoke.py [base_url]
import json
import sys
import time
import urllib.request

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000"
CASES = [
    ("mistaken transfer, known number", "Hello please I sent 25000 frs to your MTN number by mistake, it was for my mother hospital bill. Please send it back to me on this number [PHONE:654-jwmukg] God will bless you. Do it fast before they cut my line"),
    ("fake anniversary survey link", "Felicitations! MTN - Cadeau 26e anniversaire. Participez a cette enquete et recevez 26 000 FCFA. Partagez avec 15 amis WhatsApp pour valider. http://mtn-cadeau26.click/promo"),
    ("genuine MTN promo", "Get up to 5000U bonus when you buy a bundle from 100U. Dial *222# to enjoy this limited-time offer"),
]
for name, text in CASES:
    t0 = time.time()
    req = urllib.request.Request(f"{BASE}/check", data=json.dumps({"text": text}).encode(), headers={"Content-Type": "application/json"})
    c = json.loads(urllib.request.urlopen(req, timeout=300).read())
    print(f"{time.time() - t0:5.1f}s  {name:32}  {c['verdict']:13} {c['confidence']}  rounds={c['rounds']}  campaign={c['campaign']}  | {c['headline']}")
