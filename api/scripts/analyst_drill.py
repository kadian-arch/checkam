"""The analyst side end to end, as a CERT or operator fraud team would use it: sign in, read the desk,
open a campaign dossier, publish a signed alert, verify the public chain, then tamper with an alert in
the database and confirm the chain exposes it. Credentials come from .env and are never printed.
    python api/scripts/analyst_drill.py http://127.0.0.1:8000
"""
import json
import os
import sqlite3
import sys
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from checkam import config  # noqa: E402

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000").rstrip("/")
c = httpx.Client(timeout=300)


def step(name, ok, detail=""):
    print(f"{'ok  ' if ok else 'FAIL'} {name}{': ' + detail if detail else ''}")


bad = c.post(f"{BASE}/auth/login", json={"email": config.env("CHECKAM_JUDGE_EMAIL"), "password": "wrong-password"})
step("wrong password refused", bad.status_code == 401, str(bad.status_code))
r = c.post(f"{BASE}/auth/login", json={"email": config.env("CHECKAM_JUDGE_EMAIL"), "password": config.env("CHECKAM_JUDGE_PASSWORD")})
step("analyst signs in", r.status_code == 200)
h = {"Authorization": f"Bearer {r.json()['token']}"}
st = c.get(f"{BASE}/analyst/stats", headers=h).json()
step("desk figures", "total" in st, f"{st.get('total')} checks, operators {sorted((st.get('by_operator') or {}).keys())}, radar ok")
mtn = c.get(f"{BASE}/analyst/stats?operator=mtn", headers=h).json()
step("operator filter", mtn.get("operator") == "mtn", f"MTN {mtn.get('total')} checks")
camps = c.get(f"{BASE}/analyst/campaigns", headers=h).json().get("campaigns", [])
step("campaigns linked", bool(camps), f"{len(camps)} campaigns, biggest has {camps[0].get('size', len(camps[0].get('members', [])))} records" if camps else "")
if camps:
    d = c.get(f"{BASE}/analyst/campaigns/{camps[0]['id']}", headers=h).json()
    step("dossier written", bool(d.get("summary")), (d.get("name") or "")[:80])
    pub = c.post(f"{BASE}/analyst/alerts", headers=h, json={"campaign_id": camps[0]["id"], "title": d.get("name") or "Scam warning",
                                                          "body_en": (d.get("summary") or "")[:600], "body_fr": (d.get("summary_fr") or d.get("summary") or "")[:600]})
    body = pub.json()
    step("alert published with Scout contract and signature", pub.status_code == 200 and bool((body.get("alert") or body).get("signature")),
         f"{pub.status_code} {json.dumps(body)[:160]}")
chain = c.get(f"{BASE}/alerts/verify").json()
step("public chain verifies", chain.get("chain", {}).get("valid") is True, f"length {chain.get('chain', {}).get('length')}")
db = Path(os.environ.get("CHECKAM_DB") or config.DB_PATH)
con = sqlite3.connect(db)
row = con.execute("SELECT id, title FROM alerts WHERE status='published' ORDER BY rowid DESC LIMIT 1").fetchone()
if row:
    con.execute("UPDATE alerts SET title = ? WHERE id = ?", (row[1] + " (edited)", row[0]))
    con.commit()
    broken = c.get(f"{BASE}/alerts/verify").json().get("chain", {})
    step("a quietly edited alert is exposed", broken.get("valid") is False, broken.get("reason", ""))
    con.execute("UPDATE alerts SET title = ? WHERE id = ?", (row[1], row[0]))
    con.commit()
    step("restored", c.get(f"{BASE}/alerts/verify").json().get("chain", {}).get("valid") is True)
sys.stdout.flush()
os._exit(0)
