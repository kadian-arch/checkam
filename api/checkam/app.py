import base64
import hmac
import re
import json
import queue
import threading

from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import agents, config, dossier, ledger, security, seed, store, telegram
from .adapters import memory, nvidia, scout, world
from .adapters.data import data

app = FastAPI(title="CheckAm", version="0.1.0", description="Before you send, CheckAm.")
# the web app is served from the same origin; other origins only when listed in CHECKAM_ORIGINS
origins = [o.strip() for o in config.env("CHECKAM_ORIGINS").split(",") if o.strip()]
if origins:
    app.add_middleware(CORSMiddleware, allow_origins=origins, allow_methods=["GET", "POST"], allow_headers=["Authorization", "Content-Type"])
app.middleware("http")(security.middleware)
app.add_middleware(security.Compress)


@app.on_event("startup")
def _startup():
    if config.env("CHECKAM_JUDGE_EMAIL"):
        store.add_analyst(config.env("CHECKAM_JUDGE_EMAIL"), config.env("CHECKAM_JUDGE_PASSWORD"), "Judge analyst", "Open Agent Hackathon")
    def warm():
        if config.flag("CHECKAM_SEED_ON_START", True):
            seed.run()
        from .trace import Trace
        agents._scam_messages(Trace(echo=False))  # JDBC session + scam embeddings ready before the first citizen

    threading.Thread(target=warm, daemon=True).start()


class CheckIn(BaseModel):
    text: str = Field("", max_length=4000)
    sender: str = Field("", max_length=80)
    language: str = Field("", max_length=5)


class RunIn(BaseModel):
    mode: str = "check"
    text: str = Field("", max_length=4000)
    sender: str = Field("", max_length=80)
    language: str = ""
    campaign_id: str = ""


def analyst(authorization: str = Header(default="")) -> str:
    email = store.read_token(authorization.removeprefix("Bearer ").strip())
    if not email:
        raise HTTPException(401, "Sign in as an analyst")
    return email


@app.get("/health")
def health():
    w = world.health()
    return {"ok": True, "data_backend": data().mode, "sample_mode": config.SAMPLE_MODE, "nvidia": nvidia.enabled(),
            "world_model": bool(w), "world": w, "checks": store.check_stats()}


@app.post("/check")
def check(body: CheckIn):
    return agents.run_check(body.text, sender=body.sender, language=body.language)


def _stream(run):
    """Server-sent events: every agent step as it happens, then the verdict card."""
    q: queue.Queue = queue.Queue()

    def work():
        try:
            card = run(lambda line: q.put(("step", line)))
            q.put(("card", card))
        except Exception as e:  # the stream must always end with something the app can show
            q.put(("error", {"detail": str(e)[:200]}))
        q.put(None)

    threading.Thread(target=work, daemon=True).start()

    def events():
        while True:
            item = q.get()
            if item is None:
                return
            kind, payload = item
            yield f"event: {kind}\ndata: {json.dumps(payload, ensure_ascii=False, default=str)}\n\n"

    return StreamingResponse(events(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.post("/check/stream")
def check_stream(body: CheckIn):
    return _stream(lambda on_line: agents.run_check(body.text, sender=body.sender, language=body.language, on_line=on_line))


IMAGE_TYPES = {b"\x89PNG": "image/png", b"\xff\xd8\xff": "image/jpeg", b"GIF8": "image/gif", b"RIFF": "image/webp"}


async def _image(upload: UploadFile) -> tuple[str, str]:
    """Read at most 6 MB, and only real images: the type comes from the file's first bytes, not its name."""
    raw = await upload.read(6_000_001)
    if len(raw) > 6_000_000:
        raise HTTPException(413, "Image too large (6 MB max)")
    mime = next((m for sig, m in IMAGE_TYPES.items() if raw.startswith(sig)), None)
    if not mime or (mime == "image/webp" and raw[8:12] != b"WEBP"):
        raise HTTPException(415, "Send a screenshot (PNG, JPEG, WEBP or GIF)")
    return base64.b64encode(raw).decode(), mime


@app.post("/check/image/stream")
async def check_image_stream(image: UploadFile = File(...), text: str = Form("", max_length=4000), language: str = Form("", max_length=5)):
    img = await _image(image)
    return _stream(lambda on_line: agents.run_check(text, image=img, language=language, on_line=on_line))


@app.post("/check/image")
async def check_image(image: UploadFile = File(...), text: str = Form("", max_length=4000), language: str = Form("", max_length=5)):
    return agents.run_check(text, image=await _image(image), language=language)


@app.post("/run")
def run(body: RunIn):
    """Programmatic entry point for judges: {"mode": "check"|"investigate", ...}."""
    if body.mode == "investigate":
        return dossier.investigate(body.campaign_id or None)
    return agents.run_check(body.text, sender=body.sender, language=body.language)


class Login(BaseModel):
    email: str = Field(max_length=200)
    password: str = Field(max_length=200)


@app.post("/auth/login")
def login(body: Login):
    who = store.verify_analyst(body.email, body.password)
    if not who:
        raise HTTPException(401, "Wrong email or password")
    return {"token": store.make_token(who["email"]), "analyst": who}


@app.get("/analyst/campaigns")
def campaigns(_: str = Depends(analyst)):
    return dossier.overview()


@app.get("/analyst/campaigns/{campaign_id}")
def campaign(campaign_id: str, _: str = Depends(analyst)):
    return dossier.investigate(campaign_id)


@app.get("/analyst/stats")
def stats(operator: str = "", _: str = Depends(analyst)):
    w = world.health() or {}
    return {**store.analytics(operator=operator.lower()), "world": {"observations": w.get("observations"), "entities": w.get("entities"), "edges": w.get("edges")},
            "data_backend": data().mode}


@app.get("/stats/public")
def public_stats():
    s = store.check_stats()
    return {"checks": s["total"], "flagged": s["by_verdict"].get("scam", 0) + s["by_verdict"].get("suspicious", 0),
            "alerts": len(store.alerts(500)), "radar": store.radar()}


@app.get("/analyst/checks")
def checks(_: str = Depends(analyst)):
    return {"checks": store.recent_checks(100), "stats": store.check_stats()}


class AlertIn(BaseModel):
    campaign_id: str = ""
    title: str
    body_en: str
    body_fr: str = ""
    body_pcm: str = ""
    numbers: list[str] = []
    run_id: str = ""


@app.post("/analyst/alerts")
def publish(body: AlertIn, email: str = Depends(analyst)):
    """Publishing to every citizen is high risk: it needs a Scout contract, an operator-review approval
    by the signed-in analyst, and a verified signature before anything is written."""
    from .trace import Trace
    trace = Trace(body.run_id or None)
    d = scout.decide("publish the public alert for this campaign", surface="analyst", role="analyst", trace=trace, agent="Planner", user_id=email)
    contract = (d or {}).get("executionContract")
    if not contract or contract["intent"]["primary"]["id"] != "analyst.publish_alert":
        raise HTTPException(503, "Scout did not issue a publish contract")
    approved = scout.approve(contract, email, trace)
    if not approved or not scout.verify(approved, "alert.publish", trace):
        raise HTTPException(403, "Publish contract failed verification")
    row = store.publish_alert({**body.model_dump(), "published_by": email, "run_id": body.run_id, "contract_id": approved["contractId"]})
    trace.log("Reporter", "alert_published", output={"alert": row["id"], "contract": approved["contractId"], "approvals": approved["risk"]["approvals"]}, sponsor="meterless")
    # what the analyst confirmed becomes memory: later checks of the same scheme start from it
    memory.remember(f"{body.title}. {body.body_en}", "alert", "scam", f"analyst:{email}", [row["id"], body.campaign_id], trace, label="published alert")
    store.cache_clear()
    return {**row, "contract": {k: approved[k] for k in ("contractId", "parentId", "expiresAt", "signedBy")}, "approvals": approved["risk"]["approvals"]}


VERDICTS = ("scam", "suspicious", "looks_genuine")


class FlagIn(BaseModel):
    suggested: str = Field("not_sure", max_length=20)
    note: str = Field("", max_length=500)


@app.post("/checks/{check_id}/flag")
def flag(check_id: str, body: FlagIn):
    """'This answer looks wrong.' It goes to the analysts' queue; it never changes an answer or the memory by itself."""
    if not re.fullmatch(r"C-[0-9a-f]{8}", check_id) or body.suggested not in VERDICTS + ("not_sure",):
        raise HTTPException(400, "Unknown check or suggestion")
    row = store.add_flag(check_id, body.suggested, body.note)
    if not row:
        raise HTTPException(404, "Unknown check")
    return {"ok": True, "flag": row["id"]}


@app.get("/analyst/flags")
def flags(_: str = Depends(analyst)):
    return {"flags": store.open_flags()}


class ReviewIn(BaseModel):
    action: str = Field(max_length=10)
    verdict: str = Field("", max_length=20)
    note: str = Field("", max_length=500)


def _correct(check_id: str, verdict: str, note: str, email: str, refs: list[str]) -> dict:
    c = store.get_check(check_id)
    if not c or verdict not in VERDICTS:
        raise HTTPException(400, "Unknown check or verdict")
    content = f"{c['masked_text'][:600]}" + (f" | Analyst note: {note}" if note else "")
    m = memory.remember(content, "correction", verdict, f"analyst:{email}", refs, label=f"correction of {check_id}")
    if not m:
        raise HTTPException(503, "Memory engine unavailable")
    store.cache_clear()  # the next check of a similar message must hear the correction
    return m["memory"]


@app.post("/analyst/flags/{flag_id}")
def review_flag(flag_id: str, body: ReviewIn, email: str = Depends(analyst)):
    if body.action not in ("confirm", "dismiss"):
        raise HTTPException(400, "action is confirm or dismiss")
    row = store.close_flag(flag_id, "confirmed" if body.action == "confirm" else "dismissed", email)
    if not row:
        raise HTTPException(404, "Unknown flag")
    mem = _correct(row["check_id"], body.verdict or row["suggested"], body.note or row["note"], email, [row["check_id"], flag_id]) if body.action == "confirm" else None
    return {"flag": row, "memory": mem}


@app.post("/analyst/checks/{check_id}/correct")
def correct(check_id: str, body: ReviewIn, email: str = Depends(analyst)):
    return {"memory": _correct(check_id, body.verdict, body.note, email, [check_id])}


@app.get("/analyst/memory")
def memory_view(_: str = Depends(analyst)):
    return {"health": memory.health(), "memories": memory.memories(50)}


@app.post("/analyst/memory/sleep")
def memory_sleep(_: str = Depends(analyst)):
    out = memory.sleep()
    if out is None:
        raise HTTPException(503, "Memory engine unavailable")
    return out


@app.get("/alerts")
def public_alerts():
    return {"alerts": store.alerts(), "public_key": ledger.public_key_b64()}


@app.get("/alerts/verify")
def verify_ledger():
    """Anyone can check the whole published chain: signatures, contents and order."""
    return {"chain": ledger.verify_chain(store.alerts(10_000, oldest_first=True)), "public_key": ledger.public_key_b64(), "algorithm": "Ed25519 over SHA-256 of canonical JSON"}


@app.get("/alerts/verify/{alert_id}")
def verify_alert(alert_id: str):
    a = next((x for x in store.alerts(10_000) if x["id"] == alert_id), None)
    if not a:
        raise HTTPException(404, "No such alert")
    return {"alert": a, **ledger.verify(a), "public_key": ledger.public_key_b64()}


@app.post("/telegram/{secret}")
def telegram_webhook(secret: str, update: dict, x_telegram_bot_api_secret_token: str = Header(default="")):
    # two checks: the secret path and the header Telegram sends back, both set when the webhook is registered
    if not telegram.enabled() or not hmac.compare_digest(secret, telegram.SECRET) or not hmac.compare_digest(x_telegram_bot_api_secret_token, telegram.SECRET):
        raise HTTPException(404)
    telegram.handle(update)
    return {"ok": True}


class Match(BaseModel):
    text: str = Field(max_length=4000)


@app.get("/receipts/{rid}")
def receipt(rid: str):
    """Is this CheckAm answer real? Anyone can ask; the answer says only the verdict, the kind of scam and when."""
    r = store.get_receipt(rid) if re.fullmatch(r"C-[0-9a-f]{8}", rid) else None
    if not r:
        raise HTTPException(404, "No CheckAm answer has this number")
    return {"receipt": {k: r[k] for k in ("id", "created", "verdict", "confidence", "scheme")}, **ledger.verify_receipt(r),
            "public_key": ledger.public_key_b64()}


@app.post("/receipts/{rid}/match")
def receipt_match(rid: str, body: Match):
    """Paste the message you were shown: is it the one CheckAm checked?"""
    r = store.get_receipt(rid) if re.fullmatch(r"C-[0-9a-f]{8}", rid) else None
    if not r:
        raise HTTPException(404, "No CheckAm answer has this number")
    return {"same_message": ledger.text_fingerprint(body.text) == r["text_sha256"]}


@app.get("/traces/{run_id}")
def get_trace(run_id: str):
    p = config.LOG_DIR / f"trace-{run_id}.jsonl"
    if not run_id.isalnum() or not p.exists():
        raise HTTPException(404, "No such run")
    return {"run_id": run_id, "lines": [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines()]}


WEB = config.ROOT / "web" / "dist"
if WEB.exists():
    app.mount("/assets", StaticFiles(directory=WEB / "assets"), name="assets")

    ROOT_WEB = WEB.resolve()

    @app.get("/{path:path}")
    def spa(path: str):
        # only files inside the built web folder; anything else ("../.env" included) gets the app page
        f = (WEB / path).resolve()
        inside = f == ROOT_WEB or ROOT_WEB in f.parents
        return FileResponse(f if path and inside and f.is_file() else WEB / "index.html")
