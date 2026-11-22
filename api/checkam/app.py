import base64
import hmac
import re
import json
import queue
import threading

from fastapi.exceptions import RequestValidationError
from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import agents, config, dossier, ledger, retention, security, seed, store, telegram
from .adapters import memory, nvidia, scout, world
from .adapters.data import data

# the interactive API pages are for developers: off on the live site unless CHECKAM_DOCS is set
_docs = config.flag("CHECKAM_DOCS", False)
app = FastAPI(title="CheckAm", version="0.1.0", description="Before you send, CheckAm.",
              docs_url="/docs" if _docs else None, redoc_url=None, openapi_url="/openapi.json" if _docs else None)
# the web app is served from the same origin; other origins only when listed in CHECKAM_ORIGINS
origins = [o.strip() for o in config.env("CHECKAM_ORIGINS").split(",") if o.strip()]
if origins:
    app.add_middleware(CORSMiddleware, allow_origins=origins, allow_methods=["GET", "POST"], allow_headers=["Authorization", "Content-Type"])
app.middleware("http")(security.middleware)
app.add_middleware(security.Compress)


@app.on_event("startup")
def _startup():
    if config.env("CHECKAM_ADMIN_EMAIL") and config.env("CHECKAM_ADMIN_PASSWORD"):
        store.add_analyst(config.env("CHECKAM_ADMIN_EMAIL"), config.env("CHECKAM_ADMIN_PASSWORD"), "Administrator", "CheckAm", role="admin")
    if config.env("CHECKAM_JUDGE_EMAIL"):
        store.add_analyst(config.env("CHECKAM_JUDGE_EMAIL"), config.env("CHECKAM_JUDGE_PASSWORD"), "Judge analyst", "Open Agent Hackathon")
    def warm():
        from .trace import Trace
        agents._scam_messages(Trace(echo=False))  # data session open and the meaning vectors on their way first
        if config.flag("CHECKAM_SEED_ON_START", True):
            seed.run()

    threading.Thread(target=warm, daemon=True).start()

    def tidy():
        import time
        while True:
            try:
                retention.run(who="schedule")
            except Exception:
                pass  # tidying never takes the service down
            try:
                backfill_titles()
            except Exception:
                pass
            time.sleep(24 * 3600)

    threading.Thread(target=tidy, daemon=True).start()


def translate_title(title: str) -> str:
    """A French title for an English one, when the analyst did not write it. Empty if the model is not available."""
    if not config.MODEL_API_KEY or not title.strip():
        return ""
    out = nvidia.chat_json([{"role": "system", "content": "Translate this public fraud-alert title into French. Keep names, websites and numbers exactly. Reply with JSON only: {\"fr\": \"...\"}"},
                            {"role": "user", "content": title[:200]}], max_tokens=120, agent="Reporter", action="translate_title") or {}
    fr = str(out.get("fr") or "").strip()
    return fr[:200] if fr and fr.lower() != title.lower() else ""


def backfill_titles() -> int:
    """Give every published alert a French title. The signed English record is never touched."""
    done = 0
    for a in store.alerts_missing_title_fr():
        fr = translate_title(a["title"])
        if fr:
            store.set_title_fr(a["id"], fr)
            done += 1
    return done



@app.exception_handler(RequestValidationError)
async def bad_request(_, exc: RequestValidationError):
    """What is wrong with the request, without echoing what the person typed."""
    return JSONResponse({"detail": [{"loc": list(e.get("loc", ())), "msg": e.get("msg", ""), "type": e.get("type", "")} for e in exc.errors()]}, status_code=422)


class CheckIn(BaseModel):
    text: str = Field("", max_length=4000)
    sender: str = Field("", max_length=80)
    language: str = Field("", max_length=5)
    context: dict = Field(default_factory=dict)


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
    """Alive or not. Counts and engine details are analyst-only (/analyst/stats)."""
    return {"ok": True}


@app.post("/check")
def check(body: CheckIn):
    return agents.run_check(body.text, sender=body.sender, language=body.language, context=body.context)


def _ctx(raw: str) -> dict:
    try:
        d = json.loads(raw) if raw else {}
    except ValueError:
        return {}
    return d if isinstance(d, dict) else {}


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
    return _stream(lambda on_line: agents.run_check(body.text, sender=body.sender, language=body.language, on_line=on_line, context=body.context))


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


async def _images(uploads: list[UploadFile]) -> list[tuple[str, str]]:
    """One screenshot or several of the same conversation, in the order they were attached."""
    if len(uploads) > agents.MAX_SHOTS:
        raise HTTPException(413, f"Too many screenshots ({agents.MAX_SHOTS} max)")
    return [await _image(u) for u in uploads]


@app.post("/check/image/stream")
async def check_image_stream(image: list[UploadFile] = File(...), text: str = Form("", max_length=4000), sender: str = Form("", max_length=80),
                             language: str = Form("", max_length=5), context: str = Form("", max_length=600)):
    imgs = await _images(image)
    return _stream(lambda on_line: agents.run_check(text, images=imgs, sender=sender, language=language, on_line=on_line, context=_ctx(context)))


@app.post("/check/image")
async def check_image(image: list[UploadFile] = File(...), text: str = Form("", max_length=4000), sender: str = Form("", max_length=80),
                      language: str = Form("", max_length=5), context: str = Form("", max_length=600)):
    return agents.run_check(text, images=await _images(image), sender=sender, language=language, context=_ctx(context))


class AfterIn(BaseModel):
    acted: str = Field("", max_length=20)
    verdict: str = Field("", max_length=20)
    scheme: str = Field("", max_length=40)
    brands: list[str] = Field(default_factory=list, max_length=6)
    why: list[str] = Field(default_factory=list, max_length=4)
    language: str = Field("en", max_length=5)


@app.post("/advice/after")
def advice_after(body: AfterIn):
    """What to do now, given what the person has already done. Fixed official-only steps first; the model may add
    up to two more, kept only if they pass the same checks (no invented number, code or site)."""
    from . import advice
    lang = "fr" if body.language == "fr" else "en"
    if body.acted not in advice.ACTED or body.acted == "nothing":
        return {"steps": []}
    steps = advice.after_action(body.acted, [b for b in body.brands if isinstance(b, str)], lang)
    msgs = [{"role": "system", "content": "You advise a Cameroonian who may have been scammed. Reply with JSON only: {\"steps\": [up to 2 short imperative sentences]}. Never write a phone number, USSD code, website or promise of getting money back. Answer in " + ("French" if lang == "fr" else "English") + "."},
            {"role": "user", "content": json.dumps({"verdict": body.verdict, "kind": body.scheme, "reasons": body.why[:3], "already_done": body.acted, "fixed_steps": steps}, ensure_ascii=False)}]
    extra = (nvidia.chat_json(msgs, max_tokens=200, agent="Reporter", action="tailor") or {}).get("steps", []) if config.MODEL_API_KEY else []
    steps += [x for x in extra if isinstance(x, str) and advice.vetted(x) and x not in steps][:2]
    return {"steps": steps}


@app.post("/run")
def run(body: RunIn, authorization: str = Header(default="")):
    """Programmatic entry point for judges: {"mode": "check"|"investigate", ...}."""
    if body.mode == "investigate":
        analyst(authorization)  # a dossier is analyst work and spends model calls: signed-in analysts only
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


def _retention_words() -> dict:
    cfg = store.settings()
    return {"keep_months": round(cfg["check_keep_days"] / 30.4), "archive_months": round(cfg["archive_keep_days"] / 30.4) if cfg["archive_keep_days"] else 0}


@app.get("/stats/public")
def public_stats():
    s = store.check_stats()
    return {"checks": s["total"], "flagged": s["by_verdict"].get("scam", 0) + s["by_verdict"].get("suspicious", 0),
            "alerts": len(store.alerts(500)), "radar": store.radar(), "retention": _retention_words()}


@app.get("/analyst/checks")
def checks(_: str = Depends(analyst)):
    return {"checks": store.recent_checks(100), "stats": store.check_stats()}


class AlertIn(BaseModel):
    campaign_id: str = ""
    title: str
    body_en: str
    body_fr: str = ""
    body_pcm: str = ""
    title_fr: str = ""
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
    row = store.publish_alert({**{k: v for k, v in body.model_dump().items() if k != "title_fr"}, "published_by": email, "run_id": body.run_id, "contract_id": approved["contractId"]})
    trace.log("Reporter", "alert_published", output={"alert": row["id"], "contract": approved["contractId"], "approvals": approved["risk"]["approvals"]}, sponsor="meterless")
    # what the analyst confirmed becomes memory: later checks of the same scheme start from it
    memory.remember(f"{body.title}. {body.body_en}", "alert", "scam", f"analyst:{email}", [row["id"], body.campaign_id], trace, label="published alert")
    store.set_title_fr(row["id"], body.title_fr.strip() or translate_title(body.title))
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


# ======================= administrator =======================
def admin(authorization: str = Header(default="")) -> str:
    """Only an account with the administrator role. Analysts sign in the same way and do not get these."""
    email = analyst(authorization)
    if store.analyst_role(email) != "admin":
        raise HTTPException(403, "Administrator only")
    return email


@app.get("/admin/overview")
def admin_overview(_: str = Depends(admin)):
    return {"settings": store.settings(), "counts": store.counts(), "archive": retention.archive_files(), "last_retention": retention.last_run(),
            "engine": world.health(), "audit": store.admin_audit(20), "retention_preview": store.purge_preview()}


class SettingsIn(BaseModel):
    check_keep_days: int | None = None
    archive_keep_days: int | None = None
    answer_keep_days: int | None = None
    alert_show_days: int | None = None


@app.post("/admin/settings")
def admin_settings(body: SettingsIn, who: str = Depends(admin)):
    changes = {k: v for k, v in body.model_dump().items() if v is not None}
    try:
        out = store.update_settings(changes)
    except ValueError as e:
        raise HTTPException(400, str(e))
    store.admin_log(who, "settings", json.dumps(changes))
    return {"settings": out}


class RetentionIn(BaseModel):
    dry_run: bool = True


@app.post("/admin/retention")
def admin_retention(body: RetentionIn, who: str = Depends(admin)):
    """Run the cleanup now. Defaults to a dry run that only says what would happen."""
    out = retention.run(dry_run=body.dry_run, who=who)
    store.admin_log(who, "retention_dry_run" if body.dry_run else "retention_run", json.dumps({k: out.get(k) for k in ("checks_due", "deleted")}, default=str))
    return out


class DeleteCheckIn(BaseModel):
    check_id: str = Field(pattern=r"^C-[0-9a-f]{8}$")


@app.post("/admin/checks/delete")
def admin_delete_check(body: DeleteCheckIn, who: str = Depends(admin)):
    return retention.forget_check(body.check_id, who)


@app.get("/admin/alerts")
def admin_alerts(_: str = Depends(admin)):
    return {"alerts": store.all_alerts_for_admin(), "show_days": store.settings()["alert_show_days"]}


class RetractIn(BaseModel):
    reason: str = Field("", max_length=300)


@app.post("/admin/alerts/{alert_id}/retract")
def admin_retract(alert_id: str, body: RetractIn, who: str = Depends(admin)):
    if not store.retract_alert(alert_id, body.reason, who):
        raise HTTPException(404, "No such alert")
    store.admin_log(who, "retract_alert", f"{alert_id}: {body.reason}")
    return {"ok": True}


@app.post("/admin/alerts/{alert_id}/restore")
def admin_restore(alert_id: str, who: str = Depends(admin)):
    if not store.restore_alert(alert_id):
        raise HTTPException(404, "That alert is not retracted")
    store.admin_log(who, "restore_alert", alert_id)
    return {"ok": True}


class NewAnalyst(BaseModel):
    email: str = Field(max_length=200, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    name: str = Field(min_length=1, max_length=80)
    org: str = Field("", max_length=80)
    password: str = Field(min_length=12, max_length=200)


@app.get("/admin/analysts")
def admin_analysts(_: str = Depends(admin)):
    return {"analysts": store.list_analysts()}


@app.post("/admin/analysts")
def admin_add_analyst(body: NewAnalyst, who: str = Depends(admin)):
    """New accounts are analysts. The administrator account comes only from the host's secrets."""
    if store.analyst_role(body.email):
        raise HTTPException(409, "That email already has an account")
    store.add_analyst(body.email, body.password, body.name.strip(), body.org.strip(), role="analyst")
    store.admin_log(who, "add_analyst", body.email.lower())
    return {"ok": True}


class RemoveAnalyst(BaseModel):
    email: str = Field(max_length=200)


@app.post("/admin/analysts/delete")
def admin_remove_analyst(body: RemoveAnalyst, who: str = Depends(admin)):
    target = body.email.lower()
    if target == who.lower():
        raise HTTPException(400, "You cannot remove your own account")
    if store.analyst_role(target) == "admin":
        raise HTTPException(400, "The administrator account is removed from the host's secrets, not here")
    if not store.delete_analyst(target):
        raise HTTPException(404, "No such account")
    store.admin_log(who, "remove_analyst", target)
    return {"ok": True}


@app.get("/admin/archive/{name}")
def admin_archive(name: str, who: str = Depends(admin)):
    if not re.fullmatch(r"checks-\d{4}-\d{2}\.jsonl\.gz", name):
        raise HTTPException(404, "No such archive")
    f = retention.archive_dir() / name
    if not f.is_file():
        raise HTTPException(404, "No such archive")
    store.admin_log(who, "download_archive", name)
    return FileResponse(f, media_type="application/gzip", filename=name)


@app.get("/alerts")
def public_alerts():
    return {"alerts": store.alerts(50, display=True), "public_key": ledger.public_key_b64()}


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

    VERDICT_WORDS = {
        "en": {"scam": "Scam", "suspicious": "Be careful", "looks_genuine": "Looks genuine", "cant_tell": "Needs a closer look"},
        "fr": {"scam": "Arnaque", "suspicious": "Attention", "looks_genuine": "Semble authentique", "cant_tell": "À vérifier de plus près"},
    }

    def _share_page(rid: str, request: Request):
        """The app page with this answer's verdict in the link preview (WhatsApp, Telegram, Facebook read these tags)."""
        import html as _html
        from . import advice
        page = (WEB / "index.html").read_text(encoding="utf-8")
        rec = store.get_receipt(rid) if re.fullmatch(r"C-[0-9a-f]{8}", rid) else None
        if not rec:
            return HTMLResponse(page)
        fr = request.headers.get("accept-language", "").lower().startswith("fr")
        lang = "fr" if fr else "en"
        word = VERDICT_WORDS[lang].get(rec.get("verdict"), "CheckAm")
        kind = advice.label(rec.get("scheme"), lang) if rec.get("scheme") and rec.get("verdict") in ("scam", "suspicious") else ""
        title = f"CheckAm : {word}" if fr else f"CheckAm: {word}"
        desc = ((f"CheckAm a trouvé : {kind}. " if kind else "") + "Ouvrez pour voir la réponse signée.") if fr else ((f"CheckAm found {kind}. " if kind else "") + "Open to see the signed answer.")
        t, d = _html.escape(title, quote=True), _html.escape(desc, quote=True)
        if fr:
            page = page.replace('<html lang="en">', '<html lang="fr">', 1)
        page = re.sub(r"<title>.*?</title>", f"<title>{t}</title>", page, count=1, flags=re.S)
        page = re.sub(r'(<meta property="og:title" content=")[^"]*(")', lambda m: m.group(1) + t + m.group(2), page, count=1)
        page = re.sub(r'(<meta property="og:description" content=")[^"]*(")', lambda m: m.group(1) + d + m.group(2), page, count=1)
        page = re.sub(r'(<meta name="description" content=")[^"]*(")', lambda m: m.group(1) + d + m.group(2), page, count=1)
        page = re.sub(r'(<meta property="og:url" content=")[^"]*(")', lambda m: m.group(1) + _html.escape(f"https://checkam.me/v/{rid}", quote=True) + m.group(2), page, count=1)
        return HTMLResponse(page, headers={"Cache-Control": "no-store"})

    @app.get("/{path:path}")
    def spa(path: str, request: Request):
        # only files inside the built web folder; anything else ("../.env" included) gets the app page
        f = (WEB / path).resolve()
        inside = f == ROOT_WEB or ROOT_WEB in f.parents
        if path and inside and f.is_file():
            return FileResponse(f)
        if "." in path.rsplit("/", 1)[-1]:
            raise HTTPException(404, "Not found")  # a missing file is not the app page
        if path.startswith("v/"):
            return _share_page(path[2:], request)
        return FileResponse(WEB / "index.html")
