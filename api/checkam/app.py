import base64
import json
import threading

from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import agents, config, dossier, seed, store
from .adapters import nvidia, scout, world
from .adapters.data import data

app = FastAPI(title="CheckAm", version="0.1.0", description="Before you send, CheckAm.")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


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
    text: str = ""
    sender: str = ""
    language: str = ""


class RunIn(BaseModel):
    mode: str = "check"
    text: str = ""
    sender: str = ""
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


@app.post("/check/image")
async def check_image(image: UploadFile = File(...), text: str = Form(""), language: str = Form("")):
    raw = await image.read()
    if len(raw) > 6_000_000:
        raise HTTPException(413, "Image too large (6 MB max)")
    return agents.run_check(text, image=(base64.b64encode(raw).decode(), image.content_type or "image/png"), language=language)


@app.post("/run")
def run(body: RunIn):
    """Programmatic entry point for judges: {"mode": "check"|"investigate", ...}."""
    if body.mode == "investigate":
        return dossier.investigate(body.campaign_id or None)
    return agents.run_check(body.text, sender=body.sender, language=body.language)


class Login(BaseModel):
    email: str
    password: str


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
    row = store.publish_alert({**body.model_dump(), "published_by": email, "run_id": approved["contractId"]})
    trace.log("Reporter", "alert_published", output={"alert": row["id"], "contract": approved["contractId"], "approvals": approved["risk"]["approvals"]}, sponsor="meterless")
    return {**row, "contract": {k: approved[k] for k in ("contractId", "parentId", "expiresAt", "signedBy")}, "approvals": approved["risk"]["approvals"]}


@app.get("/alerts")
def public_alerts():
    return {"alerts": store.alerts()}


@app.get("/traces/{run_id}")
def get_trace(run_id: str):
    p = config.LOG_DIR / f"trace-{run_id}.jsonl"
    if not run_id.isalnum() or not p.exists():
        raise HTTPException(404, "No such run")
    return {"run_id": run_id, "lines": [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines()]}


WEB = config.ROOT / "web" / "dist"
if WEB.exists():
    app.mount("/assets", StaticFiles(directory=WEB / "assets"), name="assets")

    @app.get("/{path:path}")
    def spa(path: str):
        f = WEB / path
        return FileResponse(f if path and f.is_file() else WEB / "index.html")
