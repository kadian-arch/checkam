"""Analyst side: campaigns from the world model, investigated with evidence from Zetaris."""
import json

from . import config, store
from .adapters import nvidia, world
from .adapters.data import data
from .trace import Trace

DB = config.ZETARIS_DB


def _split(member: str) -> tuple[str, str]:
    _, source, ext = member.split(":", 2)
    return source, ext


def overview() -> dict:
    trace = Trace(echo=False)
    camps = world.campaigns(trace, agent="Planner")
    out = []
    for c in camps:
        kinds = c.get("kinds", {})
        out.append({"id": c["id"], "size": len(c["members"]), "kinds": kinds, "numbers": c["numbers"], "scam_types": c["scamTypes"],
                    "brands": c["brands"], "first_seen": c["firstSeenAt"], "last_seen": c["lastSeenAt"],
                    "citizen_checks": kinds.get("check", 0), "review_pairs": len(c["review"]),
                    "signals": sorted({l["why"].split(" ")[0] + " " + l["why"].split(" ")[1] for l in c["links"]})})
    out.sort(key=lambda c: (-c["citizen_checks"], -c["size"]))
    return {"campaigns": out, "run_id": trace.run_id, "checks": store.check_stats()}


def investigate(campaign_id: str | None) -> dict:
    trace = Trace()
    camps = world.campaigns(trace, agent="Planner")
    if not camps:
        return {"error": "no campaigns yet", "run_id": trace.run_id}
    camp = next((c for c in camps if c["id"] == campaign_id), None) if campaign_id else max(camps, key=lambda c: len(c["members"]))
    if not camp:
        return {"error": f"unknown campaign {campaign_id}", "run_id": trace.run_id}
    trace.log("Planner", "plan", input=camp["id"], output={"members": len(camp["members"]), "tools": ["members", "number_stats", "verify_links", "write_dossier"]}, target="Investigator")

    by_src: dict[str, list[str]] = {}
    for m in camp["members"]:
        s, e = _split(m)
        by_src.setdefault(s, []).append(e)
    ids = by_src.get(world.SOURCE, [])
    q = ",".join("'" + i.replace("'", "") + "'" for i in ids) or "''"
    reps = data().sql(f"SELECT id, message_text, call_description, scam_types, region, amount_lost_fcfa, channel FROM {DB}.reports WHERE id IN ({q})", trace, why="campaign reports")
    alr = data().sql(f"SELECT id, title, summary, source, source_url, date_published, impersonated FROM {DB}.public_alerts WHERE id IN ({q})", trace, why="campaign alerts")
    checks = [c for c in store.recent_checks(500) if c["campaign_id"] == camp["id"]]
    members = ([{"kind": "report", "id": r["id"], "text": (r["message_text"] or r["call_description"] or "")[:300], "region": r["region"],
                 "lost_fcfa": r["amount_lost_fcfa"], "scam_types": r["scam_types"]} for r in reps] +
               [{"kind": "alert", "id": a["id"], "text": a["title"], "outlet": a["source"], "url": a["source_url"], "date": a["date_published"],
                 "impersonated": a["impersonated"]} for a in alr] +
               [{"kind": "check", "id": c["id"], "text": c["masked_text"][:300], "date": c["created"][:10], "verdict": c["verdict"]} for c in checks])
    trace.log("Investigator", "members", output=f"{len(reps)} reports, {len(alr)} alerts, {len(checks)} citizen checks", target="Critic", sponsor="zetaris")

    num_stats = []
    for n in camp["numbers"][:6]:
        r = data().sql(f"SELECT phone_id, times_reported, times_in_alerts, top_scam_types, first_seen FROM {DB}.scam_numbers WHERE phone_id = '{n.replace(chr(39), '')}'", trace, why=f"history of {n}")
        num_stats.append(r[0] if r else {"phone_id": n, "times_reported": 0, "note": "only in citizen checks"})

    # Critic: every membership must rest on a link with a reason
    known = {m for l in camp["links"] for m in (l["a"], l["b"])}
    unsupported = [m for m in camp["members"] if m not in known]
    trace.log("Critic", "verify_links", input=f"{len(camp['links'])} links", output="all members supported" if not unsupported else f"unsupported: {unsupported}",
              status="ok" if not unsupported else "rejected", target="Reporter")
    review = [{"a": l["a"].split(":")[-1], "b": l["b"].split(":")[-1], "why": l["why"]} for l in camp["review"]]

    lost = sum(int(m.get("lost_fcfa") or 0) for m in members if m["kind"] == "report")
    facts = {"members": len(camp["members"]), "reports": len(reps), "alerts": len(alr), "citizen_checks": len(checks),
             "numbers": camp["numbers"], "scam_types": camp["scamTypes"], "brands": camp["brands"],
             "first_seen": camp["firstSeenAt"][:10], "last_seen": camp["lastSeenAt"][:10], "reported_loss_fcfa": lost,
             "links": sorted({l["why"] for l in camp["links"]}), "examples": [m["text"][:160] for m in members[:4]]}
    llm = nvidia.chat_json([
        {"role": "system", "content": "You write a fraud-analyst dossier for Cameroon. Use ONLY the facts given; every sentence must trace to them. Reply with JSON only."},
        {"role": "user", "content": json.dumps(facts, ensure_ascii=False) +
         "\nReturn {\"name\": short campaign name, \"summary\": 2-3 sentences, \"how_it_works\": 1-2 sentences, \"limitations\": 1 sentence, "
         "\"alert_title\": max 10 words, \"alert_en\": max 60 words for the public, \"alert_fr\": same in French}"},
    ], model=config.MODEL_REASON, trace=trace, agent="Reporter", action="write_dossier", max_tokens=900)
    d = llm or {}
    name = d.get("name") or f"Campaign {camp['id'][-6:]}"
    alert_en = d.get("alert_en") or (f"Warning: {len(camp['members'])} linked scam reports. " +
                                     (f"Numbers {', '.join(camp['numbers'][:3])} are involved. " if camp["numbers"] else "") +
                                     "Never send money or a code to a number in a message. Check with your operator first.")
    dossier = {
        "run_id": trace.run_id, "campaign_id": camp["id"], "name": name,
        "summary": d.get("summary") or f"{len(camp['members'])} records linked by {', '.join(facts['links'][:2])}.",
        "how_it_works": d.get("how_it_works", ""), "limitations": d.get("limitations") or "Linked records show a shared signal, not proof of one person behind them.",
        "facts": facts, "members": members, "numbers": num_stats, "links": camp["links"], "review": review,
        "recommended_actions": ([f"Ask operators to review number {n}" for n in camp["numbers"][:3]] +
                                ["Publish the public alert below in English and French"]),
        "alert": {"title": d.get("alert_title") or name, "body_en": alert_en, "body_fr": d.get("alert_fr", ""),
                  "numbers": camp["numbers"][:5]},
    }
    trace.log("Reporter", "dossier", output={"name": name, "members": len(members)}, sponsor="nvidia" if llm else "none")
    dossier["trace"] = trace.lines
    return dossier
