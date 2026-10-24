# CheckAm

**Before you send, CheckAm.**

CheckAm is a multi-agent system for mobile money scams in Cameroon. A citizen pastes a suspicious SMS, WhatsApp message or screenshot and gets a verdict with the evidence behind every claim, in English, French or Pidgin. Every check is stored without the person's number and feeds an analyst desk, where the agents link reports, public alerts and citizen checks into campaigns, write a dossier and draft a public alert that a signed-in analyst approves and publishes.

**Open Agent Hackathon 2026 · Track 02: The Agent That Can Explain Why · Team Ground Truth**

| | |
|---|---|
| Who it is for | People who receive scam messages (the citizen check), and fraud analysts, CERT staff and fact-checkers (the analyst desk) |
| Problem | In our own survey of 68 people in Cameroon, 35 had lost money or nearly did, 41 told only their family and 8 reported to an operator. Each victim faces the scam alone, and nobody sees the campaign |
| What goes in | A message or a screenshot (citizen); a campaign to investigate (analyst) |
| What comes out | A verdict card with evidence, the real operator message it imitates, safe next steps; a campaign dossier and a published alert |
| Why agents | The answer needs several sources that disagree (scam reports, public alerts, genuine operator messages, earlier checks), a link across time (campaigns), and someone arguing the other side before a citizen is told "this is a scam" |

## How it works

```
 phone app ──► Intake ──► Planner ──► Investigator ──► Critic ──► Reporter ──► verdict card
                 │           ▲             │  ▲            │                      │
                 │           └─ objections ┘  └ re-query ──┘                      ▼
                 ▼                                                         case store (no numbers)
   Scout Intent (Meterless): intent, guard, signed contracts                       │
   Zetaris: STOP_ARNAQUE (JDBC)   World Model (Meterless): campaign graph ◄────────┘
   NVIDIA Nemotron: extraction, planning, critique, writing, embeddings, safety
```

### The agents

| Agent | Job | Can block, retry or send back? |
|---|---|---|
| **Intake** | Reads text or a screenshot (Nemotron VL), strips hidden characters, turns phone numbers into the dataset's HMAC codes, finds links, asks and brands. Scout screens the message for instructions aimed at AI | Scout can block: a verdict-tampering attempt becomes evidence of a scam |
| **Planner** | Forms hypotheses and chooses tools (Nemotron Lightning), never fewer than the facts call for | Re-plans when the Critic objects |
| **Investigator** | Runs the tools: number and link history, similar scam wording (Nemotron embeddings), the genuine twin, campaign membership (World Model), scale of the scam type. All data through Zetaris | One failing tool never stops the run |
| **Critic** | Re-counts every number claim in Zetaris itself, rejects claims without an evidence row, argues the message is genuine (Nemotron Super), downgrades weak findings, asks for missing evidence | **Yes:** rejects findings, sends work back to the Planner (max 3 rounds), gates the verdict |
| **Reporter** | Writes the card from accepted findings only, in the user's language; safe next steps come from a fixed list of official channels, never from the model; Nemotron safety checks the reply | Falls back to templates if the safety check fails |

Every step of every run is a line in `logs/trace-<run_id>.jsonl` and in the app under "See how we checked": agent, action, input and output summaries, target agent, confidence, retry count, status, sponsor and latency.

## Sponsor technology

| Sponsor | Role in CheckAm (load-bearing) |
|---|---|
| **Zetaris** | The source of record. The Stop Arnaque 237 tables live in a Zetaris database (`STOP_ARNAQUE`, five tables registered from the customer-data volume) and every agent query goes through Zetaris over JDBC, with REST as a fallback. The Critic re-queries Zetaris to verify the Investigator. Without Zetaris the live system has no evidence |
| **Meterless: World Model** | The campaign graph (`engines/world-model`). Reports, alerts and citizen checks are observations with content-derived ids; numbers and links are entities; clustering follows spec 4.3 (signature entities, then wording Jaccard ≥ 0.5 or Nemotron embedding cosine ≥ 0.85, with a 0.82 review band). Idempotent ingest, bitemporal edges, audit log, debounced writes. **Passes the official conformance suite 8/8** |
| **Meterless: Scout Intent** | Intent, guard and contracts (`engines/scout-intent`). Screens every pasted message (injection, role confusion, verdict tampering, hidden bidi characters); a publish needs a Scout-signed contract, an operator-review approval and a verified signature. **Official eval harness: 1.00 on intent top-1, top-3, injection precision, injection recall and tool precision**; stage-1 scan 0.2 ms |
| **NVIDIA Nemotron** | Nemotron 3.5 Super VL (screenshots, Critic), Nemotron 3.5 Lightning (extraction, planning, writing), Nemotron 3.5 Embed (scam wording similarity and campaign clustering), Nemotron 3.5 Content Safety (every reply) |
| **Cursor / AI tools** | See `SPONSORS.md` for how the build was done |

## Run it

### 1. Sample mode (no keys, two minutes)
With an empty `.env` CheckAm runs the same agents and the same SQL on the public parquet files (DuckDB), with rule-based fallbacks instead of Nemotron.

```bash
docker build -t checkam .
docker run -p 8000:8000 checkam
```
Open http://localhost:8000 (phone app) or call the API:
```bash
curl -s localhost:8000/run -H "Content-Type: application/json" -d '{"mode":"check","text":"Please I sent 25000 to your MTN number by mistake, send it back to [PHONE:654-jwmukg]"}'
curl -s localhost:8000/run -H "Content-Type: application/json" -d '{"mode":"investigate"}'
```

### 2. Full mode (Zetaris + Nemotron)
1. Install the Zetaris local platform and register the dataset (see `docs/ZETARIS.md`).
2. `cp .env.example .env` and fill `ZETARIS_*` and `MODEL_API_KEY` (build.nvidia.com).
3. Start the engines and the API:
```bash
cd engines/world-model && npm ci && npm start          # :8790
cd engines/scout-intent && npm ci && npm start         # :8791
pip install -r api/requirements.txt && python run.py serve   # :8000
cd web && npm ci && npm run build                      # served by the API
```

### Programmatic entry points
| | |
|---|---|
| `python run.py check "<message>"` | one citizen check, prints the card |
| `python run.py investigate [campaign_id]` | one analyst dossier |
| `POST /run` | `{"mode": "check", "text": ...}` or `{"mode": "investigate", "campaign_id": ...}` |
| `POST /check`, `POST /check/image` | citizen check (text or screenshot) |
| `GET /alerts` | published alerts |
| `GET /traces/{run_id}` | full trace of a run |

Examples with real saved outputs: `examples/inputs/` and `examples/outputs/`.

## Tests
```bash
python -m pytest -q api/tests                                              # agents, offline
cd engines/world-model && WORLD_MODEL_IMPL=$PWD/src/index.ts npm run conformance
cd engines/scout-intent && SCOUT_IMPL=$PWD/src/index.ts npm run evals
```
CI runs all three on every push and pull request.

## When something fails
| Failure | What CheckAm does |
|---|---|
| Zetaris JDBC down | REST, then the local parquet sample; the trace shows which backend answered |
| Nemotron down or slow | Rule-based extraction, plan and templates; the verdict still rests on data |
| World Model or Scout down | Skipped after a 1.5 s connect timeout for 30 s; the check still runs |
| Model writes something unsafe | Content-safety check replaces it with a template |
| Message tries to steer the AI | Scout flags it; the Reporter shows it as evidence of a scam |

## Data, privacy and licence
- Data: **Stop Arnaque 237 v1.0** (CC BY 4.0, DOI 10.5281/zenodo.23287617), built by the team before the hackathon and declared as a pre-existing component. Phone numbers in it are HMAC codes that cannot be reversed.
- A citizen's real number is turned into the same code on the server, so it can be matched without being stored. Checks are stored masked; trace lines never hold more than 200 characters of a message.
- Code: Apache-2.0. The Meterless test harnesses in `engines/*/conformance` and `engines/scout-intent/evals` are the sponsor's, Apache-2.0 (see `engines/NOTICE.md`).

## Limitations
- A campaign link shows a shared signal (number, link, wording), not proof that one person is behind it. Dossiers say so.
- The dataset is small (60 reports, 160 alerts, 267 messages) and skews to the South West and Littoral. New checks grow it.
- With hosted Nemotron a full check takes 20 to 40 seconds; the app shows each step as it happens.

## Pre-existing components
The Stop Arnaque 237 dataset and its collection pipeline (separate repository). Evaluation labels and planning notes were prepared before the window. All code in this repository was written from 22 October 2026.
