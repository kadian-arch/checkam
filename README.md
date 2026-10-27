# CheckAm

**Before you send, CheckAm.**

[![CI](https://github.com/kadian-arch/checkam/actions/workflows/ci.yml/badge.svg)](https://github.com/kadian-arch/checkam/actions/workflows/ci.yml)
[![Live demo](https://img.shields.io/badge/live%20demo-checkam.me-F5A623)](https://checkam.me)
[![Telegram](https://img.shields.io/badge/Telegram-%40checkam__bot-26A5E4?logo=telegram&logoColor=white)](https://t.me/checkam_bot)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.12-3776AB?logo=python&logoColor=white)](api/requirements.txt)
[![Node](https://img.shields.io/badge/node-24-339933?logo=nodedotjs&logoColor=white)](Dockerfile)
[![React](https://img.shields.io/badge/react-PWA-61DAFB?logo=react&logoColor=black)](web)
[![Tests](https://img.shields.io/badge/tests-127%20passing-brightgreen)](api/tests)
[![Red team](https://img.shields.io/badge/red%20team-41%2F41-brightgreen)](evals/redteam.json)
[![Dataset DOI](https://img.shields.io/badge/data-10.5281%2Fzenodo.23287617-1682D4)](https://doi.org/10.5281/zenodo.23287617)
[![Zetaris](https://img.shields.io/badge/data%20layer-Zetaris-6E3FF3)](docs/ZETARIS.md)
[![Meterless](https://img.shields.io/badge/Meterless-World%20Model%20%C2%B7%20H--MEM%20%C2%B7%20Scout-111111)](docs/METERLESS.md)
[![NVIDIA Nemotron](https://img.shields.io/badge/NVIDIA-Nemotron%203.5-76B900?logo=nvidia&logoColor=white)](#ai-and-model-usage)

CheckAm is a multi-agent system for mobile money scams in Cameroon. A citizen pastes a suspicious SMS, WhatsApp message or screenshot and gets a verdict with the evidence behind every claim, in English or French. The agents also read messages written in Pidgin, the way many scams arrive. Every check is stored without the person's number and feeds an analyst desk, where the agents link reports, public alerts and citizen checks into campaigns, write a dossier and draft a public alert that a signed-in analyst approves and publishes.

**Open Agent Hackathon 2026 · Track 02: The Agent That Can Explain Why · Team Ground Truth**

| Try it | |
|---|---|
| Web app (any phone, installs like an app) | **https://checkam.me** |
| Telegram: forward any message to | **https://t.me/checkam_bot** |
| Analyst desk | https://checkam.me/analyst (judge sign-in on the submission form) |
| Contact | groundtruth.cm@gmail.com |

| | |
|---|---|
| Who it is for | People who receive scam messages (the citizen check), and fraud analysts, CERT staff and fact-checkers (the analyst desk) |
| Problem | Mobile money scams reach every part of Cameroon, and victims face them alone. In our field survey (68 people, most in the South-West, 8 regions in all), 32 of the 60 who described a scam had lost money or nearly did, 38 told their family, only 7 told their operator, and 43 said they would use a free checker (15 more said maybe). The same scam hits thousands of people separately, and nobody sees the campaign |
| What goes in | A message or a screenshot (citizen); a campaign to investigate (analyst) |
| What comes out | A verdict card with evidence, the real operator message it imitates, safe next steps; a campaign dossier and a published alert |
| Why agents | The answer needs several sources that disagree (scam reports, public alerts, genuine operator messages, earlier checks), a link across time (campaigns), and someone arguing the other side before a citizen is told "this is a scam" |

## What makes it different

- **It explains why, with the record behind every claim.** Each reason on the answer opens to its evidence: the scam report, the public alert, the real operator message it copies, the site registry, the analyst's quote. Plain words for citizens; the full agent trail for experts.
- **The Critic argues the other side.** It re-counts every number claim in Zetaris itself, looks for proof the message is genuine, and can overrule the other agents. A real MTN message with a link is not flagged just because it has a link.
- **It vets links like an analyst.** Who the message claims to be (Canada's government, MINESUP, MTN) against where the link really goes, and how old the site is in the public domain registry. A "Canada visa lottery" on istincy.com, or an "investment" site registered 9 days ago, is caught on that alone.
- **Signed answers.** Every answer has a link like `checkam.me/v/C-1a2b3c4d`, signed with CheckAm's Ed25519 key. A doctored "CheckAm says it's real" screenshot cannot produce a valid link, and anyone can paste the message to confirm it is the one that was checked. The message itself is never shown.
- **Signed, hash-chained public alerts.** Analysts publish alerts only with a Scout-signed contract and an approval; each alert is signed and chained to the one before, so nobody can quietly edit or remove one.
- **Scam radar.** The home page shows which scams are going round this week, counted from people's own anonymous checks.
- **It asks before it guesses.** When a message is too thin to judge, the answer says "need more details" and the agents ask the one or two questions that would settle it (who sent it, what it asks you to do, whether the money is really in your balance). The person answers in their own words, on the site or the bot, and the agents check again with the answer.
- **A check you can do yourself, for every kind of scam.** Money received, account blocked, an agent who will call, a prize, a relative in trouble, a new number, a withdrawal to approve, a fake security alert, a fine from the police or customs, threats, a SIM change, romance, a parcel held, a loan fee, an official communiqué, a job or scholarship: each claim comes with the one official check that settles it, such as dialing *126# yourself or calling the old number you know.
- **It learns from analysts (Meterless H-MEM).** Under any answer, a person can say it looks wrong. That waits for an analyst; what the analyst confirms is remembered, and similar messages later recall it as evidence. A scammer cannot teach it that their own message is fine.
- **It answers like a person on Telegram.** It tells a question from a message to check, edits one message from "Checking…" to the answer with live progress, asks its follow-up questions when they would settle it, and in groups only speaks when called.
- **Advice that fits the scam.** A visa scam gets "check canada.ca yourself, never pay a processing fee"; a "sent by mistake" message gets "dial *126# yourself to see your real balance". Official numbers come from a fixed, validated list, never from the model.
- **Instant for repeats.** The same scam reaches thousands of phones; a message checked in the last hours is answered in about a second and says so.
- **Built for every phone.** Works from 320 px screens up, light or dark following the phone, installs as an app, English or French following the phone. Four ways in: a one-tap Paste button, a screenshot (read by Nemotron VL, with Tesseract OCR on the server when the model is busy), Share → CheckAm from any app (Android directly; iPhone through a one-minute Apple Shortcut the site walks you through), or forwarding to the Telegram bot.
- **Its French is checked word by word.** Anything the model writes is checked against full French and English dictionaries before a person sees it; text in the wrong language, with a lost accent ("telephone") or a garbled one ("reù") is replaced by our own sentence, written in both languages.

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
| **Intake** | Reads text or a screenshot (Nemotron VL, Tesseract OCR as fallback), strips hidden characters, turns phone numbers into the dataset's HMAC codes, finds links, asks and brands. Scout screens the message for instructions aimed at AI | Scout can block: a verdict-tampering attempt becomes evidence of a scam |
| **Planner** | Forms hypotheses and chooses tools (Nemotron Lightning), never fewer than the facts call for | Re-plans when the Critic objects |
| **Investigator** | Runs the tools in parallel: number and link history, site vetting (claimed institution against the link, site age from the domain registry), similar scam wording (Nemotron embeddings), the genuine twin, the sender, a fraud analyst's reading (Nemotron Super, given the closest real labelled scams and genuine messages to compare with), campaign membership (World Model), what analysts already confirmed (H-MEM), scale of the scam type. All data through Zetaris | One failing tool never stops the run |
| **Critic** | Re-counts every number claim in Zetaris itself, rejects claims without an evidence row, overrules look-alike findings when the message only routes to official channels or comes from a registered sender and asks for nothing that costs money, argues the message is genuine whenever the evidence changes, asks for missing evidence | **Yes:** rejects findings, sends work back to the Planner (max 3 rounds), gates the verdict |
| **Reporter** | Writes the answer from accepted findings only, in plain English or French, about this message; picks next steps for the kind of scam from a fixed list of official channels, never from the model; Nemotron safety checks the reply; signs the answer | Falls back to templates if the safety check fails |

Every step of every run is a line in `logs/trace-<run_id>.jsonl` and in the app under "See how we checked": agent, action, input and output summaries, target agent, confidence, retry count, status, sponsor and latency.

## Sponsor technology

| Sponsor | Role in CheckAm (load-bearing) |
|---|---|
| **Zetaris** | The source of record. The Stop Arnaque 237 tables live in a Zetaris database (`STOP_ARNAQUE`, five tables registered from the customer-data volume) and every agent query goes through Zetaris over JDBC, with REST as a fallback. The Critic re-queries Zetaris to verify the Investigator. Without Zetaris the live system has no evidence |
| **Meterless: World Model** | The campaign graph (`engines/world-model`). Reports, alerts and citizen checks are observations with content-derived ids; numbers and links are entities; clustering follows spec 4.3 (signature entities, then wording Jaccard ≥ 0.5 or Nemotron embedding cosine ≥ 0.85, with a 0.82 review band). Idempotent ingest, bitemporal edges, audit log, debounced writes. **Passes the official conformance suite 8/8** |
| **Meterless: H-MEM** | Memory of what analysts confirm (`engines/h-mem`, the sponsor's reference implementation unchanged, our service around it). A citizen's "this looks wrong" waits in a review queue; an analyst's confirmation, correction or published alert becomes a memory with provenance; the Investigator recalls the closest ones on every check; a daily sleep cycle settles what keeps proving right and lets one-offs fade; every change is in the trust ledger. **Passes the official conformance suite 13/13** |
| **Meterless: Scout Intent** | Intent, guard and contracts (`engines/scout-intent`). Screens every pasted message (injection, role confusion, verdict tampering, hidden bidi characters); a publish needs a Scout-signed contract, an operator-review approval and a verified signature. **Official eval harness: 1.00 on intent top-1, top-3, injection precision, injection recall and tool precision**; stage-1 scan 0.2 ms |
| **NVIDIA Nemotron** | Nemotron 3.5 Super VL (screenshots, fraud analyst reading, Critic), Nemotron 3.5 Lightning (extraction, planning, writing), Nemotron 3.5 Embed (scam wording similarity and campaign clustering), Nemotron 3.5 Content Safety (every reply) |
| **Meterless Nightshift** | Supported as the model provider: the model client speaks Nightshift's hotspot contract (Bearer proxy token, `meterless-app` and `meterless-scope` headers, `meterless/*` routing modes). Set `MODEL_BASE_URL=http://127.0.0.1:8088/v1`, `MODEL_API_KEY` to the hotspot's proxy token, `NEMOTRON_MODEL=meterless/deep` and `NEMOTRON_FAST_MODEL=meterless/fast`. Checked against a stand-in of the contract, not a real hotspot: the Windows edition needs a dedicated GPU and our only machine has integrated Intel graphics, so the demo and the hosted copy call Nemotron on NVIDIA's API |
| **Cursor** | Used to set up the project at kickoff. The build itself was done with Claude Code after the organisers made Cursor optional |

Details: [docs/ZETARIS.md](docs/ZETARIS.md) and [docs/METERLESS.md](docs/METERLESS.md).

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
| `GET /alerts`, `GET /alerts/verify` | published alerts and the chain check |
| `GET /receipts/{id}`, `POST /receipts/{id}/match` | is this CheckAm answer real, and is it about this message |
| `POST /telegram/{secret}` | the Telegram bot (webhook) |
| `GET /traces/{run_id}` | full trace of a run |

Examples with real saved outputs: `examples/inputs/` and `examples/outputs/`.

## Tests
```bash
python -m pytest -q api/tests                                              # agents, offline
cd engines/world-model && WORLD_MODEL_IMPL=$PWD/src/index.ts npm run conformance
cd engines/scout-intent && SCOUT_IMPL=$PWD/src/index.ts npm run evals
```
CI runs all three on every push and pull request.

## Evaluation

All 267 labelled messages of the Stop Arnaque 237 data (87 scams, 180 genuine), checked by the full system. For each message the agents work blind:
- its own record and its text are hidden from every tool and from the Critic's re-counts;
- every near-copy of it (75% or more of the same wording: a report and the alert that quotes it, a reposted screenshot) is hidden too;
- CheckAm's own stored checks and its H-MEM memory are not consulted, and nothing is stored.

The sender shown on the phone is given, as a person would type it. Precision: of the messages CheckAm flags, how many are scams. Recall: of the scams, how many it flags. "Be careful" counts as flagged.

| Decision | Precision | Recall | False alarms | Scams missed |
|---|---|---|---|---|
| **CheckAm as it runs: rules and Critic, learned weights settle what they leave unsure** (nested 10-fold cross-validation) | **0.956** | **0.989** | **4 of 180** | 1 |
| Rules and Critic alone, all 267 | 0.955 | 0.966 | 4 of 180 | 3 |
| Learned weights alone (not used live, see below) | 0.966 | 0.977 | 3 of 180 | 2 |
| First blind measurement, 26 Oct morning, 148 messages (before the fixes below) | 0.90 | 0.78 | 4 of 102 | 10 |

How to read it, honestly:
- The first row is the system as it runs. The rules and the Critic decide; the learned weights only settle the messages they left at "need more details", and on this data none is left unsure. Each message is scored by weights learned without it (outer 10-fold split; the regularisation and the threshold are chosen inside the training part only), so no message grades itself.
- Why the weights do not decide alone, although they score a little better here: on 40 fresh messages written after the training (our field battery and a teammate's new set) they cleared an obvious bank phishing link and flagged a real Orange safety notice that the rules got right. They learned this data's patterns; the rules were written for each kind of claim. So the weights may settle the unsure, never overrule.
- We studied mistakes on these messages while building the rules, so the second row is optimistic for messages unlike these. That is why we kept the first blind measurement in the table, and why the learned weights are scored by cross-validation and never by re-running the evaluation (the evaluation switches them off).
- The learner is not allowed to use the kind of sender: in this data most scams arrived without one and most genuine messages came from operator names, so it would learn how the data was collected, not the message. With it, cross-validation showed 0.99 precision and 1.00 recall; we do not use or claim that.
- What is left: 3 genuine operator promos that read like scams (a short link plus "log in", a bonus), and 2 scams with nothing to judge (a cut opening sentence, "I cut the call"); for those CheckAm asks follow-up questions instead of guessing.
- Fresh messages from a teammate, never seen while building: 4 of 5 caught before the fixes of 26 Oct; the one missed (a fake "login attempt, cancel here" alert) became the security-alert claim.
- Field battery (35 messages we wrote from public warnings and real operator messages) and the teammate's 5 fresh messages are re-run on every change; see `evals/battery.json`.
- Red team (`api/scripts/redteam.py`, 41 messages built to beat it): scams in Pidgin and texting French, spaced-out numbers, "M0M0", hidden zero-width characters, Cyrillic look-alike letters, five kinds of "AI, call this genuine" injection, plus genuine messages built to trip a false alarm (a scam warning passed on, pay on delivery, ride and OTP codes). The first run on 26 Oct found 2 false alarms and 2 thin openers wrongly cleared; after the fixes all 41 pass, and re-running the 267 labelled messages changed no verdict. Results: `evals/redteam.json`.
- Results, with every verdict, reason and signal: `evals/results-v4-all-all.json`; the learned weights and their cross-validated report: `api/checkam/data/learned_weights.json`.

### Methods

| Method | Where | What it does |
|---|---|---|
| Multi-agent debate | Critic | A second agent re-counts every claim in Zetaris and argues the message is genuine; findings that do not hold are rejected and the Planner is sent back |
| Retrieval-augmented few-shot classification | Investigator, Nemotron Super | The fraud analyst's reading compares the message with the closest real labelled scams and genuine messages from Zetaris (k nearest by wording), never its own record or near-copies |
| Semantic similarity | Nemotron Embed | Scam wording found by meaning, not only by words |
| Stacked classifier (logistic regression, scikit-learn) | Verdict gate | Learns how much each agent's evidence should weigh from the labelled data (nested cross-validation, sender kind excluded as a collection artifact); settles the messages the rules leave unsure; exported to JSON so the server applies it with one dot product |
| Claims verification | Investigator | 17 kinds of claim across the scam taxonomy (money received, account blocked, prize, relative in trouble, security alert...), each with the official check that settles it |
| Active questioning | Reporter | When the evidence is thin, the agents ask the questions that would settle it and check again with the answer |
| Learning from analysts | Meterless H-MEM | Confirmed corrections are remembered with provenance and recalled on similar messages; a daily sleep cycle consolidates them |
| Leakage-controlled evaluation | `evaluate.py` | Own record, near-copies (difflib ratio 0.75), stored checks and memory hidden for every message |
| Dictionary language check | Reporter | Model text checked word by word against French and English dictionaries; wrong language or a garbled accent falls back to our own sentence |
| OCR | Intake | Tesseract (English and French) reads a screenshot when the vision model cannot |

## When something fails
| Failure | What CheckAm does |
|---|---|
| Zetaris JDBC down | REST, then the local parquet sample; the trace shows which backend answered |
| Nemotron down or slow | Rule-based extraction, plan and templates; the verdict still rests on data |
| World Model, Scout or H-MEM down | Skipped after a 1.5 s connect timeout for 30 s; the check still runs |
| Screenshot model busy or down | Tesseract OCR reads the screenshot on the server; if nothing can read it, the person is told so and asked to paste the text |
| One NVIDIA key refused (rate limit) | That key sits out its cooldown and the call moves to the next key at once |
| Model writes something unsafe | Content-safety check replaces it with a template |
| Message tries to steer the AI | Scout flags it; the Reporter shows it as evidence of a scam |

## Security

CheckAm is a safety tool, so it is built to be attacked.
- **Abuse limits** per client (the address our own proxy recorded, so a forged forwarding header does not reset them), stricter limits on sign-in, request bodies capped at 8 MB, screenshots accepted only when their first bytes are a real image.
- **No way out of the web folder**: the file route resolves every path and refuses anything outside the built site.
- **Headers**: strict Content-Security-Policy, HSTS, no framing, no sniffing, no referrer.
- **Analysts** sign in with scrypt-hashed passwords and short-lived HMAC tokens; publishing needs a Scout-signed contract and a signature check.
- **Messages are untrusted data** for every model call, and Scout flags instructions aimed at the AI.
- **Secrets** live only in the environment; `.env.example` lists every setting with placeholders. Dependencies are audited with `pip-audit` and `npm audit` (no known vulnerabilities at submission).
- **Official channels** come from a validated file: a number listed for two operators, a website that is not the operator's, or an entry without a source fails CI and is never loaded.

## Data, privacy and licence
- Data: **Stop Arnaque 237 v1.0** (CC BY 4.0, DOI 10.5281/zenodo.23287617), built by the team before the hackathon and declared as a pre-existing component. Phone numbers in it are HMAC codes that cannot be reversed.
- A citizen's real number is turned into the same code on the server, so it can be matched without being stored. Codes typed into a message ("my PIN is 4821") are removed before anything is saved. Checks are stored masked; trace lines never hold more than 200 characters of a message. Signed answers hold a fingerprint of the message, never the message.
- Code: Apache-2.0. The Meterless test harnesses in `engines/*/conformance` and `engines/scout-intent/evals` and the H-MEM reference in `engines/h-mem/reference` are the sponsor's, Apache-2.0 (see `engines/NOTICE.md`).

## AI and model usage
- **Models (all NVIDIA, hosted):** Nemotron 3.5 Super VL (screenshots, the analyst's reading), Nemotron 3.5 Lightning (facts, plan, Critic, the written answer), Nemotron 3.5 Embed (scam wording by meaning), Nemotron 3.5 Content Safety (every answer before it is shown). Temperature is kept low so the same message gets the same answer. Without a key every agent still runs, on rules and SQL only.
- **Learned weights:** a logistic regression (scikit-learn) on the agents' own findings, trained and scored with nested cross-validation on the labelled messages; see Evaluation.
- **Partner technology:** Zetaris (source of record, every query), Meterless World Model, Scout Intent and H-MEM (see Sponsor technology and `docs/METERLESS.md`).
- **Libraries:** FastAPI, Uvicorn, httpx, DuckDB, JayDeBeApi/JPype (Zetaris JDBC), cryptography (Ed25519 signatures), pyspellchecker, pytesseract with Tesseract OCR, Pillow, React and Vite; versions in `api/requirements.txt` and `web/package.json`.
- **Data:** Stop Arnaque 237 (real reports, public alerts and labelled messages, pseudonymised). The demo messages, the field battery and `examples/` are written by the team to look like real messages and are synthetic; any number in them is made up.
- **Adapted code:** only the Meterless files listed in `engines/NOTICE.md`.
- **Coding assistants:** the code was written with AI coding assistants (Cursor at kickoff, then Claude Code). The team reviewed, tested and can explain every part.
- **Limits:** see Limitations; answers are advice to check through official channels, not a guarantee.

### Third-party licences
FastAPI, Starlette, Uvicorn, httpx, pytest: BSD-3 or MIT. DuckDB, Pillow (HPND), React, Vite: MIT or similar permissive. JPype, cryptography, pytesseract, Tesseract: Apache-2.0 (cryptography also BSD). JayDeBeApi: LGPL-3.0 (used unchanged as a library). pyspellchecker: MIT. scikit-learn and NumPy (training only): BSD-3. Meterless files: Apache-2.0. Zetaris JDBC driver: Zetaris licence, not redistributed (loaded from the local platform install). Stop Arnaque 237 data: CC BY 4.0.

## Limitations
- A campaign link shows a shared signal (number, link, wording), not proof that one person is behind it. Dossiers say so.
- The dataset is small (60 reports, 160 alerts, 267 messages) and skews to the South West and Littoral. New checks grow it.
- With hosted Nemotron a new message takes about 10 to 40 seconds, depending on how busy the hosted models are (about 12 s for one check on its own; medians of 15 to 39 s in our evaluation runs with several checks at once). The verdict shows the moment the agents decide it, then the written explanation. Repeats answer in about a second.
- A receipt or bank notice with no sender shown can be impossible to judge from the text; CheckAm then asks who sent it instead of guessing.

## Team
- **Kum Donalsien Akwo** (KAD): agents, Zetaris and Meterless integration, data, security, deployment.
- **Chelsey**: field research and user testing, French review, official channel research, the operator view of the analyst desk (from her FraudLens mock-up), demo video.

## Contributing and security
Read [CONTRIBUTING.md](CONTRIBUTING.md) before a pull request; it explains the one rule that matters most here: a wrong official number sends people to a scammer. A verdict that looks wrong goes in a "Wrong verdict" issue. A vulnerability goes to us privately, never in an issue: see [SECURITY.md](SECURITY.md). Everyone here follows the [Code of Conduct](CODE_OF_CONDUCT.md).

## Pre-existing components
The Stop Arnaque 237 dataset and its collection pipeline (separate repository: github.com/kadian-arch/stop-arnaque-237), built by Kum Donalsien Akwo before the hackathon. The Meterless harnesses and the H-MEM reference listed in `engines/NOTICE.md` are the sponsor's. Everything else was written from 22 October.
