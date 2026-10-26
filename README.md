# CheckAm

**Before you send, CheckAm.**

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
- **A check you can do yourself, for every kind of scam.** Money received, account blocked, an agent who will call, a prize, a relative in trouble, a new number, a withdrawal to approve, a fine from the police or customs, threats, a SIM change, romance, a parcel held, a loan fee, an official communiqué, a job or scholarship: each claim comes with the one official check that settles it, such as dialing *126# yourself or calling the old number you know.
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

`python api/scripts/evaluate.py --split test --with-sender` runs the full system (Zetaris, Nemotron, both engines) on the labelled messages of the Stop Arnaque 237 data. For each message the agents must work blind:
- its own record and its text are hidden from every tool and from the Critic's re-counts;
- every near-copy of it (75% or more of the same wording: a report and the alert that quotes it, a reposted screenshot) is hidden too;
- CheckAm's own stored checks are not consulted, and nothing is stored.

The sender shown on the phone is given, as a person would type it. Precision: of the messages CheckAm flags, how many are scams. Recall: of the scams, how many it flags. "Be careful" counts as flagged.

| Set | Messages | Precision | Recall | False alarms | Can't tell |
|---|---|---|---|---|---|
| **Training messages we did not study** (fairest) | 148 (46 scams, 102 genuine) | **0.90** | **0.78** | **4 of 102** | 4 |
| Training messages we studied to find rules | 70 (23 scams, 47 genuine) | 1.00 | 0.96 | 0 of 47 | 1 |
| Test split, also studied during the build | 49 (18 scams, 31 genuine) | 1.00 | 1.00 | 0 of 31 | 0 |

- Read the first row. During the build we studied the mistakes on the test split and on 70 training messages to write general rules, so those two rows are optimistic. The 148 other training messages were only ever run once, in an early rules-only test on day one, and nobody studied them while writing the rules.
- What the 148 taught us, after they were scored: of the 10 scams missed, 5 were victims retelling a call ("I was supposed to input my code"), 3 were job or scholarship announcements cut before the fee, 1 asked a fee without the word "pay" ("the 6,000 FCFA, it's for the application") and 1 was a credit notice cut after "You have just received...". The 4 false alarms were genuine operator and service promos with shortened links or log-in details. CheckAm now judges a retold story on what the person was asked, never calls a job or scholarship announcement harmless, reads "the fee is for the application" as a demand, and spots cash offered for nothing ("recevez 35 000 F CFA") even without a "you won". We did not re-score the 148 after these fixes: a set you tune on stops being a fair test. A fresh set from field users will give the next untouched score.
- A "you received money" notice with no sender shown is never left at "can't tell": the answer tells the person to dial *126# (MTN) or #150# (Orange) themselves, because a credit that is not in the balance never came, and asks who sent it.
- After those fixes we re-ran the two studied sets to make sure nothing broke: no new false alarm on either (test 0 of 31, studied training 0 of 47).
- Results, with every verdict and reason: `evals/results-strict-train-train.json` (both training rows, as measured blind), `evals/results-strict-test-test.json`; the re-runs after the fixes are `evals/results-strict3-*.json`.

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
- Code: Apache-2.0. The Meterless test harnesses in `engines/*/conformance` and `engines/scout-intent/evals` are the sponsor's, Apache-2.0 (see `engines/NOTICE.md`).

## Limitations
- A campaign link shows a shared signal (number, link, wording), not proof that one person is behind it. Dossiers say so.
- The dataset is small (60 reports, 160 alerts, 267 messages) and skews to the South West and Littoral. New checks grow it.
- With hosted Nemotron a new message takes about 10 to 40 seconds, depending on how busy the hosted models are (about 12 s for one check on its own; medians of 15 to 39 s in our evaluation runs with several checks at once). The verdict shows the moment the agents decide it, then the written explanation. Repeats answer in about a second.
- A receipt or bank notice with no sender shown can be impossible to judge from the text; CheckAm then asks who sent it instead of guessing.

## Team
- **Kum Donalsien Akwo** (KAD): agents, Zetaris and Meterless integration, data, security, deployment.
- **Chelsey**: field research and user testing, French review, official channel research, the operator view of the analyst desk (from her FraudLens mock-up), demo video.

## Pre-existing components
The Stop Arnaque 237 dataset and its collection pipeline (separate repository: github.com/kadian-arch/stop-arnaque-237).
