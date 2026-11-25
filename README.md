# CheckAm

**Before you send, CheckAm.**

[![CI](https://github.com/kadian-arch/checkam/actions/workflows/ci.yml/badge.svg)](https://github.com/kadian-arch/checkam/actions/workflows/ci.yml)
[![Live](https://img.shields.io/badge/live-checkam.me-F5A623)](https://checkam.me)
[![Telegram](https://img.shields.io/badge/Telegram-%40checkam__bot-26A5E4?logo=telegram&logoColor=white)](https://t.me/checkam_bot)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.12-3776AB?logo=python&logoColor=white)](api/requirements.txt)
[![Dataset DOI](https://img.shields.io/badge/data-10.5281%2Fzenodo.23287617-1682D4)](https://doi.org/10.5281/zenodo.23287617)

CheckAm tells people in Cameroon whether a message, a link or a story is a scam, in English, French or Pidgin, before they send money or a code. A person pastes a message, uploads a screenshot, speaks it, or forwards it to the Telegram bot. The answer comes with the evidence behind every claim, the real message it imitates when there is one, and the next steps that fit that situation. Nothing needs a sign-up and the phone number is never stored.

Behind the citizen check is an analyst desk. Checks are stored without the person's number, linked into campaigns, and turned into public alerts that a signed-in analyst reviews and publishes.

| | |
|---|---|
| Web app (any phone, installs like an app) | https://checkam.me |
| Telegram bot | https://t.me/checkam_bot |
| Analyst desk | https://checkam.me/analyst (invitation only) |
| Project document (requirements, design, tests) | [docs/CheckAm_Project_Document.pdf](docs/CheckAm_Project_Document.pdf) |
| Operations and security notes | [docs/OPERATIONS.md](docs/OPERATIONS.md), [SECURITY.md](SECURITY.md) |
| Contact | groundtruth.cm@gmail.com |

## Why it exists
Mobile money scams reach every part of Cameroon and victims face them alone. In our field survey (68 people, most in the South-West, 8 regions in all), 32 of the 60 who described a scam had lost money or nearly did, 38 told their family, only 7 told their operator, and 43 said they would use a free checker (15 more said maybe). The same scam reaches thousands of people separately and nobody sees the campaign.

## What it does
- **Explains why, with the record behind every claim.** Each reason opens to its evidence: the scam report, the public alert, the genuine operator message it copies, the analyst's note.
- **Knows when it does not know.** A message too thin to judge gets "need more details" and one or two questions. A harmless message nobody vouches for gets "nothing to check yet", never a confident "genuine".
- **Cannot be talked into a verdict by a model.** A model may add concern; "scam" needs hard evidence (a reported number or link, a near-verbatim copy of a known scam, a link that does not belong to who the message claims to be, a request that only a scammer makes).
- **Vets links like an analyst.** Who the message claims to be against where the link really goes; how old the site is, read from the public domain registry (RDAP); and what the address itself gives away: a look-alike of MTN, Orange or a government name, a bare number address, foreign letters made to look like ours, a free page builder, an ending scam sites buy because it costs nothing.
- **Speaks the way people write and talk.** English, French, Pidgin, texting spellings, mixed languages, dictated speech. Spoken numbers ("six five five one one two two three three", "cinq mille francs") become digits before the checks run. Nobody is judged on grammar.
- **Gives advice that fits the situation.** From what the message does (asks for money back, a code, an ID, a fee, a call) first, and from the kind of scam only when the text supports it. Official numbers come from a validated file, never from the model. Eighteen named scam types; a message that fits none still gets safe general steps, a note that the kind is not known yet, and a place in the analyst review queue.
- **Is gentle with people who already paid.** "I sent money", "I gave a code", "I sent my ID": each opens the steps for that situation (on the site and as buttons on Telegram).
- **Signed answers.** Every answer has a link like `checkam.me/v/C-1a2b3c4d` signed with Ed25519, so a doctored screenshot cannot pass as a CheckAm answer. The message itself is never shown.
- **Scam radar and public alerts.** The home page shows what is going round this week, counted from anonymous checks. Alerts are signed and hash-chained so none can be quietly edited or removed.
- **Learns from analysts, not from scammers.** "This looks wrong" waits for an analyst. What they confirm is remembered and recalled on similar messages.
- **Built for every phone.** 320 px screens and up, light or dark, installable, English or French, a one-tap paste, screenshots, share-to-CheckAm, voice, Telegram.

## How it works

```
 phone / Telegram ──► Intake ──► Planner ──► Investigator ──► Critic ──► Reporter ──► answer
                        │           ▲             │  ▲            │                       │
                        │           └─ objections ┘  └ re-query ──┘                       ▼
                        ▼                                                       case store (no numbers)
        guard against instructions                 evidence tables (SQL)                   │
        aimed at the AI                            campaign graph ◄────────────────────────┘
                                                   analyst memory
```

| Part | Job |
|---|---|
| **Intake** | Reads text or screenshots (vision model, with Tesseract OCR as fallback), turns spoken numbers into digits, masks phone numbers, finds links, asks and brands. Screens for instructions aimed at the AI |
| **Planner** | Forms hypotheses and chooses the checks; re-plans when the Critic objects |
| **Investigator** | Runs the checks in parallel: number and link history, site age and address, who the message claims to be, similar wording, the genuine twin, the sender, an analyst-style reading by the model, campaign membership, what analysts already confirmed |
| **Critic** | Re-counts every claim against the evidence itself, looks for proof the message is genuine, can overrule the others and send work back (max 3 rounds). Gates the verdict |
| **Reporter** | Writes the answer from accepted findings only, in the person's language; picks steps from fixed official channels; safety-checks the reply; signs it |

Every step of every run is a line in a trace (agent, action, summaries, latency), shown in the app under "See how we checked".

Components in this repository: `api/` (FastAPI, Python 3.12), `web/` (React, Vite, installable PWA), `engines/world-model` (campaign graph), `engines/scout-intent` (guard and signed publishing contracts), `engines/h-mem` (analyst memory), `data/` (sample evidence tables), `deploy/` and `render.yaml` (hosting). The evidence tables are the Stop Arnaque 237 data, queried with SQL (DuckDB by default; a Zetaris JDBC backend is supported through configuration). The language model is optional: with no key every agent runs on rules and SQL.

## Run it

### Sample mode (no keys, two minutes)
```bash
docker build -t checkam .
docker run -p 8000:8000 checkam
```
Open http://localhost:8000, or call the API:
```bash
curl -s localhost:8000/run -H "Content-Type: application/json" \
  -d '{"mode":"check","text":"Please I sent 25000 to your MTN number by mistake, send it back to 654112233"}'
```

### From source
```bash
cp .env.example .env                                  # every setting is listed with a placeholder
pip install -r api/requirements.txt
cd engines/world-model && npm ci && npm start         # :8790
cd engines/scout-intent && npm ci && npm start        # :8791
cd web && npm ci && npm run build                     # served by the API
python run.py serve                                   # :8000
```
Set `MODEL_API_KEY` (an OpenAI-compatible endpoint; we use NVIDIA Nemotron) for the model steps. Without it the rule-based path answers. Set `CHECKAM_REDIS_URL` to share repeat answers and rate limits across instances (any Redis, for example Huawei Cloud DCS).

### Entry points
| | |
|---|---|
| `python run.py check "<message>"` | one check, prints the card |
| `python run.py investigate [campaign_id]` | one analyst dossier |
| `POST /check`, `POST /check/image` | citizen check (text or screenshot) |
| `GET /alerts`, `GET /alerts/verify` | published alerts and the chain check |
| `GET /receipts/{id}` | is this CheckAm answer real |
| `POST /telegram/{secret}` | the Telegram webhook |

## Tests
```bash
python -m pytest -q api/tests          # about 490 tests, offline
cd engines/world-model && npm run conformance
cd engines/scout-intent && npm run evals
```
CI runs all three on every push and pull request.

## Evaluation
The 267 labelled messages of the Stop Arnaque 237 data (87 scams, 180 genuine), each checked blind: its own record and every near-copy of it (75 percent or more of the same wording) are hidden from every tool, and CheckAm's stored checks and memory are not consulted. "Flagged" means scam or suspicious.

| Version and mode | Precision | Recall | Genuine messages wrongly flagged |
|---|---|---|---|
| v6, rules and model | 0.954 | 0.954 (0.973 on messages that can be checked at all) | 4 of 180 (2.2%) |
| v5, rules only, no model | 0.987 | 0.897 | 1 of 180 (0.6%) |
| First blind measurement, 26 Oct 2026, 148 messages | 0.90 | 0.78 | 4 of 102 |

How to read it:
- The evaluation is harsh for template-like genuine messages: it hides near copies of the message's own record, which production would use to clear it.
- We studied mistakes on these messages while building the rules, so the numbers are optimistic for messages unlike these. That is why the first blind measurement stays in the table.
- Four checks end in "cannot tell"; two scams in the set are retellings with nothing to judge.
- Additional sets, each re-run on every change: a red team of 65 messages built to beat the system (Pidgin and texting French, spaced-out numbers, look-alike letters, instructions aimed at the AI, genuine messages built to trip a false alarm), and a Pidgin, spoken and elder set of 26 (26 of 26 correct with the model off). These sets were written by the team, so real messages from outside remain the honest test.
- Results with every verdict and reason: `evals/results-v6-modelon-all.json`.

## When something fails
| Failure | What happens |
|---|---|
| Language model down or slow | Rule-based extraction, plan and templates; the verdict still rests on data |
| Engines (campaign graph, guard, memory) down | Skipped after a short timeout; the check still runs |
| Screenshot model busy | Tesseract OCR on the server; if nothing can read it, the person is asked to paste the text |
| Model writes something unsafe or in the wrong language | Replaced by our own sentence, written in both languages |
| Scam kind not among the eighteen | Safe general steps, a note saying so, automatic place in the analyst queue |
| Message tries to steer the AI | Shown as evidence of a scam |

## Security and privacy
- Abuse limits per client, stricter on sign-in; request bodies capped; screenshots accepted only when the first bytes are a real image; no path outside the built site is ever served.
- Strict Content-Security-Policy, HSTS, no framing, no sniffing, microphone allowed for this site only.
- Analyst sign-in with hashed passwords, short-lived tokens and optional two-factor authentication (authenticator app, recovery codes); publishing needs a signed contract and a verified signature.
- Phone numbers are masked before storage and before every call to a language model. Codes typed into a message ("my PIN is 4821") are removed. Screenshots are never stored. Checks are kept for 24 months, then archived for 72 months on the server's disk, and the public counter survives both. A person's data can be removed on request.
- Messages are untrusted data for every model call. Secrets live only in the environment.
- Official channels come from a validated file: a number listed for two operators, or an entry without a source, fails CI and is never loaded.
Report a vulnerability privately: [SECURITY.md](SECURITY.md).

## Limitations
- A campaign link shows a shared signal (number, link, wording), not proof that one person is behind it.
- The dataset is small (60 reports, 160 alerts, 267 messages) and skews to the South West and Littoral. New checks grow it.
- With a hosted model a new message takes about 10 to 40 seconds; the verdict shows the moment the agents decide it. Repeats answer in about a second.
- A receipt or bank notice with no sender shown can be impossible to judge; CheckAm then asks who sent it.
- Speech recognition runs in the person's browser and quality depends on the phone and language; Pidgin has no dedicated recogniser, so it is heard as the nearest English.
- Answers are advice to confirm through official channels, not a guarantee.

## Data and licences
- Data: **Stop Arnaque 237 v1.0** (CC BY 4.0, DOI 10.5281/zenodo.23287617), built by Kum Donalsien Akwo. Phone numbers in it are HMAC codes that cannot be reversed.
- Code: Apache-2.0. The conformance harnesses in `engines/*/conformance`, `engines/scout-intent/evals` and the H-MEM reference in `engines/h-mem/reference` come from Meterless under Apache-2.0 (see `engines/NOTICE.md`).
- Libraries: FastAPI, Uvicorn, httpx, DuckDB, JPype and JayDeBeApi, cryptography, pyspellchecker, pytesseract and Tesseract, Pillow, scikit-learn, React, Vite; versions in `api/requirements.txt` and `web/package.json`.
- The demo messages, the red-team set and `examples/` were written by the team to look like real messages and are synthetic; any number in them is made up.
- The code was written with AI coding assistants and reviewed and tested by the team.

## Team
- **Kum Donalsien Akwo**: product, agents, data, security, deployment.
- **Chelsey**: field research and user testing, French review, official channel research.

## History
CheckAm began as an entry to the Open Agent Hackathon 2026 (Track 02, Team Ground Truth), where it was submitted on 27 October 2026. It has been developed as a product since. The Stop Arnaque 237 dataset and its collection pipeline (github.com/kadian-arch/stop-arnaque-237) predate it.

## Contributing
Read [CONTRIBUTING.md](CONTRIBUTING.md) first; the rule that matters most is that a wrong official number sends people to a scammer. A verdict that looks wrong goes in a "Wrong verdict" issue. Everyone here follows the [Code of Conduct](CODE_OF_CONDUCT.md).
