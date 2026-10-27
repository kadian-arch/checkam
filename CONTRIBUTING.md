# Contributing to CheckAm

Thank you for helping people in Cameroon check a message before they send money. Reports of wrong verdicts are as useful as code.

## Ways to help
- **A verdict looks wrong.** Open a "Wrong verdict" issue. Paste the message with every phone number replaced by `XXX`, the sender shown on your phone and the verdict CheckAm gave.
- **A scam we do not know yet.** Report it through the Stop Arnaque 237 form linked from [the dataset repository](https://github.com/kadian-arch/stop-arnaque-237), so it reaches the data the agents search.
- **Official channels.** A new or changed operator number, short code or website goes in `api/checkam/data/official_channels.json`, with a source link for every entry.
- **Code, tests, French or English wording.** Open an issue first for anything larger than a small fix, so we can agree on the approach.

## The rules that keep people safe
1. **Official channels need a source.** A wrong official number sends people straight to a scammer. Every entry in `official_channels.json` needs an `https://` source from the operator or "SMS received on (date)". CI rejects the whole file if one entry is wrong.
2. **No real phone numbers** in issues, tests, fixtures or examples. Use `XXX` or numbers that are clearly made up.
3. **No secrets.** Keys live only in `.env`, which is never committed. `.env.example` lists every setting with a placeholder.
4. **Every claim needs evidence.** A new finding must point to the record behind it, and the Critic must be able to re-check it.

## Set up
Sample mode needs no keys:
```bash
docker build -t checkam .
docker run -p 8000:8000 checkam
```
Or without Docker:
```bash
cd api
python -m venv .venv
.venv/bin/pip install -r requirements.txt    # Windows: .venv\Scripts\pip
cd .. && api/.venv/bin/python run.py serve  # Windows: api\.venv\Scripts\python
```
Full mode with Zetaris and Nemotron is in the README under "Run it".

## Before you open a pull request
```bash
python -m pytest -q api/tests
python api/scripts/redteam.py               # 41 evasion, injection and genuine cases
cd web && npm ci && npm run build
```
CI runs the agent tests, the three official Meterless suites and the phone app build on every pull request. A pull request that changes a verdict says which messages changed and why.

## Style
- Python: plain functions, short comments only where the reason is not obvious, names that say what a thing is.
- Messages to citizens: short sentences, English and French both updated, no jargon.

## Licence
By contributing you agree that your work is released under the [Apache-2.0 licence](LICENSE).
