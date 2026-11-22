# Running CheckAm

Notes for whoever runs the live site. Everything here is enforced by the code and covered by tests.

## Accounts

- **Citizens** need no account.
- **Analysts** sign in at `/analyst`. They see campaigns, checks and the review desk, and can publish alerts.
- **The administrator** is one account whose email and password come from two secrets on the host:
  `CHECKAM_ADMIN_EMAIL` and `CHECKAM_ADMIN_PASSWORD`. It is created or refreshed at every start. It has an extra
  "Administration" tab. The server checks the role on every administrator call, not only in the screen.
- The administrator creates and removes analyst accounts from the Administration tab (password of at least 12
  characters). The administrator account cannot be created or removed from the screen.

Use a long passphrase from a password manager, a login email nobody else knows, and never reuse them elsewhere. Sign-in is
limited to 5 tries a minute per address, and a session lasts 12 hours.

## What is kept and for how long

| Record | Default | Then |
|---|---|---|
| Saved check (message with numbers as codes, verdict, kind of scam) | 12 months | Counted into anonymous monthly totals, written to a compressed archive, removed from the database and from the campaign graph |
| Compressed archive (`checks-YYYY-MM.jsonl.gz`) | 36 months after the live period | Deleted |
| Cache of finished answers | 30 days | Deleted |
| Review flags | Until an analyst reads them, then 12 months | Deleted |
| Monthly totals | Kept | They keep the public counter correct |
| Published alerts | Public page shows 90 days | Older alerts leave the page and stay in the signed log |

The periods can be changed in the Administration tab (Retention). The cleanup runs by itself every 24 hours and can be
previewed (dry run) or run on demand. The archive is stored beside the database, so on Render it lives on the
persistent disk (`/var/data/archive`) and survives a redeploy.

To read an archive: download it from the Administration tab, then `gzip -dc checks-2026-01.jsonl.gz` gives one JSON
record per line.

## Taking things down

- **An alert**: "Take down" hides it from the public page and keeps its signed record, so the chain of signatures still
  verifies. "Restore" brings it back. The public alerts list is cached for up to a minute.
- **One check**: "Delete one check" removes it from the database, its signed answer, review flags and the campaign graph.
- Every administrator action is written to the log at the bottom of the tab.

## French alert titles

A French title sits beside the signed record, not inside it, so old signed alerts are untouched. When an analyst leaves
the French title empty it is translated at publish time, and every day any alert without one gets a translation.

## Campaign graph

`POST /forget` on the campaign engine (port 8790, local to the service) removes old citizen-check observations, the links
from them and entities nothing refers to any more. The open dataset is never touched.
