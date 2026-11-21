"""Turn what analysts confirmed on the review desk into labelled rows for the next dataset version.

A person flags an answer ("this was wrong"), an analyst confirms or dismisses it, and a confirmed flag is the
analyst's verdict on a masked message. This script writes those rows to evals/reviewed_corrections.json in the
same shape as the other eval files, so they can be read by eye, added to the test set, and used to retrain.

  api\\.venv\\Scripts\\python.exe api\\scripts\\export_reviewed.py
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "api"))
from checkam import store  # noqa: E402

LABEL = {"scam": "scam", "suspicious": "scam", "looks_genuine": "genuine", "cant_tell": "unverifiable"}


def main() -> None:
    rows = store.conn().execute(
        "SELECT f.id, f.check_id, f.verdict AS shown, f.suggested, f.note, c.masked_text FROM flags f JOIN checks c ON c.id = f.check_id WHERE f.status = 'confirmed'"
    ).fetchall()
    out = []
    for r in rows:
        r = dict(r)
        verdict = r["suggested"] or r["shown"]
        if verdict not in LABEL or not r["masked_text"]:
            continue
        out.append({"kind": "reviewed_correction", "label": LABEL[verdict], "sender": "", "text": r["masked_text"], "shown": r["shown"], "note": r["note"], "flag": r["id"]})
    dest = ROOT / "evals" / "reviewed_corrections.json"
    dest.write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"{len(out)} confirmed corrections written to {dest}")
    print("Read every row by eye for leftover personal details before it goes anywhere else.")


if __name__ == "__main__":
    main()
