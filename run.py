"""CheckAm entry point.

  python run.py serve                         API + web app on PORT (default 8000)
  python run.py check "message text"          one citizen check, prints the verdict card
  python run.py investigate [campaign_id]     one analyst dossier
  python run.py seed                          load reports and alerts into the campaign graph
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "api"))


def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8")
    cmd = sys.argv[1] if len(sys.argv) > 1 else "serve"
    if cmd == "serve":
        import uvicorn
        uvicorn.run("checkam.app:app", host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
        return
    from checkam import agents, dossier, seed
    if cmd == "check":
        card = agents.run_check(" ".join(sys.argv[2:]) or sys.stdin.read())
        card.pop("trace", None)
        print(json.dumps(card, ensure_ascii=False, indent=2, default=str))
    elif cmd == "investigate":
        d = dossier.investigate(sys.argv[2] if len(sys.argv) > 2 else None)
        d.pop("trace", None)
        print(json.dumps(d, ensure_ascii=False, indent=2, default=str))
    elif cmd == "seed":
        print(seed.run())
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
