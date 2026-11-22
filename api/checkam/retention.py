"""What CheckAm keeps, for how long, and what happens to it after.

A saved check (the message with numbers as codes, the verdict, the kind of scam) stays in the live database for
`check_keep_days`. After that it is counted into anonymous monthly totals, written into a compressed archive file, and
removed from the live database and from the campaign graph. The archive stays for `archive_keep_days` more, then it is
deleted. The totals are kept for good, so the public counter never goes down. Only the administrator can change these
periods or open the archive."""
import gzip
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import config, store
from .adapters import world

ARCHIVE_NAME = "checks-{month}.jsonl.gz"


def archive_dir() -> Path:
    return config.ARCHIVE_DIR


def archive_files() -> list[dict]:
    d = archive_dir()
    if not d.exists():
        return []
    return [{"name": f.name, "bytes": f.stat().st_size} for f in sorted(d.glob("checks-*.jsonl.gz"))]


def _iso(days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(timespec="seconds")


def _expire_archives(cfg: dict) -> list[str]:
    """An archive file lives until its month is older than the live period plus the archive period."""
    d = archive_dir()
    gone = []
    if not d.exists():
        return gone
    horizon = datetime.now(timezone.utc) - timedelta(days=cfg["check_keep_days"] + cfg["archive_keep_days"])
    for f in d.glob("checks-*.jsonl.gz"):
        try:
            y, m = f.stem.removesuffix(".jsonl").split("-")[1:3]
            month_end = datetime(int(y), int(m), 28, tzinfo=timezone.utc) + timedelta(days=4)
        except (ValueError, IndexError):
            continue
        if month_end < horizon:
            f.unlink(missing_ok=True)
            gone.append(f.name)
    return gone


def run(dry_run: bool = False, who: str = "system") -> dict:
    cfg = store.settings()
    cut = _iso(cfg["check_keep_days"])
    old = store.old_checks(cut)
    result: dict = {"dry_run": dry_run, "cutoff": cut, "checks_due": len(old), "would_delete": store.purge_preview()}
    if dry_run:
        return result
    store.add_monthly(old)
    if old and cfg["archive_keep_days"] > 0:
        archive_dir().mkdir(parents=True, exist_ok=True)
        by_month: dict[str, list[dict]] = {}
        for r in old:
            by_month.setdefault(r["created"][:7], []).append(r)
        for month, rows in by_month.items():
            with gzip.open(archive_dir() / ARCHIVE_NAME.format(month=month), "ab") as f:  # gzip members append cleanly
                for r in rows:
                    f.write((json.dumps(r, ensure_ascii=False, default=str) + "\n").encode("utf-8"))
        result["archived"] = len(old)
    result["deleted"] = store.purge_old()
    result["campaign_graph"] = world.forget(before=cut)
    result["archives_expired"] = _expire_archives(cfg)
    store.set_setting("last_retention", json.dumps({**result, "at": store.now(), "by": who}, default=str))
    return result


def last_run() -> dict | None:
    raw = store.get_setting("last_retention")
    return json.loads(raw) if raw else None


def forget_check(check_id: str, who: str) -> dict:
    """Delete one check everywhere it lives: the database, its signed-answer record, review flags and the campaign graph."""
    out = store.delete_check(check_id)
    out["campaign_graph"] = world.forget(ids=[check_id])
    store.admin_log(who, "delete_check", check_id)
    return out
