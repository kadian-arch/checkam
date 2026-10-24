import re
import unicodedata

_TOKEN = re.compile(r"\[[A-Z_]+(?::[^\]]*)?\]")


def norm(text: str) -> str:
    t = unicodedata.normalize("NFKD", (text or "").lower())
    t = "".join(c for c in t if not unicodedata.combining(c))
    t = _TOKEN.sub(" ", t)
    t = re.sub(r"\d+", "#", t)
    return re.sub(r"[^a-z#]+", " ", t).strip()


def shingles(text: str, k: int = 5) -> set[str]:
    t = norm(text)
    return {t[i:i + k] for i in range(len(t) - k + 1)}


def jaccard(a: set, b: set) -> float:
    if not a or not b:
        return 0.0
    i = len(a & b)
    return i / (len(a) + len(b) - i)


def containment(small: set, big: set) -> float:
    """How much of the shorter text appears in the longer one: forwarded snippets of a kit still match."""
    if not small or not big:
        return 0.0
    if len(small) > len(big):
        small, big = big, small
    return len(small & big) / len(small)


def cosine(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    na = sum(x * x for x in a) ** 0.5
    nb = sum(y * y for y in b) ** 0.5
    return dot / (na * nb) if na and nb else 0.0


def words(text: str) -> set[str]:
    return {w for w in norm(text).split() if len(w) > 2}
