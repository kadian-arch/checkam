"""Vet a link the way an analyst would: how old is the site, and does it belong to whoever the message
claims to be? Age comes from the public domain registry (RDAP, no key). Fails quiet: no answer, no claim."""
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as Late
from datetime import datetime, timezone

import httpx

from .. import config

_client = httpx.Client(timeout=httpx.Timeout(4.0, connect=2.0), follow_redirects=True, headers={"Accept": "application/rdap+json"})
_cache: dict[str, tuple[float, dict]] = {}
_lock = threading.Lock()
TWO_LEVEL = {"co.uk", "org.uk", "ac.uk", "gov.uk", "com.ng", "gov.ng", "co.za", "gov.cm", "com.cm", "co.cm", "gouv.fr", "gc.ca", "com.au", "gov.au", "co.ke", "go.ke"}

# who a message may claim to be, and the only places their links can point to
INSTITUTIONS = [
    (r"canad", "the Canadian government", "le gouvernement canadien", ("canada.ca", "gc.ca")),
    (r"\b(usa|u\.s\.|united states|[ée]tats[- ]unis|american|am[ée]ricain|us embassy|dv ?lottery|green card)\b", "the US government", "le gouvernement américain", ("state.gov", "usembassy.gov", "usa.gov", "uscis.gov")),
    (r"\b(uk|united kingdom|royaume[- ]uni|british|britannique|chevening)\b", "the UK government", "le gouvernement britannique", ("gov.uk", "chevening.org")),
    (r"\b(campus ?france|ambassade de france|france)\b", "the French government", "le gouvernement français", ("campusfrance.org", "gouv.fr", "france-visas.gouv.fr")),
    (r"\b(minesup|minfopra|minesec|minsant|gouvernement camerounais|government of cameroon|r[ée]publique du cameroun|prime minister|premier ministre|pr[ée]sidence)\b",
     "the Cameroon government", "le gouvernement camerounais", ("gov.cm", "minesup.gov.cm", "minfopra.gov.cm", "prc.cm", "spm.gov.cm")),
    (r"\bmtn\b|momo|mobile ?money", "MTN", "MTN", ("mtn.cm", "mtnonline.com", "mtn.com")),
    (r"\borange\b", "Orange", "Orange", ("orange.cm", "orange.com")),
    (r"\b(unicef|unesco|united nations|nations unies|\bun\b|who|oms|world bank|banque mondiale|daad|erasmus|mastercard foundation)\b",
     "an international organisation", "une organisation internationale", ("un.org", "unicef.org", "unesco.org", "who.int", "worldbank.org", "daad.de", "erasmus-plus.ec.europa.eu", "europa.eu", "mastercardfdn.org")),
]


def enabled() -> bool:
    return config.flag("CHECKAM_LINKCHECK", True)


def registrable(host: str) -> str:
    parts = host.lower().strip(".").split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in TWO_LEVEL:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


_pool = ThreadPoolExecutor(max_workers=4)
_jobs: dict[str, object] = {}
_bootstrap: dict[str, str] = {}


def _registry_for(domain: str) -> str:
    """The registry's own RDAP address for this ending (IANA directory, read once); rdap.org when unknown."""
    if not _bootstrap:
        try:
            for tlds, urls in _client.get("https://data.iana.org/rdap/dns.json").json().get("services", []):
                for tld in tlds:
                    _bootstrap[tld.lower()] = urls[0].rstrip("/") + "/"
        except (httpx.HTTPError, ValueError):
            pass
    return _bootstrap.get(domain.rsplit(".", 1)[-1], "https://rdap.org/")


def prefetch(hosts: list[str]) -> None:
    """Start the registry lookups as soon as the links are known, while the other agents work."""
    for h in hosts:
        d = registrable(h)
        with _lock:
            if d not in _jobs:
                _jobs[d] = _pool.submit(_age, d)


def age_days(host: str, budget: float = 5.0) -> int | None:
    """Days since the site was registered, or None when the registry does not answer within the budget."""
    d = registrable(host)
    prefetch([host])
    try:
        return _jobs[d].result(timeout=budget)
    except Late:
        return None
    finally:
        with _lock:
            job = _jobs.get(d)
            if job is not None and job.done():
                _jobs.pop(d, None)


def _age(domain: str) -> int | None:
    with _lock:
        hit = _cache.get(domain)
        if hit and time.time() - hit[0] < 6 * 3600:
            return hit[1].get("age")
    age = None
    try:
        r = _client.get(f"{_registry_for(domain)}domain/{domain}")
        if r.status_code == 200:
            for e in r.json().get("events", []):
                if e.get("eventAction") == "registration":
                    born = datetime.fromisoformat(e["eventDate"].replace("Z", "+00:00"))
                    age = (datetime.now(timezone.utc) - born).days
                    break
    except (httpx.HTTPError, ValueError, KeyError):
        return None  # not remembered: the next check asks again
    with _lock:
        _cache[domain] = (time.time(), {"age": age})
    return age


def claimed(text: str, lang: str = "en") -> tuple[str, tuple[str, ...]] | None:
    for rx, en, fr, domains in INSTITUTIONS:
        if re.search(rx, text, flags=re.I):
            return (fr if lang == "fr" else en), domains
    return None


def belongs(host: str, domains: tuple[str, ...]) -> bool:
    host = host.lower()
    return any(host == d or host.endswith("." + d) for d in domains)
