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
    (r"\b(unicef|unesco|united nations|nations unies|world bank|banque mondiale|daad|erasmus|mastercard foundation)\b|(?-i:\b(?:UN|WHO|OMS)\b)",
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


# ---------------------------------------------------------------------------------------------------------------
# What the address itself gives away, before any lookup: a look-alike of a known name, foreign letters made to look
# like ours, a bare number instead of a name, a free page builder, an ending scam sites buy because it costs nothing.
BRANDS = {"mtn": ("mtn.cm", "mtnonline.com", "mtn.com"), "momo": ("mtn.cm", "mtnonline.com", "mtn.com"), "orange": ("orange.cm", "orange.com"),
          "campost": ("campost.cm",), "eneo": ("eneo.cm",), "camtel": ("camtel.cm",), "nexttel": ("nexttel.cm",), "canada": ("canada.ca", "gc.ca"),
          "minesup": ("minesup.gov.cm",), "unicef": ("unicef.org",), "whatsapp": ("whatsapp.com", "wa.me"), "facebook": ("facebook.com", "fb.com"),
          "paypal": ("paypal.com",), "afriland": ("afrilandfirstbank.com",), "ecobank": ("ecobank.com",), "uba": ("ubagroup.com",), "bicec": ("bicec.com",)}
CHEAP_ENDINGS = {"xyz", "top", "click", "icu", "buzz", "sbs", "cyou", "monster", "tk", "ml", "ga", "cf", "gq", "rest", "cfd", "lol", "work", "shop", "site", "online", "live", "vip"}
FREE_BUILDERS = ("blogspot.", "wixsite.com", "weebly.com", "github.io", "firebaseapp.com", "web.app", "netlify.app", "vercel.app", "glitch.me", "000webhostapp.com",
                 "godaddysites.com", "google.com/forms", "forms.gle", "sites.google.com", "wordpress.com", "carrd.co", "webflow.io", "pages.dev")


def shape(host: str) -> list[tuple[str, str, str]]:
    """(strength, English, French) for each thing the address itself gives away. strength is 'strong' or 'weak'."""
    host = host.lower().strip(".")
    out: list[tuple[str, str, str]] = []
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
        return [("strong", "It sends you to a bare number address instead of a website name, which real companies do not do",
                 "Il vous envoie vers une adresse faite de chiffres au lieu d'un nom de site, ce que les vraies entreprises ne font pas")]
    if "xn--" in host:
        out.append(("strong", "The address uses foreign letters made to look like ours, a way to copy a real name",
                    "L'adresse utilise des lettres étrangères faites pour ressembler aux nôtres, une façon de copier un vrai nom"))
    dom = registrable(host)
    tokens = [t for t in re.split(r"[.\-_0-9]+", host) if t]
    for brand, official in BRANDS.items():
        if any(t == brand or (len(brand) >= 4 and t.startswith(brand) and len(t) <= len(brand) + 9) for t in tokens):
            if not any(host == d or host.endswith("." + d) for d in official):
                out.append(("strong", f"The address contains the name {brand.upper() if len(brand) < 5 else brand.title()} but is not their site (theirs ends in {official[0]})",
                            f"L'adresse contient le nom {brand.upper() if len(brand) < 5 else brand.title()} mais n'est pas leur site (le leur finit par {official[0]})"))
                break
    if any(host == f.rstrip(".") or host.endswith(("." + f).rstrip(".")) or f in host for f in FREE_BUILDERS if "/" not in f):
        out.append(("weak", "It is a page anyone can build for free, not a company's own website",
                    "C'est une page que n'importe qui peut créer gratuitement, pas le site propre d'une entreprise"))
    elif dom.rsplit(".", 1)[-1] in CHEAP_ENDINGS and dom not in {"live", "online"}:
        out.append(("weak", f"The ending .{dom.rsplit('.', 1)[-1]} costs almost nothing, which is why scam sites favour it",
                    f"La terminaison .{dom.rsplit('.', 1)[-1]} ne coûte presque rien, c'est pourquoi les sites d'arnaque l'aiment"))
    if host.count("-") >= 3:
        out.append(("weak", "The address is stuffed with hyphens, a common way to make a fake name look official",
                    "L'adresse est pleine de tirets, une façon courante de faire passer un faux nom pour officiel"))
    return out
