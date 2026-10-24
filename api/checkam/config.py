import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
API = ROOT / "api"


def _load_env(path: Path) -> None:
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


_load_env(ROOT / ".env")


def env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


def flag(name: str, default: bool = False) -> bool:
    v = os.environ.get(name)
    return default if v is None else v.strip().lower() in ("1", "true", "yes", "on")


# An empty .env means sample mode: same agents, same SQL, local parquet instead of Zetaris.
SAMPLE_MODE = flag("SAMPLE_MODE", default=not env("ZETARIS_ADMIN_PASSWORD") and not env("ZETARIS_API_KEY"))

DATA_DIR = Path(env("CHECKAM_DATA_DIR", str(ROOT / "data")))
SAMPLE_DIR = DATA_DIR / "sample"
LOG_DIR = Path(env("CHECKAM_LOG_DIR", str(ROOT / "logs")))
DB_PATH = Path(env("CHECKAM_DB", str(DATA_DIR / "checkam.db")))

ZETARIS_JDBC_URL = env("ZETARIS_JDBC_URL", "jdbc:zetaris:lightning@localhost:10000")
ZETARIS_JDBC_JAR = env("ZETARIS_JDBC_JAR", str(ROOT.parent / "zetaris-platform" / "jdbc" / "ndp-jdbc-driver-2.4.3.1-7eff043-driver.jar"))
ZETARIS_USER = env("ZETARIS_ADMIN_EMAIL") or env("ZETARIS_USERNAME")
ZETARIS_PASSWORD = env("ZETARIS_ADMIN_PASSWORD") or env("ZETARIS_PASSWORD")
ZETARIS_REST_URL = env("ZETARIS_REST_URL", "http://127.0.0.1:8888/api/v1.0")
ZETARIS_API_KEY = env("ZETARIS_API_KEY")
ZETARIS_ORG_ID = env("ZETARIS_ORG_ID", "1")
ZETARIS_DB = env("ZETARIS_DB", "STOP_ARNAQUE")

MODEL_BASE_URL = env("MODEL_BASE_URL", "https://integrate.api.nvidia.com/v1")
MODEL_API_KEY = env("MODEL_API_KEY")
MODEL_REASON = env("NEMOTRON_MODEL", "nvidia/nemotron-3.5-super-vl-120b-a12b")
MODEL_FAST = env("NEMOTRON_FAST_MODEL", "nvidia/nemotron-3.5-lightning-30b-a3b")
MODEL_EMBED = env("NEMOTRON_EMBED_MODEL", "nvidia/nemotron-3.5-embed-1b")
MODEL_SAFETY = env("NEMOTRON_SAFETY_MODEL", "nvidia/nemotron-3.5-content-safety")

WORLD_MODEL_URL = os.environ.get("WORLD_MODEL_URL", "http://127.0.0.1:8790")
SCOUT_URL = os.environ.get("SCOUT_URL", "http://127.0.0.1:8791")

# HMAC key of the Stop Arnaque 237 pseudonyms. Lets a pasted real number match the dataset codes.
PSEUDONYM_KEY_FILE = env("PSEUDONYM_KEY_FILE")
PSEUDONYM_KEY_B64 = env("PSEUDONYM_KEY")

SECRET = env("CHECKAM_SECRET", "dev-only-change-me")
MAX_AGENT_ROUNDS = int(env("MAX_AGENT_ROUNDS", "3"))
