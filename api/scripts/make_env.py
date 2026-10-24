# Builds 05_build/.env from the hackathon root .env without printing any value.
from pathlib import Path

build = Path(__file__).resolve().parents[2]
src = build.parent / ".env"
keep = ["ZETARIS_ADMIN_EMAIL", "ZETARIS_ADMIN_PASSWORD", "ZETARIS_REST_URL", "ZETARIS_ORG_ID", "ZETARIS_API_KEY",
        "MODEL_BASE_URL", "MODEL_API_KEY", "NEMOTRON_MODEL", "METERLESS_API_KEY"]
vals = {}
for line in src.read_text(encoding="utf-8").splitlines():
    if "=" in line and not line.lstrip().startswith("#"):
        k, v = line.split("=", 1)
        if k.strip() in keep and v.strip():
            vals[k.strip()] = v.strip()
vals["PSEUDONYM_KEY_FILE"] = "D:/StopArnaque237/pipeline/.pseudonym_key"
vals["SAMPLE_MODE"] = "false"
out = build / ".env"
out.write_text("".join(f"{k}={v}\n" for k, v in vals.items()), encoding="utf-8")
print("wrote", out, "keys:", ", ".join(sorted(vals)))
