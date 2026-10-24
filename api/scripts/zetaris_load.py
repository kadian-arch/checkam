"""Register the Stop Arnaque 237 parquet files in a local Zetaris install as database STOP_ARNAQUE.

Run once, after copying the files into the driver's customer-data volume (see docs/ZETARIS.md):
    python api/scripts/zetaris_load.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from checkam import config  # noqa: E402
from checkam.adapters.data import ZetarisJDBC  # noqa: E402

FOLDER = "/home/zetaris/customer-data/shared/stop_arnaque"
TABLES = {"messages": "messages.parquet", "reports": "reports.parquet", "public_alerts": "public_alerts.parquet",
          "genuine_messages": "genuine_messages.parquet", "scam_numbers": "scam_numbers.parquet"}

z = ZetarisJDBC()
have = {r["name"] for r in z.query("SHOW LIGHTNING DATABASES")}
if config.ZETARIS_DB not in have:
    z.query(f'CREATE LIGHTNING DATABASE {config.ZETARIS_DB} DESCRIBE BY "Stop Arnaque 237 v1.0, local files"')
for table, file in TABLES.items():
    try:
        z.query(f"SELECT 1 FROM {config.ZETARIS_DB}.{table} LIMIT 1")
        print(f"{table}: already registered")
    except Exception:
        z.query(f'CREATE LIGHTNING FILESTORE TABLE {table} FROM {config.ZETARIS_DB} FORMAT PARQUET OPTIONS (PATH "file://{FOLDER}/{file}")')
        print(f"{table}: registered")
for row in z.query(f"SELECT label, count(*) AS n FROM {config.ZETARIS_DB}.messages GROUP BY label"):
    print(row)
