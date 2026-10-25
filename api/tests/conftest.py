import os
import sys
import tempfile
from pathlib import Path

# Offline, keyless, like a judge with an empty .env. Set before checkam is imported.
tmp = Path(tempfile.mkdtemp(prefix="checkam-test-"))
os.environ.update({
    "SAMPLE_MODE": "true", "MODEL_API_KEY": "", "ZETARIS_API_KEY": "", "ZETARIS_ADMIN_PASSWORD": "",
    "WORLD_MODEL_URL": "", "SCOUT_URL": "",
    "CHECKAM_DB": str(tmp / "test.db"), "CHECKAM_LOG_DIR": str(tmp / "logs"),
    "PSEUDONYM_KEY": "dGVzdC1rZXktbm90LXRoZS1yZWFsLW9uZQ==", "PSEUDONYM_KEY_FILE": "",
    "CHECKAM_SECRET": "test-secret", "CHECKAM_LINKCHECK": "0",
})
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
