# Runs the three input examples against a running server and saves the real outputs.
#   python api/scripts/make_examples.py [base_url]
import json
import sys
import urllib.request
import uuid
from pathlib import Path

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000"
EX = Path(__file__).resolve().parents[2] / "examples"
(EX / "outputs").mkdir(parents=True, exist_ok=True)


def post_json(path, body):
    req = urllib.request.Request(BASE + path, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
    return json.loads(urllib.request.urlopen(req, timeout=300).read())


def post_image(path, file: Path, language="fr"):
    b = uuid.uuid4().hex
    body = (f"--{b}\r\nContent-Disposition: form-data; name=\"language\"\r\n\r\n{language}\r\n"
            f"--{b}\r\nContent-Disposition: form-data; name=\"image\"; filename=\"{file.name}\"\r\nContent-Type: image/png\r\n\r\n").encode()
    body += file.read_bytes() + f"\r\n--{b}--\r\n".encode()
    req = urllib.request.Request(BASE + path, data=body, headers={"Content-Type": f"multipart/form-data; boundary={b}"})
    return json.loads(urllib.request.urlopen(req, timeout=300).read())


text = {"mode": "check", "text": "Hello please I sent 25000 frs to your MTN number by mistake, it was for my mother hospital bill. "
        "Please send it back to me on this number [PHONE:654-jwmukg] God will bless you. Do it fast before they cut my line"}
(EX / "inputs" / "01_text_check.json").write_text(json.dumps(text, indent=2, ensure_ascii=False), encoding="utf-8")
(EX / "outputs" / "01_text_check.json").write_text(json.dumps(post_json("/run", text), indent=2, ensure_ascii=False), encoding="utf-8")
print("01 done")

out = post_image("/check/image", EX / "inputs" / "02_screenshot.png")
(EX / "outputs" / "02_screenshot_check.json").write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
print("02 done", out.get("verdict"))

inv = {"mode": "investigate"}
(EX / "inputs" / "03_investigate.json").write_text(json.dumps(inv, indent=2), encoding="utf-8")
(EX / "outputs" / "03_investigate.json").write_text(json.dumps(post_json("/run", inv), indent=2, ensure_ascii=False), encoding="utf-8")
print("03 done")

real = {"mode": "check", "sender": "MTN",
        "text": "1GB free + 3GB to stream at 200F to enjoy this football weekend, including tomorrow's Clasico. "
                "Get your MTN TV bundle now and be one of the first. *280*16*#"}
(EX / "inputs" / "04_real_operator.json").write_text(json.dumps(real, indent=2, ensure_ascii=False), encoding="utf-8")
(EX / "outputs" / "04_real_operator.json").write_text(json.dumps(post_json("/run", real), indent=2, ensure_ascii=False), encoding="utf-8")
print("04 done")
