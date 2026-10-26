"""Optical character recognition with Tesseract (English and French), on the server itself.

Nemotron VL reads screenshots first because it understands layout (the sender line, bubbles, a cut message).
When it is busy, down or has no key, Tesseract still turns the screenshot into text, so a screenshot is
never left unread. Without the tesseract binary (a laptop without it), this adapter simply says so."""
import base64
import io
import shutil

from ..trace import Trace, timer

try:
    import pytesseract
    from PIL import Image, ImageOps
except ImportError:  # the image without OCR still runs
    pytesseract = None


def available() -> bool:
    return pytesseract is not None and shutil.which("tesseract") is not None


def read(image_b64: str, trace: Trace | None = None) -> str | None:
    if not available():
        if trace:
            trace.log("Intake", "ocr", output="tesseract not installed here", status="skipped")
        return None
    with timer() as t:
        try:
            img = Image.open(io.BytesIO(base64.b64decode(image_b64)))
            img = ImageOps.exif_transpose(img).convert("L")  # phone photos come rotated; grey reads best
            if img.width < 1000:
                img = img.resize((img.width * 2, img.height * 2))  # small screenshots read better enlarged
            text = pytesseract.image_to_string(img, lang="eng+fra", config="--psm 6", timeout=20).strip()
            status = "ok" if text else "empty"
        except Exception as e:
            text, status = None, f"error: {e}"
    if trace:
        trace.log("Intake", "ocr", input="screenshot", output=(text or status)[:300], status="ok" if text else "error",
                  sponsor="none", latency_ms=t.ms, model="tesseract")
    return text or None
