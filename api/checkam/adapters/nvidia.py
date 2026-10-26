"""NVIDIA Nemotron over the OpenAI-compatible API. Every call is traced; with no key, or when the
API fails, callers get None and fall back to their rule-based path."""
import json
import random
import re
import threading
import time

import httpx

from .. import config
from ..trace import Trace, timer


def enabled() -> bool:
    return bool(config.MODEL_API_KEY)


_client = httpx.Client(limits=httpx.Limits(max_connections=16, max_keepalive_connections=8))
_slots = threading.BoundedSemaphore(int(config.env("NVIDIA_MAX_INFLIGHT", "6")))


class Pacer:
    """The hosted API limits requests per minute per key. Calls queue for their turn instead of
    being refused; after a refusal the pace slows down for a while, then recovers."""

    def __init__(self, key: str, rpm: float):
        self.key, self.gap, self.base = key, 60.0 / rpm, 60.0 / rpm
        self.next, self.strikes = 0.0, 0
        self.lock = threading.Lock()

    def wait(self, deadline: float) -> bool:
        with self.lock:
            now = time.monotonic()
            start = max(now, self.next)
            if start > deadline - 2:
                return False
            self.next = start + self.gap
            self.gap = max(self.base, self.gap * 0.97)  # recover towards the normal pace
        time.sleep(start - now)
        return True

    def refused(self, retry_after: float | None = None) -> None:
        """A refused key sits out its cooldown, so the next try goes to another key instead of knocking again."""
        with self.lock:
            self.gap = min(self.gap * 2, 10.0)
            self.strikes += 1
            rest = retry_after if retry_after else min(5.0 * 2 ** (self.strikes - 1), 60.0)
            self.next = max(self.next, time.monotonic() + rest)

    def served(self) -> None:
        self.strikes = 0


# several keys (comma-separated) share the load, each at its own pace
_pacers = [Pacer(k.strip(), float(config.env("NVIDIA_RPM", "35"))) for k in config.MODEL_API_KEY.split(",") if k.strip()]
_turn_lock = threading.Lock()


def _pacer(deadline: float) -> "Pacer | None":
    for _ in range(len(_pacers)):
        with _turn_lock:
            p = min(_pacers, key=lambda x: x.next)  # the key free soonest
        if p.wait(deadline):
            return p
    return None


def _post(path: str, body: dict, timeout: float) -> dict:
    """timeout is the budget for the whole call, retries included, so one slow step cannot stall a check."""
    last = None
    deadline = time.monotonic() + timeout
    for attempt in range(4):
        pacer = _pacer(deadline)
        left = deadline - time.monotonic()
        if pacer is None or left < 2:
            last = last or "no turn left within the time budget"
            break
        try:
            with _slots:
                r = _client.post(f"{config.MODEL_BASE_URL.rstrip('/')}{path}", json=body, timeout=left,
                                 headers={"Authorization": f"Bearer {pacer.key}"})
            if r.status_code == 429:
                wait = r.headers.get("retry-after", "")
                pacer.refused(float(wait) if wait.replace(".", "", 1).isdigit() else None)
                last = "429 on one key, trying the next"
                continue  # the refused key is benched; the next turn goes to another key at once
            if r.status_code >= 500:
                raise httpx.HTTPStatusError(f"{r.status_code}", request=r.request, response=r)
            r.raise_for_status()
            out = r.json()
            if "choices" not in out and "data" not in out:
                raise ValueError(f"no choices in reply: {str(out)[:120]}")
            pacer.served()
            return out
        except httpx.HTTPStatusError as e:
            last = e
            if e.response.status_code < 500 and e.response.status_code != 429:
                break  # a bad request will not get better by asking again
            wait = e.response.headers.get("retry-after", "")
            pause = min(float(wait), 8) if wait.replace(".", "", 1).isdigit() else 1.5 * 2 ** attempt + random.random()
            time.sleep(max(0, min(pause, deadline - time.monotonic() - 2)))
        except (httpx.HTTPError, ValueError) as e:
            last = e
            time.sleep(1 + attempt + random.random())
    raise RuntimeError(f"nvidia call failed: {last}")


def chat(messages: list[dict], *, model: str | None = None, trace: Trace | None = None, agent: str = "",
         action: str = "llm", max_tokens: int = 700, temperature: float = 0.2, timeout: float = 90, think: bool = False) -> str | None:
    if not enabled():
        return None
    model = model or config.MODEL_REASON
    with timer() as t:
        try:
            body = {"model": model, "messages": messages, "max_tokens": max_tokens, "temperature": temperature}
            if not think and model in (config.MODEL_REASON, config.MODEL_FAST):
                body["chat_template_kwargs"] = {"enable_thinking": False}
            out = _post("/chat/completions", body, timeout)
            text = out["choices"][0]["message"]["content"] or ""
            status = "ok"
        except Exception as e:
            text, status = None, f"error: {e}"
    if trace:
        trace.log(agent, action, input=messages[-1]["content"] if isinstance(messages[-1]["content"], str) else "[image+text]",
                  output=text if text is not None else status, status="ok" if text is not None else "error",
                  sponsor="nvidia", latency_ms=t.ms, model=model, thinking=think)
    return text


def chat_json(messages: list[dict], **kw) -> dict | None:
    text = chat(messages, **kw)
    if not text:
        return None
    text = re.sub(r"(?s)<think>.*?</think>", "", text)
    m = re.search(r"\{.*\}", text, re.S)
    if not m:
        return None
    try:
        return json.loads(m.group(0))
    except json.JSONDecodeError:
        return None


def read_image(image_b64: str, mime: str, trace: Trace | None = None) -> str | None:
    """Screenshot to text with Nemotron VL."""
    msg = [{"role": "user", "content": [
        {"type": "text", "text": "Transcribe every word of the message(s) in this screenshot exactly, including the sender name or number shown at the top. Output only the transcription."},
        {"type": "image_url", "image_url": {"url": f"data:{mime};base64,{image_b64}"}},
    ]}]
    return chat(msg, model=config.MODEL_REASON, trace=trace, agent="Intake", action="read_screenshot", max_tokens=900, timeout=90)


def embed(texts: list[str], trace: Trace | None = None, kind: str = "passage") -> list[list[float]] | None:
    if not enabled() or not texts:
        return None
    with timer() as t:
        try:
            out = _post("/embeddings", {"model": config.MODEL_EMBED, "input": [x[:2000] for x in texts],
                                        "input_type": kind, "encoding_format": "float", "truncate": "END"}, 90)
            vecs = [d["embedding"] for d in out["data"]]
            status = "ok"
        except Exception as e:
            vecs, status = None, f"error: {e}"
    if trace:
        trace.log("Investigator", "embed", input=f"{len(texts)} texts", output=f"{len(vecs)} vectors" if vecs else status,
                  status="ok" if vecs else "error", sponsor="nvidia", latency_ms=t.ms, model=config.MODEL_EMBED)
    return vecs


def safety(user_text: str, reply: str, trace: Trace | None = None) -> bool | None:
    """Nemotron content-safety on the reply we are about to show. The scam itself is expected to be
    'unsafe'; only the response verdict matters. None when the check could not run."""
    if not enabled():
        return None
    out = chat([{"role": "user", "content": user_text[:2000]}, {"role": "assistant", "content": reply}], model=config.MODEL_SAFETY,
               trace=trace, agent="Reporter", action="safety_check", max_tokens=60, timeout=45)
    if not out:
        return None
    m = re.search(r"(?i)response safety:\s*(\w+)", out)
    return None if not m else m.group(1).lower() == "safe"
