"""NVIDIA Nemotron over the OpenAI-compatible API. Every call is traced; with no key, or when the
API fails, callers get None and fall back to their rule-based path."""
import json
import re
import time

import httpx

from .. import config
from ..trace import Trace, timer


def enabled() -> bool:
    return bool(config.MODEL_API_KEY)


def _post(path: str, body: dict, timeout: float) -> dict:
    last = None
    for attempt in range(2):
        try:
            r = httpx.post(f"{config.MODEL_BASE_URL.rstrip('/')}{path}", json=body, timeout=timeout,
                           headers={"Authorization": f"Bearer {config.MODEL_API_KEY}"})
            if r.status_code == 429 or r.status_code >= 500:
                raise httpx.HTTPStatusError(f"{r.status_code}", request=r.request, response=r)
            r.raise_for_status()
            out = r.json()
            if "choices" not in out and "data" not in out:
                raise ValueError(f"no choices in reply: {str(out)[:120]}")
            return out
        except (httpx.HTTPError, ValueError) as e:
            last = e
            time.sleep(1.5 * (attempt + 1))
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
