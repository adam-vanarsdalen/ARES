"""ARES Ollama compatibility helpers."""

import json
import random
import re
import time
import urllib.error
import urllib.request

from utils.config import OLLAMA_BASE_URL, OLLAMA_MODEL, OLLAMA_USE_NO_THINK_PROMPT

OLLAMA_BASE = OLLAMA_BASE_URL
DEFAULT_MODEL = OLLAMA_MODEL
USE_NO_THINK_PROMPT = OLLAMA_USE_NO_THINK_PROMPT


# ── Response shims (mimic Anthropic SDK shape) ────────────────────────────────
class ContentBlock:
    def __init__(self, type, text=None, id=None, name=None, input=None):
        self.type = type
        self.text = text or ""
        self.id = id or ""
        self.name = name or ""
        self.input = input or {}


class MessagesResponse:
    def __init__(self, content, stop_reason):
        self.content = content
        self.stop_reason = stop_reason


# ── Helpers ───────────────────────────────────────────────────────────────────
def _strip_think(text: str) -> str:
    """Remove <think>...</think> blocks emitted by Qwen extended thinking mode."""
    return re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()


def _to_ollama_messages(system: str, messages: list) -> list:
    result = []
    system_content = system or ""
    if USE_NO_THINK_PROMPT:
        system_content = f"/no_think\n{system_content}".strip()
    if system_content:
        result.append({"role": "system", "content": system_content})

    for msg in messages:
        role = msg["role"]
        content = msg["content"]
        if isinstance(content, str):
            result.append({"role": role, "content": content})
        elif isinstance(content, list):
            parts = []
            for block in content:
                if isinstance(block, dict):
                    if block.get("type") == "text":
                        parts.append(block.get("text", ""))
                    elif block.get("type") == "tool_result":
                        parts.append(str(block.get("content", "")))
                elif hasattr(block, "text"):
                    parts.append(block.text)
            result.append({"role": role, "content": " ".join(parts)})
    return result


def _tools_to_system_prompt(tools: list, existing_system: str = "") -> str:
    if not tools:
        return existing_system
    tool_desc = (
        "\n\nYou have access to these tools. To use one, respond ONLY with JSON:\n"
        '{"tool": "name", "input": {"param": "value"}}\n\nAvailable tools:\n'
    )
    for t in tools:
        props = t.get("input_schema", {}).get("properties", {})
        required = t.get("input_schema", {}).get("required", [])
        params = ", ".join(
            f"{k}{'*' if k in required else ''}: {v.get('type', 'any')}"
            for k, v in props.items()
        )
        tool_desc += f"\n- {t['name']}({params}): {t.get('description', '')}"
    tool_desc += "\n\nIf no tool is needed, respond in plain text."
    return (existing_system + tool_desc).strip()


def _parse_tool_call(text: str):
    candidate = extract_first_json_object(text)
    if not candidate:
        return None
    try:
        data = json.loads(candidate)
        if "tool" in data and "input" in data:
            return data
    except Exception:
        return None
    return None


def extract_first_json_object(text: str) -> str:
    text = text.strip()
    for start_idx, opener, closer in ((i, c, ("}" if c == "{" else "]")) for i, c in enumerate(text) if c in "{["):
        depth = 0
        in_string = False
        escape = False
        for idx in range(start_idx, len(text)):
            ch = text[idx]
            if in_string:
                if escape:
                    escape = False
                elif ch == "\\":
                    escape = True
                elif ch == '"':
                    in_string = False
                continue
            if ch == '"':
                in_string = True
            elif ch == opener:
                depth += 1
            elif ch == closer:
                depth -= 1
                if depth == 0:
                    candidate = text[start_idx:idx + 1]
                    try:
                        json.loads(candidate)
                        return candidate
                    except Exception:
                        break
    return ""


def _http_post_json(url: str, payload: dict, timeout_s: int | float) -> dict:
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout_s) as resp:
        return json.loads(resp.read())


def _is_cloud_model(model: str) -> bool:
    lowered = model.lower()
    return lowered.endswith(":cloud") or lowered.endswith("-cloud") or ":cloud-" in lowered


def ollama_chat(
    messages: list,
    *,
    model: str = DEFAULT_MODEL,
    system: str = "",
    max_tokens: int = 1000,
    timeout_s: int | float = 60,
    total_timeout_s: int | float | None = None,
    max_retries: int = 1,
    response_format: str | None = None,
    json_schema: dict | None = None,
    schema_hint: str | None = None,
    think: bool = False,
) -> dict:
    started_at = time.monotonic()
    total_timeout_s = total_timeout_s if total_timeout_s is not None else max(timeout_s * (max_retries + 1), timeout_s)
    attempt = 0
    repaired = False
    active_format = json_schema if json_schema is not None else ("json" if response_format == "json" else None)
    last_error = "Unknown Ollama error"

    while attempt <= max_retries:
        elapsed = time.monotonic() - started_at
        remaining = total_timeout_s - elapsed
        if remaining <= 0:
            return {"ok": False, "error": f"Ollama total timeout exceeded after {attempt} attempts"}
        if attempt > 0 and remaining <= min(float(timeout_s), 1.0):
            return {"ok": False, "error": f"Ollama total timeout exceeded after {attempt} attempts"}

        payload = {
            "model": model,
            "messages": _to_ollama_messages(system, messages),
            "think": think,
            "stream": False,
            "options": {"num_predict": max_tokens, "temperature": 0.1},
        }
        if active_format is not None:
            payload["format"] = active_format

        try:
            result = _http_post_json(f"{OLLAMA_BASE}/api/chat", payload, timeout_s)
        except (urllib.error.URLError, TimeoutError) as exc:
            last_error = str(exc)
            attempt += 1
            continue
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

        if result.get("error"):
            return {"ok": False, "error": result["error"]}

        raw_text = result.get("message", {}).get("content", "")
        text = _strip_think(raw_text)
        if not text:
            if active_format not in (None, "json"):
                last_error = "Model returned empty content with schema format"
                active_format = "json"
                attempt += 1
                continue
            if active_format == "json":
                last_error = "Model returned empty content with JSON format"
                if _is_cloud_model(model):
                    attempt += 1
                    continue
                active_format = None
                attempt += 1
                continue
            last_error = "Model returned empty content"
            attempt += 1
            continue

        if response_format == "json":
            extracted = extract_first_json_object(raw_text) or extract_first_json_object(text)
            if extracted:
                try:
                    return {"ok": True, "text": text, "data": json.loads(extracted), "repaired": repaired}
                except Exception:
                    pass
            if schema_hint and not repaired:
                repaired = True
                repair_messages = messages + [{
                    "role": "user",
                    "content": (
                        "Your last response was not valid JSON. "
                        f"{schema_hint}. Return only valid JSON."
                    ),
                }]
                repair_res = ollama_chat(
                    repair_messages,
                    model=model,
                    system=system,
                    max_tokens=max_tokens,
                    timeout_s=timeout_s,
                    total_timeout_s=max(total_timeout_s - (time.monotonic() - started_at), 0.01),
                    max_retries=0,
                    response_format=response_format,
                    json_schema=json_schema,
                    schema_hint=None,
                    think=think,
                )
                if repair_res.get("ok"):
                    repair_res["repaired"] = True
                    return repair_res
            last_error = f"Invalid JSON response: {text[:200]}"
            attempt += 1
            continue

        return {"ok": True, "text": text, "data": None, "repaired": repaired}

    return {"ok": False, "error": last_error}


# ── Main client ───────────────────────────────────────────────────────────────
class Messages:
    def create(self, model=DEFAULT_MODEL, max_tokens=1000, system="",
               messages=None, tools=None, **kwargs) -> MessagesResponse:
        effective_system = _tools_to_system_prompt(tools or [], system)
        response_format = kwargs.get("response_format") or ("json" if tools else None)
        res = ollama_chat(
            messages or [],
            model=model,
            system=effective_system,
            max_tokens=max_tokens,
            timeout_s=kwargs.get("timeout_s", 180),
            total_timeout_s=kwargs.get("total_timeout_s"),
            max_retries=kwargs.get("max_retries", 1),
            response_format=response_format,
            json_schema=kwargs.get("json_schema"),
            schema_hint=kwargs.get("schema_hint"),
            think=kwargs.get("think", False),
        )
        if not res.get("ok"):
            raise ConnectionError(res.get("error", "Unknown Ollama error"))

        text = res.get("text", "")
        if tools:
            tc = _parse_tool_call(text)
            if tc:
                if tc["tool"] == "final":
                    final_text = tc.get("input", {}).get("text", "")
                    return MessagesResponse(
                        content=[ContentBlock(type="text", text=final_text)],
                        stop_reason="end_turn",
                    )
                return MessagesResponse(
                    content=[ContentBlock(
                        type="tool_use",
                        id=f"call_{random.randint(1000, 9999)}",
                        name=tc["tool"],
                        input=tc["input"],
                    )],
                    stop_reason="tool_use",
                )

        return MessagesResponse(content=[ContentBlock(type="text", text=text)], stop_reason="end_turn")


class OllamaClient:
    """Drop-in replacement for anthropic.Anthropic()"""
    def __init__(self, **kwargs):
        self.messages = Messages()


def check_ollama() -> dict:
    """Check if Ollama is running and list available models."""
    try:
        req = urllib.request.Request(
            f"{OLLAMA_BASE}/api/tags",
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
            return {"running": True, "models": [m["name"] for m in data.get("models", [])]}
    except Exception:
        return {"running": False, "models": []}
