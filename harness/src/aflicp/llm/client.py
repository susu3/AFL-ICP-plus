"""Small provider adapters; request hashes, raw responses and attempts are auditable."""
import base64
import http.client
import json
import os
import shutil
import socket
import time
import urllib.parse
from pathlib import Path
from ..common import ICPError, append_jsonl, atomic_write, digest, read_json, save_json


class ModelClient:
    def __init__(self, config, run_root):
        self.config, self.root = config, Path(run_root)
        self.cache_root = Path(config["paths"]["output_root"]) / "cache" / "validated_artifacts" / "llm"

    def _snapshot(self, cache, key):
        destination = self.root / "llm_calls" / key
        destination.mkdir(parents=True, exist_ok=True)
        for path in cache.iterdir():
            if path.is_file() and not path.is_symlink():
                target = destination / path.name
                if not target.exists():
                    shutil.copyfile(path, target)

    def call(self, profile_name, stage, data, images=()):
        profile = self.config["llm"]["profiles"].get(profile_name)
        if not profile:
            raise ICPError("Missing LLM profile: " + profile_name, "configuration")
        serialized_data = json.dumps(data, ensure_ascii=False)
        if len(serialized_data) > self.config["document"]["max_context_chars"]:
            raise ICPError("Context exceeds configured limit for " + stage + "; partition the specification or raise document.max_context_chars", "context_limit")
        for image_path in images:
            if Path(image_path).stat().st_size > self.config["document"]["max_page_image_bytes"]:
                raise ICPError("Whole-page screenshot exceeds document.max_page_image_bytes; lower render_scale or adjust the configured bound", "context_limit")
        prompt_path = Path(__file__).parent.parent / "prompts" / (stage + ".md")
        prompt = prompt_path.read_text()
        key = digest({"profile": profile, "stage": stage, "prompt": prompt, "data": data,
                      "images": [digest(Path(p).read_bytes()) for p in images]})
        cache = self.cache_root / key
        if (cache / "parsed.json").exists():
            history = read_json(cache / "usage.json") if (cache / "usage.json").exists() else {}
            append_jsonl(self.root / "usage" / "usage.jsonl", {**history, "stage": stage, "key": key,
                          "cached": True, "charged_cost": 0, "historical_cost": history.get("cost")})
            self._snapshot(cache, key)
            return read_json(cache / "parsed.json")
        provider = profile.get("provider", "compatible")
        if provider not in ("compatible", "anthropic"):
            raise ICPError("Unsupported provider: " + provider, "configuration")
        endpoint = urllib.parse.urlsplit(profile["endpoint"])
        if endpoint.scheme not in ("https", "http") or endpoint.username or endpoint.password or endpoint.query:
            raise ICPError("Invalid model endpoint; configure credentials through api_key_env, not URL query/userinfo", "configuration")
        if endpoint.scheme == "http" and endpoint.hostname not in ("127.0.0.1", "localhost", "::1"):
            raise ICPError("Non-local model endpoints must use HTTPS", "configuration")
        if self.config["offline"] and endpoint.hostname not in ("127.0.0.1", "localhost", "::1"):
            raise ICPError("Offline mode prohibits remote model endpoint", "offline")
        api = self.config["llm"]["api"]
        text = serialized_data
        pictures = [(base64.b64encode(Path(p).read_bytes()).decode(), "image/png") for p in images]
        if provider == "compatible":
            content = [{"type": "text", "text": text}] + [
                {"type": "image_url", "image_url": {"url": "data:" + mime + ";base64," + b64}} for b64, mime in pictures]
            body = {"model": profile["model"], "messages": [{"role": "system", "content": prompt},
                    {"role": "user", "content": content}], **profile.get("parameters", {})}
        else:
            body = {"model": profile["model"], "system": prompt, "max_tokens": profile.get("max_tokens", 8192),
                    "messages": [{"role": "user", "content": [{"type": "text", "text": text}] + [
                        {"type": "image", "source": {"type": "base64", "media_type": mime, "data": b64}} for b64, mime in pictures]}],
                    **profile.get("parameters", {})}
        headers = {"Content-Type": "application/json"}
        secret = os.environ.get(profile.get("api_key_env", ""), "")
        if profile.get("api_key_env") and not secret:
            raise ICPError("Missing credential environment variable: " + profile["api_key_env"], "authentication")
        if secret:
            headers["Authorization" if provider == "compatible" else "x-api-key"] = ("Bearer " if provider == "compatible" else "") + secret
        if provider == "anthropic":
            headers["anthropic-version"] = profile.get("api_version", "2023-06-01")
        cache.mkdir(parents=True, exist_ok=True)
        save_json(cache / "request.json", {"stage": stage, "profile": profile_name, "model": profile["model"],
                  "prompt_hash": digest(prompt.encode()), "data_hash": digest(text.encode()), "data_bytes": len(text.encode()),
                  "image_hashes": [digest(Path(p).read_bytes()) for p in images], "images_bytes": sum(Path(p).stat().st_size for p in images)})
        atomic_write(cache / "system.md", prompt)
        last = None
        for attempt in range(api["max_retries"] + 1):
            started = time.monotonic()
            entry = {"stage": stage, "profile": profile_name, "provider": provider, "model": profile["model"],
                     "key": key, "attempt": attempt, "cached": False, "tokens": None, "cost": None}
            conn = None
            try:
                cls = http.client.HTTPSConnection if endpoint.scheme == "https" else http.client.HTTPConnection
                conn = cls(endpoint.hostname, endpoint.port, timeout=api["connect_timeout_seconds"])
                conn.connect()
                conn.sock.settimeout(api["request_timeout_seconds"])
                conn.request("POST", endpoint.path + ("?" + endpoint.query if endpoint.query else ""), json.dumps(body).encode(), headers)
                response = conn.getresponse()
                raw = response.read(api["max_response_bytes"] + 1)
                if len(raw) > api["max_response_bytes"]:
                    raise ICPError("Model response exceeds configured llm.api.max_response_bytes", "response_limit")
                atomic_write(cache / ("response-%d.json" % attempt), raw)
                entry["request_id"] = response.getheader("x-request-id")
                if response.status >= 400:
                    raise ICPError("Model HTTP %d: %s" % (response.status, raw.decode(errors="replace")[:2000]),
                                   "authentication" if response.status in (401, 403) else "api", response.status in (408, 429) or response.status >= 500)
                payload = json.loads(raw)
                entry["tokens"] = payload.get("usage")
                if provider == "compatible":
                    choice = payload["choices"][0]
                    finish = choice.get("finish_reason")
                    answer = choice["message"]["content"]
                else:
                    finish = payload.get("stop_reason")
                    answer = "".join(b["text"] for b in payload["content"] if b["type"] == "text")
                if finish in ("length", "max_tokens"):
                    raise ICPError("Model output truncated", "truncation")
                result = json.loads(answer)  # strict entire response, no regex extraction or fence guessing
                if not isinstance(result, dict):
                    raise ICPError("Expected a JSON object", "model_format")
                entry.update({"ok": True, "finish_reason": finish})
                prices = profile.get("prices_per_million")
                if prices and entry["tokens"]:
                    usage = entry["tokens"]
                    incoming = usage.get("prompt_tokens", usage.get("input_tokens"))
                    outgoing = usage.get("completion_tokens", usage.get("output_tokens"))
                    if incoming is not None and outgoing is not None:
                        entry["cost"] = {"amount": (incoming * prices["input"] + outgoing * prices["output"]) / 1000000,
                                         "currency": prices.get("currency", "USD"), "price_version": prices.get("version", "unknown")}
                save_json(cache / "parsed.json", result)
                save_json(cache / "usage.json", entry)
                self._snapshot(cache, key)
                return result
            except (OSError, socket.timeout, http.client.HTTPException) as exc:
                last = ICPError(str(exc), "transport", True)
                entry.update({"ok": False, "error": str(last)})
            except (ValueError, KeyError, IndexError, TypeError) as exc:
                last = ICPError("Invalid structured model response: " + str(exc), "model_format")
                entry.update({"ok": False, "error": str(last)})
            except ICPError as exc:
                last = exc
                entry.update({"ok": False, "error": str(last)})
            finally:
                if conn:
                    conn.close()
                entry["elapsed_seconds"] = time.monotonic() - started
                append_jsonl(self.root / "usage" / "usage.jsonl", entry)
            if not last.retryable or attempt == api["max_retries"]:
                self._snapshot(cache, key)
                raise last
            time.sleep(min(api["backoff_seconds"] * 2 ** attempt, api["max_backoff_seconds"]))


def require_review(result):
    if result.get("is_valid") is not True or not isinstance(result.get("issues"), list) or result["issues"] or result.get("unresolved_questions"):
        raise ICPError("Review did not approve: " + json.dumps(result, ensure_ascii=False), "review", True)
