import copy
import ipaddress
import re
from pathlib import Path
from .common import ICPError, digest, load_mapping

DEFAULTS = {
    "protocol": "MODBUS", "offline": False, "specifications": [],
    "document": {"render_scale": 2.0, "vision_pages": "all", "ocr_backend": "native",
                 "fallback_ocr_backend": "tesseract", "secondary_split_pages": 50, "max_context_chars": 160000,
                 "max_page_image_bytes": 16777216},
    "llm": {"profiles": {}, "api": {"max_retries": 3, "connect_timeout_seconds": 30,
            "request_timeout_seconds": 180, "max_backoff_seconds": 30, "max_response_bytes": 10485760,
            "backoff_seconds": 1}},
    "repair": {"specification_max_retries": 3, "adapter_max_retries": 3, "generator_max_retries": 3},
    "seeds": {"random_seed": 12345, "candidate_budget": 1000, "preferred_corpus_size": 200,
              "max_sequence_messages": 16, "max_seed_bytes": 1048576,
              "sandbox": {"backend": "bubblewrap", "cpu_limit": 1, "memory_mb": 256, "timeout_seconds": 60}},
    "campaign": {"duration_seconds": 60, "execution_timeout_ms": 1000, "memory_limit_mb": 100,
                 "startup_wait_us": 10000, "socket_timeout_us": 1000, "poll_wait_ms": 1,
                 "stop_timeout_seconds": 30, "feedback": 3, "seed_schedule": 1, "aflnet_arguments": []},
    "evidence": {"enabled": True, "periodic_interval": 1000, "queue_capacity_bytes": 1048576,
                 "max_record_bytes": 16777216, "pack_segment_bytes": 67108864, "writer_stall_timeout_seconds": 120,
                 "backpressure": "block", "save_coverage_bitmap": True},
    "analysis": {"replay_count": 1, "max_records": 100, "require_source_evidence": True}, "experiment": {"repetitions": 1},
    "reuse": {}, "target": {"host": "127.0.0.1", "port": 1502, "transport": "tcp", "build_backend": "local"}, "paths": {}
}


def merge(base, update):
    result = copy.deepcopy(base)
    for key, value in update.items():
        result[key] = merge(result[key], value) if isinstance(value, dict) and isinstance(result.get(key), dict) else copy.deepcopy(value)
    return result


def validate(config):
    errors = []
    def positive(section, keys, zero=False):
        for key in keys:
            value = config.get(section, {}).get(key)
            if type(value) is not int or value < (0 if zero else 1):
                errors.append(section + "." + key + " must be " + ("nonnegative" if zero else "positive") + " integer")
    if not re.fullmatch(r"[A-Z][A-Z0-9_]{0,31}", config.get("protocol", "")):
        errors.append("protocol must be an uppercase registry name")
    for key in ("user_seeds", "output_root"):
        if not config.get("paths", {}).get(key):
            errors.append("paths." + key + " is required")
    positive("campaign", ["duration_seconds", "execution_timeout_ms", "stop_timeout_seconds", "memory_limit_mb",
                           "startup_wait_us", "poll_wait_ms", "socket_timeout_us"])
    positive("evidence", ["periodic_interval"], True)
    positive("evidence", ["queue_capacity_bytes", "max_record_bytes", "pack_segment_bytes", "writer_stall_timeout_seconds"])
    if config["evidence"]["max_record_bytes"] < 76:
        errors.append("evidence.max_record_bytes must include the 20-byte frame and fixed 56-byte payload")
    if config["evidence"]["max_record_bytes"] > 2**32 - 1 or config["evidence"]["queue_capacity_bytes"] > 2**31 - 1:
        errors.append("evidence record/queue byte bounds exceed the C recorder ABI limits")
    if config["evidence"]["pack_segment_bytes"] < config["evidence"]["max_record_bytes"] + 20:
        errors.append("evidence.pack_segment_bytes must fit at least one maximum-sized framed record")
    positive("seeds", ["candidate_budget", "preferred_corpus_size", "max_sequence_messages", "max_seed_bytes"])
    if config["seeds"]["candidate_budget"] < 2 or config["seeds"]["max_sequence_messages"] < 2:
        errors.append("seed generation requires candidate_budget >= 2 and max_sequence_messages >= 2")
    for key in ("cpu_limit", "memory_mb", "timeout_seconds"):
        value = config["seeds"]["sandbox"].get(key)
        if type(value) not in (int, float) or value <= 0:
            errors.append("seeds.sandbox.%s must be positive" % key)
    sandbox_backend = config["seeds"]["sandbox"].get("backend", "bubblewrap")
    if sandbox_backend not in ("bubblewrap", "docker"):
        errors.append("seeds.sandbox.backend must be bubblewrap or docker")
    if sandbox_backend == "docker" and not config["seeds"]["sandbox"].get("image"):
        errors.append("seeds.sandbox.image is required when backend=docker")
    positive("analysis", ["replay_count", "max_records"])
    positive("experiment", ["repetitions"])
    positive("repair", list(DEFAULTS["repair"]), True)
    positive("document", ["secondary_split_pages", "max_context_chars"])
    positive("document", ["max_page_image_bytes"])
    if type(config["document"].get("render_scale")) not in (int, float) or config["document"]["render_scale"] <= 0:
        errors.append("document.render_scale must be positive")
    if config["document"].get("vision_pages") != "all":
        errors.append("document.vision_pages must be all; every complete PDF page is retained and reviewed")
    if config["document"]["max_context_chars"] < 1000:
        errors.append("document.max_context_chars must be at least 1000")
    if type(config["llm"]["api"]["max_retries"]) is not int or config["llm"]["api"]["max_retries"] < 0:
        errors.append("llm.api.max_retries must be nonnegative")
    for key in ("connect_timeout_seconds", "request_timeout_seconds"):
        if type(config["llm"]["api"].get(key)) not in (int, float) or config["llm"]["api"][key] <= 0:
            errors.append("llm.api.%s must be positive" % key)
    if type(config["llm"]["api"].get("max_response_bytes")) is not int or config["llm"]["api"]["max_response_bytes"] < 1024:
        errors.append("llm.api.max_response_bytes must be an integer of at least 1024")
    for key in ("backoff_seconds", "max_backoff_seconds"):
        if type(config["llm"]["api"].get(key)) not in (int, float) or config["llm"]["api"][key] < 0:
            errors.append("llm.api.%s must be nonnegative" % key)
    if config["evidence"]["backpressure"] != "block":
        errors.append("evidence.backpressure must be block")
    if config["analysis"].get("require_source_evidence") is not True:
        errors.append("analysis.require_source_evidence must be true for confirmed findings")
    if not isinstance(config["campaign"].get("aflnet_arguments", []), list) or any(not isinstance(a, str) for a in config["campaign"].get("aflnet_arguments", [])):
        errors.append("campaign.aflnet_arguments must be a list of strings")
    environment = config["target"].get("environment", {})
    if not isinstance(environment, dict):
        errors.append("target.environment must map names to env references")
    else:
        for key, value in environment.items():
            if key.startswith("AFLICP_") or not isinstance(value, dict) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value.get("from_env", "")):
                errors.append("target.environment.%s must use {from_env: ENV_NAME} and cannot override AFLICP_*" % key)
    try:
        address = ipaddress.ip_address(config["target"]["host"])
        lab_nets = (ipaddress.ip_network("10.0.0.0/8"), ipaddress.ip_network("172.16.0.0/12"),
                    ipaddress.ip_network("192.168.0.0/16"), ipaddress.ip_network("127.0.0.0/8"),
                    ipaddress.ip_network("169.254.0.0/16"))
        if address.version != 4 or not any(address in network for network in lab_nets):
            errors.append("target host must be a local or private authorized lab address")
    except (ValueError, TypeError, KeyError):
        if config["target"].get("host") == "localhost":
            pass
        else:
            errors.append("target.host must be a literal lab IP address or localhost")
    if not 1 <= config["target"].get("port", 0) <= 65535:
        errors.append("target.port is invalid")
    if config["target"].get("transport") != "tcp":
        errors.append("first validated runner supports TCP only")
    if config["target"].get("executable"):
        if not isinstance(config["target"].get("launch_argv", []), list) or any(not isinstance(arg, str) for arg in config["target"].get("launch_argv", [])):
            errors.append("target.launch_argv must be an argv list of strings")
    elif config["target"].get("recipe") != "libmodbus":
        errors.append("provide a local target.executable or the reviewed libmodbus recipe")
    elif not config["target"].get("source") and not config["target"].get("repository"):
        errors.append("libmodbus recipe requires target.source or target.repository")
    elif config["target"].get("repository") and not config["target"].get("ref"):
        errors.append("remote target.repository requires an immutable target.ref")
    build_backend = config["target"].get("build_backend", "local")
    if build_backend not in ("local", "docker"):
        errors.append("target.build_backend must be local or docker")
    if (not config["target"].get("executable") and build_backend == "docker"
            and not config["target"].get("build_image")):
        errors.append("target.build_image is required when target.build_backend=docker")
    if not isinstance(config["specifications"], list) or not config["specifications"]:
        errors.append("at least one specification PDF is required")
    specs = config["specifications"] if isinstance(config["specifications"], list) else []
    ids = [s.get("id") for s in specs if isinstance(s, dict)]
    if len(ids) != len(specs) or len(set(ids)) != len(ids) or any(not i or not re.fullmatch(r"[A-Za-z0-9_-]+", i) for i in ids):
        errors.append("specification ids must be unique safe identifiers")
    # These flags must not override artifact/campaign identities assembled by the controller.
    forbidden = {"-i", "-o", "-P", "-N", "-t", "-m", "-D", "-W", "-w", "-F", "-R", "-E", "-K", "-c", "-q", "-s", "-h", "-b"}
    if any(a in forbidden or (a.startswith("-") and a[:2] in forbidden) or a == "--" for a in config["campaign"]["aflnet_arguments"]):
        errors.append("aflnet_arguments overrides controller-owned flags")
    for name, profile in config["llm"]["profiles"].items():
        if not isinstance(profile, dict):
            errors.append("llm profile must be a mapping (" + str(name) + ")")
        elif _contains_secret_field(profile):
            errors.append("LLM credentials must use api_key_env, not literal secrets (" + name + ")")
        elif profile.get("provider", "compatible") not in ("compatible", "anthropic"):
            errors.append("unsupported LLM provider in profile " + name)
        elif not profile.get("endpoint") or not profile.get("model"):
            errors.append("LLM profile requires endpoint and model (" + name + ")")
        elif profile.get("api_key_env") and not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", profile["api_key_env"]):
            errors.append("api_key_env must be an environment-variable name (" + name + ")")
    required_profiles = {"text", "vision", "coding", "reasoning"}
    if not required_profiles.issubset(config["llm"]["profiles"]):
        errors.append("llm.profiles must configure text, vision, coding, and reasoning roles")
    if config["document"].get("ocr_backend") not in ("native", "tesseract", "paddle"):
        errors.append("document.ocr_backend must be native, tesseract, or paddle")
    if config["document"].get("fallback_ocr_backend") not in ("tesseract", "paddle"):
        errors.append("document.fallback_ocr_backend must be tesseract or paddle")
    if errors:
        raise ICPError("\n".join(errors), "configuration")
    if config["target"].get("host") == "localhost":
        config["target"]["host"] = "127.0.0.1"
    return config


def _contains_secret_field(value):
    if isinstance(value, dict):
        return any(str(key).lower() in ("api_key", "token", "secret", "password", "credential", "authorization") or _contains_secret_field(item)
                   for key, item in value.items())
    if isinstance(value, list):
        return any(_contains_secret_field(item) for item in value)
    return False


def load_config(path, offline=False):
    path = Path(path).resolve()
    config = merge(DEFAULTS, load_mapping(path.read_text()))
    for key in ("user_seeds", "output_root", "engine_root"):
        if config["paths"].get(key):
            config["paths"][key] = str((path.parent / config["paths"][key]).resolve())
    if isinstance(config["specifications"], list):
        for spec in config["specifications"]:
            if isinstance(spec, dict) and spec.get("path"):
                spec["path"] = str((path.parent / spec["path"]).resolve())
    for key in ("executable", "source", "cc", "cxx"):
        if config["target"].get(key) and ("/" in config["target"][key] or key in ("source", "executable")):
            config["target"][key] = str((path.parent / config["target"][key]).resolve())
    repository = config["target"].get("repository")
    if repository and not repository.startswith(("https://", "http://", "ssh://", "git@")):
        config["target"]["repository"] = str((path.parent / repository).resolve())
    if config["document"].get("paddle_pipeline_config"):
        config["document"]["paddle_pipeline_config"] = str((path.parent / config["document"]["paddle_pipeline_config"]).resolve())
    for key, value in config["reuse"].items():
        config["reuse"][key] = str((path.parent / value).resolve())
    config["offline"] = bool(offline or config["offline"])
    return validate(config)


def fingerprint(config):
    return digest(config)
