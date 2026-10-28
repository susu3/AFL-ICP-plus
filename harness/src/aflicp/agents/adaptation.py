import ast
import json
import re
import shutil
import subprocess
import sys
import platform
from pathlib import Path
from ..common import ICPError, atomic_write, command, digest, file_hash, save_json
from ..llm.client import require_review


def engine_snapshot(source, destination):
    source, destination = Path(source).resolve(), Path(destination)
    if not (source / "afl-fuzz.c").is_file() or not (source / "protocols/protocols.json").is_file():
        raise ICPError("Engine source is not a prepared AFL-ICP checkout")
    if destination.exists():
        return destination
    ignore = shutil.ignore_patterns(".git", "__pycache__", "*.o", "afl-fuzz", "afl-replay", "aflnet-replay",
                                    "afl-gcc", "afl-clang", "afl-showmap", "afl-tmin", "out_dir")
    shutil.copytree(source, destination, ignore=ignore)
    return destination


def _syntax_gate(code, name):
    if not isinstance(code, str):
        raise ICPError("Adapter source must be C text implementing the two protocol functions")
    includes = re.findall(r"(?m)^\s*#\s*include\s+([<\"].*?[>\"])\s*$", code)
    allowed_includes = {"\"../../alloc-inl.h\"", "\"../adapter.h\"", "<stdint.h>", "<string.h>", "<limits.h>", "<stddef.h>"}
    if any(include not in allowed_includes for include in includes) or not {"\"../../alloc-inl.h\"", "\"../adapter.h\""}.issubset(set(includes)):
        raise ICPError("Adapter includes must be limited to the AFL allocation/ABI headers and basic C integer/string headers")
    directives = re.findall(r"(?m)^\s*#.*$", code)
    if len(directives) != len(includes):
        raise ICPError("Adapter may use approved include directives only")
    without_directives = re.sub(r"(?m)^\s*#.*$", "", code)
    lexical = re.sub(r"/\*.*?\*/|//[^\n]*|\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'", " ", without_directives, flags=re.S)
    if "#" in lexical:
        raise ICPError("Adapter preprocessor directives other than approved includes are prohibited")
    prohibited = {"system", "popen", "pclose", "exec", "execve", "execl", "fork", "vfork", "clone", "socket", "connect",
                  "accept", "bind", "listen", "open", "fopen", "freopen", "read", "write", "remove", "unlink", "rename",
                  "dlopen", "dlsym", "getenv", "setenv", "putenv", "malloc", "calloc", "realloc", "free", "exit", "abort",
                  "raise", "signal", "pthread_create", "extern", "asm", "__asm__", "__attribute__"}
    tokens = set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", lexical))
    forbidden = sorted(tokens & prohibited)
    if forbidden:
        raise ICPError("Adapter uses prohibited process, I/O, allocation, or foreign-state operations: " + ", ".join(forbidden))
    required = ("aflicp_%s_requests" % name.lower(), "aflicp_%s_responses" % name.lower())
    if any(symbol not in code for symbol in required):
        raise ICPError("Adapter source does not implement required symbols " + str(required))
    if len(code.encode()) > 500000:
        raise ICPError("Adapter source exceeds configured artifact bound")


def prepare(store, model, bundle):
    protocol = store.config["protocol"]
    existing = store.config.get("reuse", {}).get("adapter_source")
    if existing:
        source = Path(existing).resolve()
        gate_path = store.config.get("reuse", {}).get("adapter_validation")
        if not gate_path:
            raise ICPError("Reused adapter requires reuse.adapter_validation with its prior validation record")
        gate = json.loads(Path(gate_path).read_text())
        if gate.get("status") != "validated" or gate.get("source_sha256") != file_hash(source) or gate.get("knowledge_bundle_id") != bundle.manifest["bundle_id"]:
            raise ICPError("Reused adapter validation record does not match its source and knowledge bundle")
        module = store.root / "adapter" / "generated" / (protocol.lower() + ".c")
        module.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, module)
        save_json(module.parent / (protocol.lower() + ".state.json"), gate["state_encoding"])
        store.register("adapter_source", module, "validated_cache", [bundle.manifest["bundle_id"]])
        return module
    for attempt in range(store.config["repair"]["adapter_max_retries"] + 1):
        try:
            if existing:
                code = Path(existing).read_text()
                encoding = {"source": "reused", "state_id_stability": "campaign"}
            else:
                response = model.call("coding", "adapter", {"protocol": protocol,
                    "knowledge": bundle.select_context("response_parser"), "interface_header": (Path(store.config.get("paths", {}).get("engine_root", Path(__file__).parents[4])) / "protocols/adapter.h").read_text(),
                    "required_symbols": ["aflicp_%s_requests" % protocol.lower(), "aflicp_%s_responses" % protocol.lower()],
                    "diagnostics": store.tasks.get("adapter_diagnostics", [])})
                code, encoding = response.get("source_code"), response.get("state_encoding")
            _syntax_gate(code, protocol)
            review = model.call("coding", "adapter_review", {"source_code": code, "state_encoding": encoding,
                               "knowledge": bundle.select_context("response_parser"), "interface": "region_t request parser and uint32 response state parser"})
            require_review(review)
            source_dir = store.root / "adapter" / "generated"
            source_dir.mkdir(parents=True, exist_ok=True)
            module = source_dir / (protocol.lower() + ".c")
            if module.exists():
                raise ICPError("Generated adapter version already exists; create a revision-specific run")
            atomic_write(module, code)
            save_json(source_dir / (protocol.lower() + ".state.json"), encoding)
            save_json(source_dir / (protocol.lower() + ".review.json"), review)
            store.register("adapter_source", module, "protocol_adaptation_agent", [bundle.manifest["bundle_id"]])
            return module
        except (ICPError, OSError, ValueError, KeyError, TypeError) as exc:
            item = store.diagnostic("adapter", exc, attempt=attempt)
            store.tasks.setdefault("adapter_diagnostics", []).append(item)
            store.save()
    raise ICPError("Adapter generation/review budget exhausted")


def build_engine(store, source, module):
    if not sys.platform.startswith("linux"):
        raise ICPError("AFLNet engine and instrumentation build require a Linux lab host; no macOS build fallback is configured", "platform")
    root = engine_snapshot(source, store.root / "engine")
    protocol = store.config["protocol"]
    registry_path = root / "protocols/protocols.json"
    registry = json.loads(registry_path.read_text())
    registry["protocols"] = [p for p in registry["protocols"] if p["name"] != protocol]
    target_module = root / "protocols/generated" / (protocol.lower() + "_" + digest(module.read_bytes())[:12] + ".c")
    target_module.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(module, target_module)
    symbols = {"requests": "aflicp_%s_requests" % protocol.lower(), "responses": "aflicp_%s_responses" % protocol.lower()}
    registry["protocols"].append({"name": protocol, "variant": "generated", "source": str(target_module.relative_to(root)), **symbols,
                                 "state_encoding": json.loads((module.parent / (protocol.lower() + ".state.json")).read_text())})
    save_json(registry_path, registry)
    command([store.config.get("paths", {}).get("python", "python3"), "tools/registry.py"], cwd=root,
            timeout=30, log=store.root / "adapter" / "registry-generation.log")
    make = shutil.which("make")
    if not make:
        raise ICPError("make is required to build the AFLNet engine", "dependency")
    cc = store.config.get("target", {}).get("engine_cc", "clang")
    command([make, "-j1", "afl-showmap", "afl-fuzz", "afl-replay", "aflnet-replay", "CC=" + cc], cwd=root,
            timeout=store.config.get("target", {}).get("engine_build_timeout_seconds", 1800),
            log=store.root / "adapter" / "engine-build.log")
    target_config = store.config.get("target", {})
    llvm_cc = target_config.get("llvm_cc", "clang")
    llvm_cxx = target_config.get("llvm_cxx", "clang++")
    instrumentation_mode = target_config.get("instrumentation_mode", "trace-pc-guard")
    if instrumentation_mode == "trace-pc-guard":
        # Use compiler-provided SanitizerCoverage callbacks. The old loadable
        # LLVM pass depends on legacy LLVM APIs and is not compatible with the
        # modern LLVM shipped by current Ubuntu releases.
        llvm_args = ["AFL_TRACE_PC=1", "CC=" + llvm_cc, "CXX=" + llvm_cxx]
    elif instrumentation_mode == "legacy-pass":
        llvm_config = target_config.get("llvm_config", "llvm-config")
        llvm_args = ["CC=" + llvm_cc, "CXX=" + llvm_cxx, "LLVM_CONFIG=" + llvm_config]
    else:
        raise ICPError("Unsupported target.instrumentation_mode: " + str(instrumentation_mode), "configuration")
    command([make, "-j1"] + llvm_args + ["all"], cwd=root / "llvm_mode",
            timeout=target_config.get("engine_build_timeout_seconds", 1800),
            log=store.root / "adapter" / "llvm-build.log")
    binaries = {}
    for name in ("afl-fuzz", "afl-replay", "aflnet-replay"):
        path = root / name
        if not path.is_file():
            raise ICPError("Build did not produce " + name)
        binaries[name] = {"path": str(path), "sha256": file_hash(path)}
    profile = {"protocol": protocol, "engine_source": str(source), "engine_snapshot": str(root),
               "engine_revision": command(["git", "rev-parse", "HEAD"], cwd=source, timeout=5).strip(),
               "engine_source_tree_sha256": digest(tree_manifest(source)), "engine_snapshot_tree_sha256": digest(tree_manifest(root)),
               "platform": platform.platform(), "machine": platform.machine(),
               "adapter_module": str(target_module), "adapter_sha256": file_hash(target_module),
               "registry_sha256": file_hash(registry_path), "cc": cc,
               "llvm_cc": llvm_cc, "llvm_cxx": llvm_cxx,
               "instrumentation_mode": instrumentation_mode, "binaries": binaries,
               "adapter_manifest": json.loads((module.parent / (protocol.lower() + ".state.json")).read_text())}
    save_json(store.root / "adapter" / "build-profile.json", profile)
    store.register("engine", root, "adapter_build", [store.manifest["artifacts"]["adapter_source"]["artifact_id"]])
    return profile
