# AFL-ICP deterministic harness

This directory contains the offline preparation/orchestration package. The AFLNet C engine remains the runtime fuzzer; no LLM call is made from the fuzzing process. A local campaign is intentionally an explicit operator action (`aflicp run`). The controller accepts only loopback/private IPv4 target addresses and does not scan or discover targets.

## Host and package setup

The primary deployment baseline is x86-64 Ubuntu 20.04, matching the AFLNet-derived engine. Install the C/LLVM toolchain, AFLNet build dependencies, `bubblewrap`, Python 3.8, and Tesseract when OCR fallback is needed. Docker is not required for the default workflow: the Modbus target builds locally with `afl-clang-fast`, and generated seed code runs in a no-network bubblewrap namespace. Run the harness as an ordinary unprivileged account; local seed isolation deliberately refuses root execution. This source workspace is macOS, so Linux engine/sandbox/target/campaign acceptance must be performed on the Linux host. For PDF text extraction, PyMuPDF is installed with the package; PP-StructureV3 is optional and needs local model files when used offline.

Install into an isolated virtual environment with `python3 -m pip install -e .`. Optional table/layout OCR dependencies are installed with `python3 -m pip install -e '.[layout]'`. Build the C engine and LLVM instrumentation from the repository root:

```sh
make -j"$(nproc)" all
make -C llvm_mode LLVM_CONFIG=llvm-config-10 CC=clang-10 CXX=clang++-10
```

Docker images are only needed for later experiments that intentionally compare containerized preparation. They are not built, pulled, or required by normal preparation/fuzzing. The optional Dockerfiles target Ubuntu 20.04 and can be selected with `target.build_backend: docker` / `seeds.sandbox.backend: docker`.

The example config is deliberately incomplete. Replace the PDF and C0 paths, target revision (the resolved commit is recorded), endpoint/model names, and environment-variable names. Never put API credentials directly in YAML. If opting into Docker comparisons, pin image digests and record image IDs; the harness never builds or pulls them automatically.

The first target recipe supports a pinned libmodbus test server. An already-built local executable is also supported through `target.executable` plus an argv list. Unknown source repositories do not execute README-provided scripts; they require a reviewed recipe implementation or prebuilt executable. `target prepare` copies a known recipe source into the run artifact tree and builds it locally by default; setting `target.build_backend: docker` opts into a prebuilt Docker build image. For campaigns and replay, AFLNet launches the configured executable as a local child process. Only configure a target you control, and for less-trusted test binaries run the whole harness inside a dedicated disposable Linux VM/container with no production or public-network route.

## Deterministic workflow

`validate-config` only checks local configuration and paths. `prepare` creates an immutable run directory and executes a deterministic dependency graph: render/read all PDF pages, OCR fallback and visual reconstruction, segment/relevance labeling, six-file client/server knowledge synthesis and review, adapter synthesis/review/build, seed-generator synthesis/review/local sandbox, target profile, representative C0 dry run, and launch barrier. LLM and OCR provider outputs, page images, source hashes, model usage and all stage diagnostics are retained with the run.

```sh
aflicp validate-config --config config.yaml
aflicp prepare --config config.yaml
aflicp status --config config.yaml --run-id RUN_ID
aflicp run --config config.yaml --run-id RUN_ID
aflicp analyze --config config.yaml --run-id RUN_ID
aflicp export --config config.yaml --run-id RUN_ID --output /safe/location/RUN_ID.tar.gz
```

Use `aflicp resume` only for a stopped/incomplete campaign. It reuses the exact fuzzer, adapter, output directory, corpus and evidence counter; it refuses changed binaries. `aflicp experiment` creates configured independent repetitions and refuses to start campaigns if adapter, fuzzer, original C0, or prepared corpus hashes differ across repetitions. Run time, repetitions, LLM retry budgets, evidence sample period and replay limits are configuration values.

The individual `specification prepare`, `adapter prepare`, `seeds prepare`, and `target prepare` commands require an existing `--run-id` and satisfy that stage's artifact dependencies. They are for controlled continuation/diagnosis; `prepare` is the normal complete workflow.

## Artifacts and safety properties

Each run contains `run_manifest.json`, `task_state.json`, `dag.json`, `diagnostics.jsonl`, the full PDF snapshots and screenshots, `knowledge/` (client/server request and response JSON, Mermaid, and Markdown), the adapter source/state encoding/build profile, the untouched C0 snapshot, generated candidate metadata, a flat `corpus/input/` of raw `.bin` files, target build/profile/validation records, `campaign.json`, AFLNet's original crash/hang output, and per-campaign `interactions/campaigns/<campaign-id>/` evidence packs/indexes.

Knowledge is source-grounded and physically separated by protocol endpoint role in all three representations. Generated seed Python runs by default under bubblewrap with a read-only root, hidden home directories, an unshared network namespace, reduced UID, and CPU, address-space, file-size, descriptor, process, candidate and wall-time limits. Docker is an optional sandbox backend for later comparison experiments. The original C0 files are copied and hashed; they are not passed through generated-code execution. Generated empty/failed seeds and exact SHA-256 duplicates are removed; no `afl-tmin`/`afl-cmin` minimization is run. Final AFLNet input directories contain only flat raw binary files.

At runtime the C hooks capture normal ordinary executions only (not calibration/trim/import): request bytes and send result, receive windows, parser state IDs, coverage bitmap when enabled, timestamps, and new-coverage or every-Nth-execution trigger. A separate local Unix-socket writer validates and fsyncs bounded frames before indexing them. Full queues block the fuzzer; writer failure/stall marks evidence incomplete. Crash/hang testcases remain in AFLNet's own directories and are referenced in the analysis report rather than duplicated.

`analyze` reads only complete evidence, verifies pack hashes, replays selected exact exchanges against the configured local target, asks the reasoning model for source-grounded candidates, and uses the same configured model for independent review. Each invocation writes a new `analysis/revisions/vNNN/` directory, so partial output is preserved and analysis can be repeated without overwriting evidence. A result is labeled confirmed only if the reviewer confirms it, citations are exact substrings of preserved source text, and at least one replay reproduces the recorded receive-window bytes/status. A protocol deviation is not automatically a vulnerability. Review output remains a research finding, not a substitute for human triage.

## Provider configuration and offline mode

Provider profiles use OpenAI-compatible chat-completions or Anthropic messages APIs and refer to credentials only by environment-variable name. Retries/timeouts are operator-controlled in `llm.api`. Successful structured responses are cached by model profile, prompt, input and page-image hashes; cache hits are reported at zero newly charged cost. Request logs retain hashes/size rather than duplicating raw PDF screenshots. Offline mode forbids remote LLM/OCR/model and repository downloads, so all required PDF, OCR model, LLM response cache, target source, build toolchain, and sandbox dependencies must already exist locally.

## Current scope and known limits

The first closed loop is `MODBUS` over TCP with a known libmodbus test-server recipe. Legacy ICS protocol adapters are retained in the registry, while generated protocol adapters are built as regular C modules selected by protocol name; adding another ICS protocol requires a reviewed protocol-specific parser/state encoding and a target recipe where needed. No protocol semantic behavior is invented when the PDF leaves it unspecified; unresolved source questions stop publication or confirmation.

The evidence recorder and adapter registry are integrated into the engine clone. Ubuntu 20.04 compilation, a real PDF/model response, bubblewrap sandbox execution, local libmodbus build, dry-run against a locally configured target, campaign, and replay confirmation require the operator's authorized Linux lab environment and have not been run from this macOS implementation workspace.
