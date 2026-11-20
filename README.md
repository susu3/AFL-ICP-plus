# AFL-ICP+

## 1. Introduction
**AFL-ICP+** is an autonomous.....

### Core Features
* **📄 Automated Specification Formalization:**
Transforms complex, multimodal PDF specifications (including text, tables, and architectural diagrams) into rigorous machine-readable grammars.
* **🌱 Specification-Guided Seed Synthesis:**
Overcomes the "cold start" problem by generating high-quality, diverse, and structurally valid initial seed corpora directly from the formalized grammar, allowing the fuzzer to penetrate deep protocol states.
* **🧠 Semantic Vulnerability Reasoning:**
Features an LLM-powered differential checker that serves as a specification-conformance oracle. It cross-references execution traces against formal requirements to detect subtle semantic deviations and logic bugs that do not trigger standard crashes. 
### Supported Protocols
AFL-ICP+ currently supports the following industrial protocols:
*   **Modbus/TCP** (`MODBUS`)

## 2. Installation
### Prerequisites
```bash
# Install dependencies (Tested on Ubuntu 26.04)
sudo apt-get update
sudo apt-get install -y build-essential clang make graphviz libgraphviz-dev libcap-dev autoconf automake libtool pkg-config git python3 python3-venv python3-pip tesseract-ocr bubblewrap libclang-rt-21-dev

#使用普通用户执行
adduser aflicp
su - aflicp
```
### Build AFL-ICP+
```bash
# Clone the repository (if you haven't already)
git clone git@github.com:susu3/AFL-ICP-plus.git
cd /home/aflicp/AFL-ICP-plus 

# Compile the source
make -C llvm_mode clean
make AFL_NO_X86=1 CC=clang -j"$(nproc)" all
make -C llvm_mode AFL_TRACE_PC=1 CC=clang CXX=clang++

# edit the harness/config.yaml?
engine_cc: clang
llvm_cc: clang
llvm_cxx: clang++
instrumentation_mode: trace-pc-guard

# Setup environment variables?

```

## 3. Usage
AFL-ICP adds the following options to AFLNet. Run afl-fuzz --help to see all options. 
### Options
*   **-P protocol**: application protocol to be tested. (Available: `MQTT`, `MODBUS`, `IEC104`, `ETHERNETIP`, `BACNETIP`, `DNP3`, `OPCUACP`, `SLMPA`, `SLMPB`).
*   **-r file**: protocol specification file (text format)
*   **-Y mode**: (Optional) protocol consistency analysis mode (0: disable collection; 1: only new coverage; 2: new coverage + no duplicate random sampling)
*   **-Z rate**: (Optional) protocol consistency analysis sampling rate (‰)

### General Command
```bash
afl-fuzz -d -i <input_dir> -o <output_dir> -N <net_info> -P <protocol> -r <spec_file> -Y <mode> -Z <rate> [options] -- <target_binary> [target_args]
```
## 4. Tutorial - Fuzzing Modbus with libmodbus

This tutorial uses the Modbus/TCP protocol adapter, the sample Modbus specification and user-provided seed corpus included in this repository, and the harness's supported `libmodbus` target recipe. The target is built locally and exercised on the loopback interface (`127.0.0.1`); this workflow does not fuzz a public Modbus service.

Run the commands as the unprivileged account that owns the checkout. The examples assume the repository is `/home/aflicp/AFL-ICP-plus` and the virtual environment is `/home/aflicp/.venv-aflicp`. Adjust those paths if your installation differs. Complete the [Installation](#2-installation) steps and build AFL-ICP+ before starting this tutorial.

### Step 1: Prepare the Python harness environment

From the repository root, create the virtual environment once, activate it, and install the harness:

```bash
cd /home/aflicp/AFL-ICP-plus
python3 -m venv /home/aflicp/.venv-aflicp
source /home/aflicp/.venv-aflicp/bin/activate
python -m pip install --upgrade pip
python -m pip install --upgrade -e ./harness
```

If the virtual environment already exists, skip `python3 -m venv` and activate it with the `source` command. Activate the environment again in every new shell or tmux session before using `aflicp`.

### Step 2: Locate the specification and initial seeds

The repository includes the Modbus specification at `sample_specs/PDF/modbus.pdf` and user-provided initial seeds at `tutorials/libmodbus/in-modbus`. The initial seed directory is the experimental C0 corpus supplied by the user; the harness preserves it separately from the generated corpus.

Check that both paths exist and that the seed directory contains nonempty files:

```bash
ls -l sample_specs/PDF/modbus.pdf
find tutorials/libmodbus/in-modbus -type f -size +0c
```

### Step 3: Create and edit the harness configuration

Copy the example configuration and open it:

```bash
cp harness/config.example.yaml harness/config.yaml
vim harness/config.yaml
```

Keep the configuration fields from `config.example.yaml` and update their values. Paths below are relative to `harness/config.yaml`:

```yaml
protocol: MODBUS

specifications:
  - id: modbus-vendor-spec
    path: ../sample_specs/PDF/modbus.pdf

paths:
  engine_root: ..
  user_seeds: ../tutorials/libmodbus/in-modbus
  output_root: ../aflicp-output

target:
  id: libmodbus-local-simulator
  recipe: libmodbus
  build_backend: local
  repository: https://github.com/stephane/libmodbus
  ref: REPLACE_WITH_A_PINNED_COMMIT_SHA
  host: 127.0.0.1
  port: 1502
  transport: tcp
```

Replace `target.ref` with the full immutable commit SHA you intend to test. Do not leave the placeholder or use a moving branch. Preserve the compiler and instrumentation settings from the example configuration; they must match the AFL-ICP+ engine you built.

Also review all four `llm.profiles` entries in the configuration. Set the provider, endpoint, model, JSON response options, and `api_key_env` to values supported by your provider. The `vision` profile must accept image inputs. The `api_key_env` value must exactly match the environment variable you export in Step 5. Do not put an API key directly in the YAML file.

### Step 4: (Optional) Start a tmux session for long-running work

A preparation run makes many model calls and can take a long time. Start tmux before setting the API key and launching `prepare`, so the environment variable and process stay in the same session if your SSH connection drops:

```bash
cd /home/aflicp/AFL-ICP-plus
tmux new -s aflicp-prepare
```

Run the remaining commands inside tmux. To detach while leaving the process running, press **Ctrl+B**, release the keys, then press **D**. After reconnecting, use `tmux attach -t aflicp-prepare` to return to the session. If tmux is unavailable, install it using your system administrator or root account; tmux is optional.

### Step 5: Set the LLM API key and validate the configuration

The example configuration uses `DEEPSEEK_API_KEY`. If you changed `api_key_env`, use that exact variable name instead. The following prompt reads the key without echoing it:

```bash
source /home/aflicp/.venv-aflicp/bin/activate
read -r -s -p 'DeepSeek API key: ' DEEPSEEK_API_KEY
printf '\n'
export DEEPSEEK_API_KEY
test -n "$DEEPSEEK_API_KEY" && echo 'API key is set'
```

Validate the file and input paths before running the preparation workflow:

```bash
aflicp validate-config --config harness/config.yaml
```

`validate-config` checks local configuration and input paths. It does not contact the LLM, clone/build the target, or start fuzzing.

### Step 6: Prepare protocol knowledge, adapter, seeds, and target

Run:

```bash
aflicp prepare --config harness/config.yaml
```

Preparation processes every PDF page, detects sections, labels relevant segments, extracts and reviews protocol knowledge, generates and builds the adapter, generates and validates seeds, checks out and compiles the configured `libmodbus` target, and runs a representative dry-run against `127.0.0.1:1502`. It makes multiple LLM calls and can incur substantial token usage. The CLI prints timestamped stage and progress messages while it runs. The generated AFLNet input corpus is stored under the run's `corpus/input/`; the original C0 snapshot is kept under `corpus/user/`.

When preparation completes, record the `run_id` printed in the final JSON output. Check the run status with:

```bash
RUN_ID='PASTE_THE_RUN_ID_HERE'
aflicp status --config harness/config.yaml --run-id "$RUN_ID"
```

The run must reach the prepared/ready state and representative target validation must pass before fuzzing.

### Step 7: Start the fuzzing campaign

Start the campaign against the locally built target using the prepared run:

```bash
aflicp run --config harness/config.yaml --run-id "$RUN_ID"
```

Campaign duration and AFLNet options are controlled by the `campaign` section of `harness/config.yaml`. The CLI prints periodic campaign progress. AFLNet standard output and error are saved under the run's `fuzz/` directory. Check progress or the final state with:

```bash
aflicp status --config harness/config.yaml --run-id "$RUN_ID"
```

### Step 8: Review results

After a campaign completes, run the evidence analysis and export the run artifacts if needed:

```bash
aflicp analyze --config harness/config.yaml --run-id "$RUN_ID"
aflicp export --config harness/config.yaml --run-id "$RUN_ID" --output "../${RUN_ID}.tar.gz"
```

The run directory contains the resolved configuration, source and knowledge artifacts, generated adapter and seed corpus, target build logs, campaign logs, and analysis results. Keep this directory with the recorded run ID to reproduce or inspect the experiment.
