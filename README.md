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
## 4. Tutorial - Fuzzing libplctag library
### Step 1: Prepare Python harness environment
```bash
python3 -m venv /home/aflicp/.venv-aflicp
source /home/aflicp/.venv-aflicp/bin/activate
python -m pip install --upgrade pip
python -m pip install --upgrade -e ./harness
# 若虚拟环境已经存在，跳过创建命令，只需启用它
```

### Step 2: Protocol specification and seeds preparation
Collect the industrial control protocol specification and some seeds of the target protocol. We have provided several sample industrial protocol specifications in `AFL-ICP-plus/sample_specs/PDF`: `IEC104.pdf`, `ethernetip.pdf`, `modbus.pdf`, `slmp.pdf`. We also have provided several sample protocol seeds in `/AFL-ICP-plus/tutorials/XX/in-XX/`.


### Step 3: 创建并编辑harness配置
```bash
cp harness/config.example.yaml harness/config.yaml
vim harness/config.yaml
```
```YAML
#将对应配置改为正确路径和待测目标协议设置（以modbus为例）
protocol: MODBUS # Must match a protocol adapter registered in this AFL-ICP+ build.
offline: false # Set true only when every model/OCR/target source dependency is already cached locally.

specifications:
  - id: modbus-vendor-spec
    path: ../specifications/modbus.pdf # REQUIRED: replace with an existing local PDF; add more list items for more PDFs.
    # Each id must be unique. Paths are resolved relative to this config file.

paths:
  engine_root: .. # Normally the repository root; change only if using another AFLNet/AFL-ICP+ checkout.
  user_seeds: ../seeds/C0 # REQUIRED: original user-provided C0, not the generated corpus; must contain nonempty files.
  output_root: ../aflicp-output # REQUIRED: writable location for runs, caches, and reports; paths are config-relative.

llm:
  ...
  profiles:
    text:
      provider: compatible # Choose compatible (OpenAI Chat Completions) or anthropic to match the provider API.
      endpoint: https://api.deepseek.com/chat/completions # Full request URL, not only the provider base URL.
      model: deepseek-v4-pro # REQUIRED: confirm model ID is available to your account/provider.
      api_key_env: DEEPSEEK_API_KEY # REQUIRED: set this environment variable in the shell; never put the key here.
      ...
    vision:
      provider: compatible
      endpoint: https://api.deepseek.com/chat/completions
      model: deepseek-flash # REQUIRED: must accept image input; current DeepSeek V4-Pro is text-only.
      api_key_env: DEEPSEEK_API_KEY
      ...
    coding:
      provider: compatible
      endpoint: https://api.deepseek.com/chat/completions
      model: deepseek-v4-pro # Adapter/seed generator and their reviewers share this profile/model.
      api_key_env: DEEPSEEK_API_KEY
      ...
    reasoning:
      provider: compatible
      endpoint: https://api.deepseek.com/chat/completions
      model: deepseek-v4-pro # Finding proposal and review share this profile/model.
      api_key_env: DEEPSEEK_API_KEY
      ...
          
target:
  id: libmodbus-local-simulator
  recipe: libmodbus # First supported build recipe; other targets need a reviewed recipe or local executable.
  build_backend: local               # Default: build with the host Ubuntu toolchain; Docker is optional.
  engine_cc: clang # Must match the compiler used for this engine build.
  llvm_cc: clang
  llvm_cxx: clang++
  instrumentation_mode: trace-pc-guard # Modern LLVM; avoids the legacy LLVM pass plugin.
  repository: https://github.com/stephane/libmodbus
  ref: REPLACE_WITH_COMMIT_SHA # REQUIRED: pin a reviewed commit for reproducibility; do not use a moving branch.
  host: 127.0.0.1 # REQUIRED: only the authorized local/private lab target; never a public/production endpoint.
  port: 1502 # Confirm this port is unused and matches the target launch configuration.
  transport: tcp
  build_timeout_seconds: 1800
  build_memory_mb: 4096
  build_cpus: 2
...
```

### Step 4: 设置tmux (根据需要选择)
由于....于是设置tmux
```bash
cd /home/aflicp/AFL-ICP-plus
tmux new -s aflicp-prepare

#主动从tmux会话中退出，回到普通命令行
#按Ctrl+B, 再按D

#重新登录服务器后
tmux ls
tmux attach -t aflicp-prepare #如果看到aflicp-prepare
tmux attach -d -t aflicp-prepare #如果提示aflicp-prepare会话仍被占用，用该命令接管
```

### Step 5: 设置LLM API KEY并检查配置
```bash
source /home/aflicp/.venv-aflicp/bin/activate #启用虚拟环境
read -rsp 'LLM API key: ' AFLICP_API_KEY
export AFLICP_API_KEY
test -n "$AFLICP_API_KEY" && echo "API key 已设置" #注意环境变量名要和config中引用的一致
# echo $AFLICP_API_KEY #该命令会显示密钥
```

### Step 6: 执行准备流程
```bash
cd /home/aflicp/AFL-ICP-plus
source /home/aflicp/.venv-aflicp/bin/activate

aflicp validate-config --config harness/config.yaml
aflicp prepare --config harness/config.yaml
```
prepare 会按 PDF 页处理文档并调用 LLM，也会构建 adapter、生成和验证种子、获取并编译配置的 libmodbus 目标，最后使用原始种子对 127.0.0.1:1502 做 dry-run。**这是多次 API 调用，可能产生明显高于单次测试的 token 费用。**准备成功后记下输出中的 run_id。








Use the provided scripts to convert the PDF specification into Markdown format and filter the content for LLM processing.
1.  **PDF to Markdown Conversion**:
    Configure API keys (Mistral OCR, LLM) and file paths in `parse_pdf_conversion.py`, then run the script:
    `python3 parse_pdf_conversion.py`. This will generate an initial Markdown file from the PDF.
2.  **Content Filtering**:
    Configure API keys (LLM) and run the filtering script to clean and refine the Markdown content:
    `python3 parse_filter.py`. Ensure the output Markdown file is saved in a directory accessible for the subsequent steps (e.g., `sample_specs/Markdown`).

### Step 4: Compile Target (libplctag)
Clone and compile the target library with AFL-ICP instrumentation and ASAN support.
```bash
# Clone specific version of libplctag
git clone https://github.com/libplctag/libplctag.git
cd libplctag
git checkout v2.6.12
# Build with AFL-ICP instrumentation and ASAN
mkdir -p build && cd build
# AFL_USE_ASAN=1 enables AddressSanitizer in afl-clang-fast
AFL_USE_ASAN=1 cmake .. \
    -DCMAKE_C_COMPILER=afl-clang-fast \
    -DCMAKE_CXX_COMPILER=afl-clang-fast++ \
    -DCMAKE_C_FLAGS="-g -fno-omit-frame-pointer" \
    -DCMAKE_CXX_FLAGS="-g -fno-omit-frame-pointer" \
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DBUILD_TESTS=1 
# Compile
AFL_USE_ASAN=1 make -j$(nproc) plctag_static plctag_dyn modbus_server
```

*(Optional)* **Traffic Collection**:
You can also collect network traffic (PCAP) for the target protocol to help with seed generation. Please refer to the [AFLNet tutorial](https://github.com/aflnet/aflnet?tab=readme-ov-file#tutorial---fuzzing-live555-media-server) for instructions on how to capture and prepare traffic samples. 

### Step 5: Start Fuzzing
AFL-ICP will automatically parse the protocol documentation, generate initial seeds (saved in the input directory), and start fuzzing.
```bash
afl-fuzz -d -i <inputs> -o <outputs> -N tcp://127.0.0.1/5502 -P MODBUS -r /AFL-ICP/sample_specs/Markdown/modbus.md -D 10000 -Y 2 -Z 1 -q 3 -s 3 -E -K -R ./modbus_server --listen 127.0.0.1:5502
```
*Note: The parsed protocol documentation and generated seeds will be stored in the specified input/output directories.* 

### Step 6: Vulnerability Analysis

For the memory safety vulnerabilities, refer to the [AFLNet tutorial](https://github.com/aflnet/aflnet) for details on how to replay and analyze these crashes to identify memory safety issues.

For the semantic and logic vulnerabilities, use the included specification consistency analysis tool to detect semantic deviations and logic bugs.
1.  The Makefile for compiling the tool is located in the `functional_test` directory:
    ```bash
    cd functional_test
    make -f Makefile.rfc-consistency
    ```
2.  Run the analysis using the interactions captured during fuzzing:
    ```bash
    # Usage: ./rfc-consistency <interactions_dir> <results_dir> <grammar_dir> <spec_markdown> <protocol>
    # Example for MODBUS (assuming interactions are stored in ../out/interactions):
    ./rfc-consistency ../out/interactions ./results ../modbus_output ../sample_specs/Markdown/modbus.md MODBUS
    ```

