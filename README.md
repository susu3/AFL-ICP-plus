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

# Prepare Python harness environment
python3 -m venv ../.venv-aflicp
source ../.venv-aflicp/bin/activate
python -m pip install --upgrade pip
python -m pip install --upgrade -e ./harness
# 每次重新登录都先执行：source ../.venv-aflicp/bin/activate

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
### Step 1: LLM Configuration
To enable LLM-assisted features, you need to configure the LLM API settings:
1.  **Set the API Key**:
    Export your API key as an environment variable:
    ```bash
    export LLM_API_KEY="your_api_key_here"
    ```
2.  **Configure the API Endpoint**:
    The default API endpoint is configured for OpenRouter in `chat-llm.c`. If you need to use a different provider, modify the URL in `chat-llm.c` around line 180:
    ```c
    // chat-llm.c:180
    char *url = "https://openrouter.ai/api/v1/chat/completions"; 
    ``` 
### Step 2: Protocol Specification Preparation
Collect the industrial control protocol specification of the target protocol. We have provided several sample industrial protocol specifications in `sample_specs/PDF`: `IEC104.pdf`, `ethernetip.pdf`, `modbus.pdf`, `slmp.pdf`. 

### Step 3: Preprocessing (PDF to Markdown)
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

