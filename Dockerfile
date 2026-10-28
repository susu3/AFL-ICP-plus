# syntax=docker/dockerfile-upstream:master-labs
# Optional Ubuntu 20.04 comparison image. The normal AFL-ICP+ install/build/run
# workflow does not require Docker.
FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential clang-10 llvm-10 llvm-10-dev make git \
    graphviz libgraphviz-dev libcap-dev libssl-dev ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Download and compile AFLNet
ENV LLVM_CONFIG="llvm-config-10"

ADD --keep-git-dir=true https://github.com/aflnet/aflnet.git /opt/aflnet
WORKDIR /opt/aflnet

RUN make clean all && \
    cd llvm_mode && \
    make

# Set up environment variables for AFLNet
ENV AFLNET="/opt/aflnet"
ENV PATH="${PATH}:${AFLNET}"
ENV AFL_PATH="${AFLNET}"
ENV AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
    AFL_SKIP_CPUFREQ=1
