FROM ubuntu:20.04

# OCI annotations for non-static labels such as creation date are set in the CI pipeline instead.
# The following annotations will generally remain fixed.
LABEL org.opencontainers.image.title="BitCamo"
LABEL org.opencontainers.image.description="Creates adversarial Windows PE files for evading ML detection models"
LABEL org.opencontainers.image.source="https://github.com/juburr/bitcamo"
LABEL org.opencontainers.image.authors="Justin Burr <justin.burr@trojans.dsu.edu>"
LABEL org.opencontainers.image.base.name="docker.io/library/ubuntu:20.04"

RUN apt-get -y update && \
    apt-get install -y software-properties-common && \
    add-apt-repository -y ppa:deadsnakes/ppa && \
    apt-get -y update && \
    apt-get install -y \
        python3.8 \
        python3-distutils \
        python3-pip \
        python3-apt \
        python3.8-venv \
        python3.8-dev \
        build-essential \
        libpq-dev \
        libssl-dev \
        libffi-dev && \
    rm -rf /var/lib/apt/lists/*

RUN useradd -ms /bin/bash nonroot
USER nonroot
WORKDIR /home/nonroot

COPY . .

RUN python3 -m venv .venv && \
    ./ubuntu-activate.sh && \
    echo "./ubuntu-activate.sh" >> ~/.bashrc && \
    export PATH=$PATH:/home/nonroot && \
    echo "export PATH=$PATH:/home/nonroot" >> ~/.bashrc && \
    pip3 install --upgrade pip setuptools wheel && \
    pip3 install -r requirements.txt
