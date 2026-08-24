FROM --platform=linux/amd64 ubuntu:24.04

# Check https://github.com/horsicq/DIE-engine/releases for newer versions.
ARG DIE_VERSION=3.21

RUN apt update -qq \
    && apt install -y --no-install-recommends wget ca-certificates \
    && wget -q https://github.com/horsicq/DIE-engine/releases/download/${DIE_VERSION}/die_${DIE_VERSION}_Ubuntu_24.04_amd64.deb \
    && apt install -y ./die_${DIE_VERSION}_Ubuntu_24.04_amd64.deb \
    && rm die_${DIE_VERSION}_Ubuntu_24.04_amd64.deb \
    && apt remove -y wget \
    && apt autoremove -y \
    && rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["/usr/bin/diec"]
