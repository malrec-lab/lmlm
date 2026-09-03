FROM --platform=linux/amd64 eclipse-temurin:21-jdk

ARG GHIDRA_VERSION=12.1.3
ARG GHIDRA_DATE=20260817

RUN apt-get update -qq \
    && apt-get install -y --no-install-recommends wget unzip \
    && wget -q "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_DATE}.zip" -O /tmp/ghidra.zip \
    && unzip -q /tmp/ghidra.zip -d /opt \
    && mv /opt/ghidra_${GHIDRA_VERSION}_PUBLIC /opt/ghidra \
    && rm /tmp/ghidra.zip \
    && apt-get remove -y wget unzip \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

ENV PATH="/opt/ghidra/support:${PATH}"

WORKDIR /work

ENTRYPOINT ["analyzeHeadless"]
