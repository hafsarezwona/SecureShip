FROM node:22.16.0-bookworm-slim

ARG SEMGREP_VERSION=1.163.0
ARG TRIVY_VERSION=0.76.0-16-g1f93b251d

ENV NODE_ENV=production \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PATH="/opt/semgrep/bin:${PATH}" \
    SCAN_TEMP_DIRECTORY=/var/lib/secureship/tmp \
    TRIVY_CACHE_DIR=/var/lib/trivy

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl python3 python3-venv tar gzip \
    && rm -rf /var/lib/apt/lists/* \
    && python3 -m venv /opt/semgrep \
    && /opt/semgrep/bin/pip install "semgrep==${SEMGREP_VERSION}" \
    && curl -fsSLO "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" \
    && curl -fsSLO "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_checksums.txt" \
    && grep " trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz$" "trivy_${TRIVY_VERSION}_checksums.txt" | sha256sum -c - \
    && tar -xzf "trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" -C /usr/local/bin trivy \
    && rm "trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" "trivy_${TRIVY_VERSION}_checksums.txt"

WORKDIR /app
COPY scanner-worker/package*.json ./
COPY shared/archive /shared/archive
RUN npm install --omit=dev
COPY scanner-worker/src ./src
COPY scanner-worker/rules ./rules
RUN mkdir -p /var/lib/secureship/tmp /var/lib/trivy \
    && chown -R node:node /var/lib/secureship /var/lib/trivy /app

USER node
EXPOSE 4100
CMD ["node", "src/server.js"]
