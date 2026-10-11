FROM node:20-alpine AS builder
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install
COPY tsconfig.json ./
COPY src/ ./src/
RUN npm run build

FROM node:20-alpine
WORKDIR /app

# Real Gitleaks (used by the VULN-014 check and its verify probe — see
# src/modules/scanner/gitleaks.ts). Static Go binary, runs on Alpine with no extra libs.
ARG GITLEAKS_VERSION=8.21.2
RUN apk add --no-cache curl tar \
  && curl -sL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" -o /tmp/gitleaks.tar.gz \
  && tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks \
  && chmod +x /usr/local/bin/gitleaks \
  && rm /tmp/gitleaks.tar.gz \
  && apk del curl tar

# Real Semgrep (used by the VULN-006 check — src/modules/scanner/semgrep.ts), the second real
# external AppSec tool alongside Gitleaks. PyPI ships musllinux wheels, so this works on Alpine.
RUN apk add --no-cache python3 py3-pip \
  && pip install --no-cache-dir --break-system-packages semgrep

COPY package.json package-lock.json* ./
RUN npm install --omit=dev
COPY --from=builder /app/dist ./dist
COPY gitleaks.toml ./gitleaks.toml
COPY semgrep-rules.yml ./semgrep-rules.yml
EXPOSE 4000
CMD ["node", "dist/index.js"]
