FROM python:3.13-slim

WORKDIR /app

# Install the package (no dev deps, no cache)
COPY pyproject.toml README.md ./
COPY src/ ./src/
RUN pip install --no-cache-dir .

# Scan target is mounted at runtime
VOLUME ["/scan"]

ENTRYPOINT ["skill-scanner"]
CMD ["--help"]
