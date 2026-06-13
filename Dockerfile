# Stage 1: Build
FROM python:3.12-slim AS builder

WORKDIR /build
COPY pyproject.toml README.md LICENSE ./
COPY src/ src/

RUN pip install --no-cache-dir build \
    && python -m build --wheel

# Stage 2: Runtime
FROM python:3.12-slim

LABEL maintainer="PIIGuard"
LABEL description="Secure, compliant offshore data migration toolkit"

WORKDIR /app

COPY --from=builder /build/dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm -rf /tmp/*.whl

# Default data directories
VOLUME ["/data", "/output"]

ENTRYPOINT ["piiguard"]
CMD ["--help"]
