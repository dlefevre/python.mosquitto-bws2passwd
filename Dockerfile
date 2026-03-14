# Stage 1 – build the wheel
FROM python:3.14-slim AS builder

RUN pip install --no-cache-dir uv

WORKDIR /build
COPY . .
RUN uv build --wheel --out-dir dist/

# Stage 2 – minimal runtime image
FROM python:3.14-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends bash \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/dist/*.whl /tmp/

RUN pip install --no-cache-dir /tmp/*.whl \
    && rm /tmp/*.whl

CMD ["bash"]
