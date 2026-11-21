# Example digest: replace with the current python:3.12-slim digest from
# `docker buildx imagetools inspect python:3.12-slim` before building for real.
FROM python:3.12-slim@sha256:0000000000000000000000000000000000000000000000000000000000000000
WORKDIR /app
COPY app/ /app/
RUN pip install --no-cache-dir pytest==8.3.5
RUN useradd --create-home agent
USER agent
