# Digest of python:3.12-slim as pulled on 2026-11-22
# (`docker image inspect python:3.12-slim`); refresh with
# `docker buildx imagetools inspect python:3.12-slim` when updating.
FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b
WORKDIR /app
COPY app/ /app/
RUN pip install --no-cache-dir pytest==8.3.5
RUN useradd --create-home agent
USER agent
