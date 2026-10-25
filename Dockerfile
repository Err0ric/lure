# Lure in a container: a non-root user, a pinned base image, and no secrets
# in the image. Keys come in at run time (--env-file .env); results go to a
# mounted folder. See docs/container.md.
#
# The base image is pinned to the digest of its multi-arch index
# (python:3.12-slim-trixie, Python 3.12.15, linux/amd64 and linux/arm64,
# checked 2026-10-25). Update the two FROM lines together, and the one in
# docker/agent.Dockerfile (the sandbox reference agent).

FROM python:3.12-slim-trixie@sha256:a0f57064cbdcd6285fa45f51237ab0b35ea8ebaed06a1f5973e89e19dfb86704 AS build
WORKDIR /src
COPY pyproject.toml LICENSE ./
COPY lure ./lure
# Wheels for Lure and its dependencies, with the store extra for lure store.
RUN pip wheel --no-cache-dir --wheel-dir /wheels ".[store]"

FROM python:3.12-slim-trixie@sha256:a0f57064cbdcd6285fa45f51237ab0b35ea8ebaed06a1f5973e89e19dfb86704
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1
RUN groupadd --system --gid 10001 lure \
 && useradd --system --uid 10001 --gid lure --home-dir /home/lure --create-home \
      --shell /usr/sbin/nologin lure
COPY --from=build /wheels /wheels
RUN pip install --no-index --find-links /wheels "lure[store]" && rm -rf /wheels

# The attack library, fixtures, example profiles and the shipped policy,
# owned by root and read-only to the lure user. Mount your own profiles.
WORKDIR /work
COPY attacks ./attacks
COPY fixtures ./fixtures
COPY profiles/example-*.yaml ./profiles/
COPY lure.yaml prices.example.yaml ./
RUN mkdir -p /work/results && chown lure:lure /work/results

USER 10001:10001
ENTRYPOINT ["lure"]
CMD ["--help"]
