# Lure's reference agent for the sandbox (lure sandbox run). Built from this
# repository only: Python's standard library, no third-party agent code.
# See docs/container.md.
#
# The base image is the same pinned digest as ../Dockerfile; update all
# three FROM lines together.
#
#   docker build -f docker/agent.Dockerfile -t lure-ref-agent:<version> .

FROM python:3.12-slim-trixie@sha256:a0f57064cbdcd6285fa45f51237ab0b35ea8ebaed06a1f5973e89e19dfb86704
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
# No package manager the agent could use: pip goes, and curl, wget, git and
# npm were never in the base image. Decoys of the same names take their
# place, first on PATH, and only log how they were called.
RUN python -m pip uninstall -y -q pip \
 && rm -f /usr/local/bin/pip /usr/local/bin/pip3 /usr/local/bin/pip3.12 \
 && groupadd --system --gid 10001 agent \
 && useradd --system --uid 10001 --gid agent --home-dir /workspace --no-create-home \
      --shell /usr/sbin/nologin agent
COPY lure/sandbox/refagent/agent.py lure/sandbox/refagent/decoy.py /opt/lure/
RUN chmod 0755 /opt/lure/agent.py /opt/lure/decoy.py \
 && mkdir /opt/lure/decoys \
 && for c in npm npx pip pip3 curl wget git; do ln -s ../decoy.py /opt/lure/decoys/$c; done
ENV PATH=/opt/lure/decoys:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
USER 10001:10001
WORKDIR /workspace
ENTRYPOINT ["/usr/local/bin/python3", "/opt/lure/agent.py"]
