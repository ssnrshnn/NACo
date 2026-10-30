# syntax=docker/dockerfile:1.7
# NACo application image: unprivileged, no compilers, hash-locked dependencies.
ARG PYTHON_IMAGE=python:3.12-slim-bookworm@sha256:e697c81897302a4c4333bade000d98038fbb21eb064f8ee1fd42d02ebcd9d337

FROM ${PYTHON_IMAGE} AS build
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1
WORKDIR /src
COPY requirements.lock ./
RUN pip install --require-hashes --only-binary=:all: --prefix=/install -r requirements.lock
COPY pyproject.toml README.md LICENSE ./
COPY naco ./naco
RUN pip install --no-deps --prefix=/install .

FROM ${PYTHON_IMAGE}
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 NACO_CONFIG=/etc/naco/config.yaml
# age: encrypted backups (nacoctl backup --age-recipient).
RUN apt-get update \
 && apt-get install -y --no-install-recommends age \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system --gid 10001 naco \
 && useradd --system --uid 10001 --gid naco --no-create-home --shell /usr/sbin/nologin naco \
 && install -d -o naco -g naco -m 0750 /var/lib/naco /backups \
 && install -d -m 0755 /etc/naco \
 && touch /etc/naco/config.yaml
COPY --from=build /install /usr/local
USER naco
WORKDIR /var/lib/naco
EXPOSE 8080/tcp 8081/tcp 4949/tcp
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/api/v1/health/ready', timeout=3)"]
CMD ["naco"]
