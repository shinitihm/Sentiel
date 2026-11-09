# Imagem do Sentiel gerada pela pipeline CI/CD (.github/workflows/ci.yml).
# Instala exatamente o wheel que passou pela CI (pasta dist/, artefato do job "build").
#
#   docker run --rm ghcr.io/shinitihm/sentiel:latest                 # demo sem IA
#   docker run --rm ghcr.io/shinitihm/sentiel:latest doctor --no-ai
#   docker run --rm -v "$PWD:/data" -v /var/log:/host/log:ro ghcr.io/shinitihm/sentiel:latest scan --no-ai
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    COLUMNS=120

COPY dist/*.whl /tmp/dist/
RUN pip install /tmp/dist/*.whl && rm -rf /tmp/dist \
    && useradd --create-home --uid 10001 sentiel \
    && mkdir /data && chown sentiel:sentiel /data

USER sentiel
WORKDIR /data
VOLUME ["/data"]

ENTRYPOINT ["sentiel"]
CMD ["demo", "--no-ai"]
