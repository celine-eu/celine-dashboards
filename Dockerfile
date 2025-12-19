FROM apache/superset:5.0.0

USER root

RUN apt-get update && apt-get install -y \
    python3-dev \
    default-libmysqlclient-dev \
    build-essential \
    pkg-config

RUN cd /app && uv pip install .

COPY ./config/superset /app/docker

RUN uv pip install -r /app/docker/requirements-local.txt

RUN chmod +x /app/docker/superset-bootstrap.sh
RUN chmod +x /app/docker/superset-setup.sh

USER superset

ENV PYTHONPATH=/app/pythonpath:/app/docker/pythonpath_dev:${PYTHONPATH}
ENV SUPERSET_LOAD_EXAMPLES=no
ENV CYPRESS_CONFIG=false

CMD ["/app/docker/superset-bootstrap.sh"]