#!/usr/bin/env bash
set -e

cd /app && uv pip install --reinstall "/opt/celine-dashboards[superset]"

superset db upgrade
superset init
