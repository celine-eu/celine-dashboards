#!/usr/bin/env bash
set -e

cd /app && uv pip install --reinstall /packages/celine-superset

superset db upgrade
superset init