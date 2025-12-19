#!/usr/bin/env bash
set -e

superset db upgrade
superset init