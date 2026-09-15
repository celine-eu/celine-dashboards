#!/usr/bin/env bash
set -eo pipefail

case "${1}" in
  worker)
    echo "Starting Celery worker..."
    # setting up only 2 workers by default to contain memory usage in dev environments
    celery --app=superset.tasks.celery_app:app worker -O fair -l INFO --concurrency=${CELERYD_CONCURRENCY:-2}
    ;;
  beat)
    echo "Starting Celery beat..."
    rm -f /tmp/celerybeat.pid
    celery --app=superset.tasks.celery_app:app beat --pidfile /tmp/celerybeat.pid -l INFO -s "${SUPERSET_HOME}"/celerybeat-schedule
    ;;
  app)
    echo "Starting web app (using development server)..."
    flask run -p $SUPERSET_PORT --with-threads --reload --debugger --host=0.0.0.0
    ;;
  app-gunicorn)
    echo "Starting web app..."

    HYPHEN_SYMBOL='-'

    gunicorn \
        --bind "${SUPERSET_BIND_ADDRESS:-0.0.0.0}:${SUPERSET_PORT:-8088}" \
        --access-logfile "${ACCESS_LOG_FILE:-$HYPHEN_SYMBOL}" \
        --error-logfile "${ERROR_LOG_FILE:-$HYPHEN_SYMBOL}" \
        --workers ${SERVER_WORKER_AMOUNT:-1} \
        --worker-class ${SERVER_WORKER_CLASS:-gthread} \
        --threads ${SERVER_THREADS_AMOUNT:-20} \
        --log-level "${GUNICORN_LOGLEVEL:info}" \
        --timeout ${GUNICORN_TIMEOUT:-60} \
        --keep-alive ${GUNICORN_KEEPALIVE:-2} \
        --max-requests ${WORKER_MAX_REQUESTS:-0} \
        --max-requests-jitter ${WORKER_MAX_REQUESTS_JITTER:-0} \
        --limit-request-line ${SERVER_LIMIT_REQUEST_LINE:-0} \
        --limit-request-field_size ${SERVER_LIMIT_REQUEST_FIELD_SIZE:-0} \
        "${FLASK_APP}"
    ;;
  *)
    echo "Unknown Operation!!!"
    ;;
esac
