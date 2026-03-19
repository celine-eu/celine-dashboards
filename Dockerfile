FROM apache/superset:6.0.0

USER root

RUN apt-get update && apt-get install -y \
    python3-dev \
    build-essential \
    pkg-config

RUN cd /app && uv pip install .

COPY ./packages /packages
# NOTE: this will install also pg drivers
RUN uv pip install -e /packages/celine-superset

COPY ./config/superset /app/docker

RUN chmod +x /app/docker/superset-bootstrap.sh
RUN chmod +x /app/docker/superset-setup.sh

USER superset

ENV PYTHONPATH=/app/pythonpath:/app/docker/pythonpath_dev:${PYTHONPATH}
ENV SUPERSET_LOAD_EXAMPLES=no
ENV CYPRESS_CONFIG=false

USER root

# Set environment variable for Playwright
ENV PLAYWRIGHT_BROWSERS_PATH=/usr/local/share/playwright-browsers

# Install packages using uv into the virtual environment
RUN . /app/.venv/bin/activate && \
    uv pip install \
    # install psycopg2 for using PostgreSQL metadata store - could be a MySQL package if using that backend:
    psycopg2-binary \
    # add the driver(s) for your data warehouse(s), in this example we're showing for Microsoft SQL Server:
    pymssql \
    # package needed for using single-sign on authentication:
    Authlib \
    # openpyxl to be able to upload Excel files
    openpyxl \
    # Pillow for Alerts & Reports to generate PDFs of dashboards
    Pillow \
    # install Playwright for taking screenshots for Alerts & Reports. This assumes the feature flag PLAYWRIGHT_REPORTS_AND_THUMBNAILS is enabled
    # That feature flag will default to True starting in 6.0.0
    # Playwright works only with Chrome.
    # If you are still using Selenium instead of Playwright, you would instead install here the selenium package and a headless browser & webdriver
    playwright \
    && playwright install-deps \
    && PLAYWRIGHT_BROWSERS_PATH=/usr/local/share/playwright-browsers playwright install chromium

RUN chown -R superset:superset /app/superset_home/.cache || true

# Switch back to the superset user
USER superset

CMD ["/app/docker/superset-bootstrap.sh"]