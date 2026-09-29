FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

RUN useradd --create-home --uid 10001 app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY --chown=app:app . .

# Build-time only key so collectstatic can import settings; the real key comes from the environment.
RUN DJANGO_SECRET_KEY=collectstatic-build-only python manage.py collectstatic --noinput

USER app
EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=3s --start-period=20s --retries=5 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health/', timeout=2)"

CMD ["sh", "-c", "python manage.py migrate --noinput && exec gunicorn vault_project.wsgi:application --bind 0.0.0.0:8000 --workers 3 --no-control-socket --access-logfile - --forwarded-allow-ips='*'"]
