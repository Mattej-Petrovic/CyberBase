FROM python:3.12-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

COPY requirements.txt ./
RUN python -m pip install --upgrade pip && \
    pip install -r requirements.txt

RUN adduser --disabled-password --gecos "" appuser

COPY --chown=appuser:appuser . .

USER appuser

EXPOSE 5000

ENV GUNICORN_CMD_ARGS="--bind 0.0.0.0:5000 --workers 4"
CMD ["gunicorn", "app:app"]