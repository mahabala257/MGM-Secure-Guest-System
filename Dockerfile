FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install dependencies first for better layer caching.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn

COPY . .

# Run as a non-root user (defence in depth).
RUN useradd --create-home appuser
USER appuser

EXPOSE 8000

# 4 workers behind gunicorn; app:app is the Flask WSGI callable.
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "4", "app:app"]
