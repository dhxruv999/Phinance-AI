# Builder: create wheels (needs build deps)
FROM python:3.11-slim AS builder
WORKDIR /wheels
RUN apt-get update && apt-get install -y --no-install-recommends build-essential gcc \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --upgrade pip && pip wheel --no-cache-dir --wheel-dir /wheels -r requirements.txt

# Final: runtime only
FROM python:3.11-slim
ENV PYTHONUNBUFFERED=1
WORKDIR /app

# Install only runtime system libraries needed by wheels (example: libgomp for xgboost)
RUN apt-get update && apt-get install -y --no-install-recommends libgomp1 \
    && rm -rf /var/lib/apt/lists/*

# Install wheels from builder
COPY --from=builder /wheels /wheels
RUN pip install --no-cache-dir /wheels/*

# Copy application code (exclude large datasets via .dockerignore)
COPY . .

EXPOSE 5001
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5001", "app:app"]