FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .
COPY model_info.json .
COPY predict_phishing.py .

COPY templates/ ./templates/
COPY static/ ./static/

EXPOSE 5001

CMD ["gunicorn", "app:app", "--bind", "0.0.0.0:5001", "--workers", "1", "--timeout", "180"]
