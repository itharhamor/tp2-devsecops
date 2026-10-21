FROM python:3.12-slim

# Utilisateur non-root (bonne pratique de sécurité)
RUN useradd --create-home appuser
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .
USER appuser

EXPOSE 5000
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "app:app"]
