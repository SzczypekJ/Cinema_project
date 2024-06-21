FROM python:3.9-slim

WORKDIR /distrubuted-booking-app/admin_service

COPY . /distrubuted-booking-app/admin_service

# Instalacja narzędzi build-essential, gcc, i sqlite3
RUN apt-get update && apt-get install -y \
    gcc \
    build-essential \
    sqlite3 \
    && rm -rf /var/lib/apt/lists/*

# Instalacja psycopg2-binary bezpośrednio
RUN pip install psycopg2-binary

# Instalacja zależności z requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 8000

ENV FLASK_APP=admin.py

CMD ["flask", "run", "--host=0.0.0.0", "--port=8000"]
