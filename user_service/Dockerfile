FROM python:3.9-slim

WORKDIR /distrubuted-booking-app/user_service

COPY . /distrubuted-booking-app/user_service

# Instalacja narzędzi build-essential, gcc, i sqlite3
RUN apt-get update && apt-get install -y \
    gcc \
    build-essential \
    sqlite3 \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Instalacja zależności z requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 8000

ENV FLASK_APP=user_service.py

CMD ["flask", "run", "--host=0.0.0.0", "--port=8000"]
