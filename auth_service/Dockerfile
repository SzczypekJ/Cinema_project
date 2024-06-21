FROM python:3.9-slim

WORKDIR /Cinema_project/auth_service

# COPY ./auth_service /Cinema_project/auth_service
COPY ./config.py /Cinema_project/auth_service/config.py
COPY ./database.py /Cinema_project/auth_service/database.py
COPY ./database_connection.py /Cinema_project/auth_service/database_connection.py
COPY requirements.txt .

RUN apt-get update && apt-get install -y \
    gcc \
    build-essential \
    sqlite3 \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 8000

ENV FLASK_APP=auth.py

CMD ["flask", "run", "--host=0.0.0.0", "--port=8000", "--debug"]
