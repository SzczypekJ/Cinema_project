FROM python:3.9-slim

WORKDIR /Cinema_project/user_service

COPY ./user_service /Cinema_project/user_service
# COPY ./user_service/entrypoint.sh /opt
COPY ./user_service/requirements.txt /Cinema_project/user_service/
COPY ./database_connection.py /Cinema_project/user_service/
# Instalacja narzędzi build-essential, gcc, i sqlite3
RUN apt-get update && apt-get install -y \
    gcc \
    build-essential \
    sqlite3 \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Instalacja zależności z requirements.txt
RUN pip install --no-cache-dir -r /Cinema_project/user_service/requirements.txt

EXPOSE 8003

ENV FLASK_APP=user.py

CMD [ "flask", "run" ,"--host=0.0.0.0", "--port=8003" ]
