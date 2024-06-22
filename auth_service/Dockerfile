FROM python:3.9-slim

WORKDIR /Cinema_project/auth_service

COPY ./auth_service /Cinema_project/auth_service
COPY ./auth_service/requirements.txt /Cinema_project/auth_service/

# Instalacja narzędzi build-essential, gcc, i bibliotek potrzebnych do obsługi MySQL
RUN apt-get update && apt-get install -y \
    gcc \
    build-essential \
    libpq-dev \
    default-libmysqlclient-dev \
    && rm -rf /var/lib/apt/lists/*

# Instalacja zależności z requirements.txt
RUN pip install --no-cache-dir -r /Cinema_project/auth_service/requirements.txt

EXPOSE 8000

ENV FLASK_APP=auth.py

CMD [ "flask", "run" ,"--host=0.0.0.0", "--port=8000" ]
