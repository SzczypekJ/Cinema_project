FROM python:3.9-slim

WORKDIR /Cinema_project/auth_service

COPY ./auth_service /Cinema_project/auth_service
COPY ./auth_service/requirements.txt /Cinema_project/auth_service/

# Instalacja narzędzi build-essential, gcc, i bibliotek potrzebnych do obsługi MySQL oraz Supervisord
RUN apt-get update && apt-get install -y \
    gcc \
    build-essential \
    libpq-dev \
    default-libmysqlclient-dev \
    supervisor \
    && rm -rf /var/lib/apt/lists/*

# Instalacja zależności z requirements.txt
RUN pip install --no-cache-dir -r /Cinema_project/auth_service/requirements.txt

# Utworzenie katalogu dla logów
RUN mkdir -p /Cinema_project/auth_service/logs

COPY ./auth_service/supervisord.conf /etc/supervisor/conf.d/supervisord.conf

EXPOSE 8000

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
