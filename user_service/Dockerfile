FROM python:3.9-slim

WORKDIR /Cinema_project/user_service

COPY ./user_service /Cinema_project/user_service
COPY ./config.py /Cinema_project/user_service/config.py
COPY ./database.py /Cinema_project/user_service/database.py
COPY ./database_connection.py /Cinema_project/user_service/database_connection.py

RUN apt-get update && apt-get install -y \
    gcc \
    build-essential \
    sqlite3 \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 8000

ENV FLASK_APP=user_service.py

CMD ["flask", "run", "--host=0.0.0.0", "--port=8000"]
