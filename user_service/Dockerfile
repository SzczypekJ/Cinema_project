FROM python:3.9-slim

WORKDIR /Cinema_project/user_service

COPY ./user_service /Cinema_project/user_service
COPY ./user_service/requirements.txt /Cinema_project/user_service/

RUN apt-get update && apt-get install -y \
    gcc \
    build-essential \
    libpq-dev \
    default-libmysqlclient-dev \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir -r /Cinema_project/user_service/requirements.txt

EXPOSE 8002

ENV FLASK_APP=user.py

CMD [ "flask", "run" ,"--host=0.0.0.0", "--port=8002" ]
