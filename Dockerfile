FROM python:3.9

WORKDIR /app

COPY requirements.txt .
RUN apt-get update && apt-get install -y netcat-openbsd iputils-ping dnsutils

COPY . .

COPY wait-for-it.sh /wait-for-it.sh
RUN chmod +x /wait-for-it.sh

CMD ["/wait-for-it.sh", "mysql", "python", "app.py"]