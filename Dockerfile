FROM python:3.9

WORKDIR /app

RUN apt-get update && apt-get install -y netcat-openbsd

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

COPY wait-for-it.sh /wait-for-it.sh
RUN chmod +x /wait-for-it.sh

CMD ["/wait-for-it.sh", "mysql", "python", "app.py"]