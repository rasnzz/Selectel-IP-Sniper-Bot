FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY hunter.py ./

STOPSIGNAL SIGTERM
CMD ["python", "-u", "hunter.py"]
