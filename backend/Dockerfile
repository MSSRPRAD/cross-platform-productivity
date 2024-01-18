FROM python:3.8-slim

WORKDIR /

COPY requirements.txt .

RUN pip install -r requirements.txt

WORKDIR /cross-platform-productivity-backend

CMD ["python", "app.py"]