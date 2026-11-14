FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir confluent-kafka==2.5.3
COPY services/common.py web/enforcer/enforcer.py ./
ENV PYTHONUNBUFFERED=1
