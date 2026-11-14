FROM python:3.12-slim
WORKDIR /app
COPY services/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY services/common.py services/classifier.py services/responder.py services/rulegen.py services/tier3.py services/logsink.py services/ctl.py services/feats.py services/secrule.py services/rulegen_ml.py services/rulesel_g2r.py services/benign_seed.txt ./
ENV PYTHONUNBUFFERED=1
