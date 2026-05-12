FROM node:20-bookworm-slim

WORKDIR /app

# Installer Python + pip + venv
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-venv \
    && rm -rf /var/lib/apt/lists/*

# Dépendances Node
COPY package*.json ./
RUN npm ci --only=production

# Copier tout le backend
COPY . .

# Installer dépendances Python dans un venv
RUN python3 -m venv /opt/venv
RUN /opt/venv/bin/pip install --upgrade pip
RUN /opt/venv/bin/pip install --no-cache-dir \
    pandas \
    numpy \
    joblib \
    scikit-learn==1.6.1 \
    lightgbm

# Pour que "python" utilise le venv
ENV PATH="/opt/venv/bin:$PATH"

RUN rm -f .env

EXPOSE 5000

CMD ["node", "server.js"]
