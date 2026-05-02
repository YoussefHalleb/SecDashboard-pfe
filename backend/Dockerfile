FROM node:20-bookworm-slim

WORKDIR /app

# Installer Python + venv + pip
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-venv \
    python3-pip \
  && rm -rf /var/lib/apt/lists/*

# Dépendances Node
COPY package*.json ./
RUN npm ci --only=production

# Copier tout le backend
COPY . .

# Environnement Python pour le modèle ML
RUN python3 -m venv /opt/venv
RUN /opt/venv/bin/pip install --no-cache-dir --upgrade pip
RUN /opt/venv/bin/pip install --no-cache-dir \
    pandas \
    joblib \
    scikit-learn==1.6.1

# Faire pointer "python" vers le venv
ENV PATH="/opt/venv/bin:$PATH"

RUN rm -f .env

EXPOSE 5000

CMD ["node", "server.js"]
