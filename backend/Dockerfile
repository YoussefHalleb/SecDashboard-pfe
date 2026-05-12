FROM node:20-alpine

WORKDIR /app

# Installer Python + pip + outils nécessaires
RUN apk add --no-cache python3 py3-pip

# Dépendances Node
COPY package*.json ./
RUN npm ci --only=production

# Copier tout le backend
COPY . .

# Installer dépendances Python dans un venv
RUN python3 -m venv /opt/venv
RUN /opt/venv/bin/pip install --no-cache-dir pandas numpy joblib scikit-learn==1.6.1 lightgbm

# Pour que "python" utilise le venv
ENV PATH="/opt/venv/bin:$PATH"

RUN rm -f .env

EXPOSE 5000

CMD ["node", "server.js"]
