FROM node:20-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci --only=production

COPY . .

# Exclure le .env (passé via --env-file ou secrets)
RUN rm -f .env

EXPOSE 3000

CMD ["node", "server.js"]
```



---

## `backend/.dockerignore` et `security-dashboard/.dockerignore`

Crée ce fichier dans **chaque dossier** :
```
node_modules
.env
.git
*.log
