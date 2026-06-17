FROM node:20-bookworm-slim 

WORKDIR /app

COPY package*.json ./
RUN npm ci --only=production

COPY . .

RUN rm -f .env

EXPOSE 5000

CMD ["node", "server.js"]