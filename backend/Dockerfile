FROM node:20-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci --only=production

COPY . .

RUN rm -f .env

EXPOSE 3000

CMD ["node", "server.js"]