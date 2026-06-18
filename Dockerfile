FROM mcr.microsoft.com/playwright:v1.61.0-noble

WORKDIR /app
COPY package*.json ./
RUN npm install

COPY . .
CMD ["node", "server.js"]