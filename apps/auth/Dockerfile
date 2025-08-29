FROM node:20-alpine
WORKDIR /app
COPY package.json ./
RUN npm i --omit=dev
COPY server.js ./
EXPOSE 3001
CMD ["npm", "start"]