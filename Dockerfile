FROM node:22-slim
WORKDIR /app
COPY package*.json tsconfig.json ./
COPY src ./src
RUN npm ci && npm run build && npm prune --omit=dev
ENV NODE_ENV=production
EXPOSE 8080
CMD ["node", "dist/index.js"]
