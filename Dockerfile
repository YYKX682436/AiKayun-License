FROM node:24-alpine@sha256:06d7adf3e0ef61a13f1d28682726366f97a15aa1888c934d3ecec86c33918b53 AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN node --input-type=commonjs -e "const fs=require('node:fs'); const p=JSON.parse(fs.readFileSync('package.json','utf8')); const r={name:p.name,version:p.version,private:p.private,type:p.type,engines:p.engines,dependencies:p.dependencies}; fs.writeFileSync('package.runtime.json',JSON.stringify(r,null,2)+'\\n')"
RUN npm ci
COPY tsconfig.json tsconfig.build.json ./
COPY src ./src
RUN npm run build

FROM node:24-alpine@sha256:06d7adf3e0ef61a13f1d28682726366f97a15aa1888c934d3ecec86c33918b53 AS runtime
ENV NODE_ENV=development
WORKDIR /app
COPY --from=build /app/package.runtime.json ./package.json
COPY package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force
COPY --from=build /app/dist ./dist
USER node
EXPOSE 4318
CMD ["node", "dist/main.js"]
