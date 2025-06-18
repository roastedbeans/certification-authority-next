FROM node:18-alpine AS base

# Install dependencies only when needed
FROM base AS deps
WORKDIR /app

# Copy package.json and package-lock.json
COPY package.json package-lock.json ./

# Install dependencies
RUN npm ci

# Rebuild the source code only when needed
FROM base AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .

# Next.js collects completely anonymous telemetry data about general usage.
# Learn more here: https://nextjs.org/telemetry
# Uncomment the following line in case you want to disable telemetry.
ENV NEXT_TELEMETRY_DISABLED 1

# Build the Next.js application
RUN npm run build

# Production image, copy all the files and run next
FROM base AS runner
WORKDIR /app

# Environment variables
ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
ENV PORT=3000
ENV HOSTNAME=0.0.0.0

# Application configuration
ENV CA_API_URL=http://certification-authority:3000
ENV JWT_SECRET=starlight-anya-jwt-secret
ENV CA_CODE=certauth00
ENV CA_PRIVATE_KEY=certification-authority-private-key
ENV CA_PUBLIC_KEY=certification-authority-public-key

# Bond Bank configuration
ENV BOND_BANK_API=http://mydata-operator:4200
ENV BOND_ORG_CODE=bond123456
ENV BOND_ORG_SERIAL_CODE=bondserial00
ENV BOND_CLIENT_ID=xv9gqz7mb4t2o5wcf8rjy6kphudsnea0l3ytkpdhqrvcxz1578
ENV BOND_CLIENT_SECRET=m4q7xv9zb2tgc8rjy6kphudsnea0l3ow5ytkpdhqrvcfz926bt

# Anya Bank configuration
ENV ANYA_BANK_API=http://information-provider:4000
ENV ANYA_ORG_CODE=anya123456
ENV ANYA_ORG_SERIAL_CODE=anyaserial00
ENV ANYA_CLIENT_ID=wcf8rjy6kphudsnea0l3ytkpdhqrvcxz1578m4q7xv9zb2tgca
ENV ANYA_CLIENT_SECRET=a0l3ytkpdhqrvcfz926btm4q7xv9zb2tgc8rjy6kphudsnew5o

# Next.js public environment variables
ENV NEXT_PUBLIC_CA_CODE=certauth00
ENV NEXT_PUBLIC_CA_PRIVATE_KEY=certification-authority-private-key
ENV NEXT_PUBLIC_CA_PUBLIC_KEY=certification-authority-public-key
ENV NEXT_PUBLIC_BOND_BANK_API=http://localhost:4200
ENV NEXT_PUBLIC_BOND_ORG_CODE=bond123456
ENV NEXT_PUBLIC_BOND_ORG_SERIAL_CODE=bondserial00
ENV NEXT_PUBLIC_BOND_CLIENT_ID=xv9gqz7mb4t2o5wcf8rjy6kphudsnea0l3ytkpdhqrvcxz1578
ENV NEXT_PUBLIC_BOND_CLIENT_SECRET=m4q7xv9zb2tgc8rjy6kphudsnea0l3ow5ytkpdhqrvcfz926bt
ENV NEXT_PUBLIC_ANYA_BANK_API=http://localhost:4000
ENV NEXT_PUBLIC_ANYA_ORG_CODE=anya123456
ENV NEXT_PUBLIC_ANYA_ORG_SERIAL_CODE=anyaserial00
ENV NEXT_PUBLIC_ANYA_CLIENT_ID=wcf8rjy6kphudsnea0l3ytkpdhqrvcxz1578m4q7xv9zb2tgca
ENV NEXT_PUBLIC_ANYA_CLIENT_SECRET=a0l3ytkpdhqrvcfz926btm4q7xv9zb2tgc8rjy6kphudsnew5o

RUN addgroup --system --gid 1001 nodejs
RUN adduser --system --uid 1001 nextjs

# Copy public directory and scripts
COPY --from=builder /app/public ./public
COPY --from=builder /app/scripts ./scripts

# Install script runtime dependencies
RUN npm install -g tsx@4.19.3
RUN npm install @faker-js/faker@9.4.0 dayjs@1.11.13 @prisma/client@6.5.0

# Set the correct permission for prerender cache
RUN mkdir .next
RUN chown nextjs:nodejs .next

# Automatically leverage output traces to reduce image size
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static

USER nextjs

EXPOSE 3000

CMD ["node", "server.js"] 