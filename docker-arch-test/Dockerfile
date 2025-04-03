FROM --platform=linux/amd64 node:18-alpine

# Create app directory
WORKDIR /app

# Set ARGs for multi-architecture builds
ARG TARGETARCH=amd64
ARG TARGETPLATFORM=linux/amd64
ARG BUILDPLATFORM=linux/amd64

# Copy app code
COPY . .

# Run with explicit architecture info
CMD ["node", "index.js"]
