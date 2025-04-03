FROM --platform=linux/amd64 node:18-alpine

# Set platform ARGs
ARG TARGETARCH=amd64
ARG TARGETPLATFORM=linux/amd64
ARG BUILDPLATFORM=linux/amd64

WORKDIR /app

# Copy our custom entrypoint script and make it executable
COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Copy our test file
COPY test.js .

# Use our custom entrypoint
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["node", "test.js"]
