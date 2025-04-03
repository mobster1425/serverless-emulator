# Serverless Emulator

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## Overview

Serverless Emulator is a powerful platform for developing, testing, and running serverless functions locally or in the cloud. It provides a consistent environment that emulates cloud serverless platforms (like AWS Lambda), allowing developers to build and test functions with minimal latency and maximum flexibility.

The platform supports both local development using Docker containers and production deployment using AWS ECS and CodeBuild services, providing a seamless transition between environments.

## Features

- **Multi-runtime Support**: Run functions written in various languages and runtimes
- **Hybrid Execution Model**: Choose between Docker (local) or AWS ECS (cloud) execution
- **Synchronous & Asynchronous Invocation**: Support for both blocking and non-blocking function calls
- **Persistent Storage**: Store function code, dependencies, and assets in S3-compatible storage
- **Comprehensive Logging**: Detailed execution logs and metrics for debugging and monitoring
- **Resource Controls**: Configure memory, CPU limits, and execution timeouts
- **REST API**: Full-featured API for function management and invocation
- **Container-based Isolation**: Secure execution environment for each function
- **Queue-based Worker Pool**: Efficient handling of concurrent function executions

## Supported Runtimes

The Serverless Emulator supports the following runtimes:

- **Node.js**: nodejs18
- **Python**: python3.10
- **Go**: go1.18
- **Custom runtimes**: Any runtime that can be containerized

## Architecture

Serverless Emulator follows a modular architecture with the following main components:

- **API Server**: Handles HTTP requests for function management and invocation
- **Worker Pool**: Manages concurrent function executions
- **Runtime Clients**: Abstracts the underlying execution environment (Docker/ECS)
- **Database**: Stores function metadata, configurations, and execution logs
- **Queue**: Manages asynchronous function invocations
- **Storage**: Handles function code and dependency storage

## Requirements

- Go 1.23 or higher
- PostgreSQL 12+
- Redis 6+
- Docker (for local execution mode)
- AWS Account (for ECS execution mode)

## Installation

### Clone the Repository

```bash
git clone https://github.com/yourusername/serverless-emulator.git
cd serverless-emulator
```

## Building and Running

### 1. Configure Environment Variables

Create a `.env` file in the root directory by copying the example:

```bash
cp cmd/server/.env .env
```

Then edit the `.env` file to configure your database, Docker, and AWS settings as needed.

### 2. Set Up Database

Ensure PostgreSQL is running and create a database for the application:

```bash
createdb serverless-emulator
```

### 3. Build the Server

```bash
# Ensure you have Go 1.23+ installed
go version

# Build the server
go build -o bin/server ./cmd/server
```

### 4. Run the Server

```bash
# Run using the built binary
./bin/server

# Alternatively, run directly with Go
go run cmd/server/main.go
```

The server will start and listen on the port specified in your `.env` file (default: 8080).

## Testing with Sample Functions

The repository includes test scripts for different runtimes to help you verify that your setup is working correctly. These scripts create and invoke functions in Node.js, Go, and Python.

### Node.js Function Test

```bash
# Make the script executable
chmod +x testNode.sh

# Run the test
./testNode.sh
```

This script:
1. Creates a sample Node.js image analysis function
2. Uploads it to the Serverless Emulator
3. Invokes the function with a test payload
4. Retrieves and displays the function logs

### Go Function Test

```bash
# Make the script executable
chmod +x testGo.sh

# Run the test
./testGo.sh
```

This script does the same as the Node.js test but uses a Go function for image analysis.

### Python Function Test

```bash
# Make the script executable
chmod +x testPython.sh

# Run the test
./testPython.sh
```

This script demonstrates Python function deployment and invocation.

### Test Script Requirements

The test scripts require:
- `jq` for JSON processing
- `curl` for API requests
- `zip` for packaging function code

Install them using your system's package manager:

```bash
# Ubuntu/Debian
apt-get install jq curl zip

# macOS
brew install jq curl
```

## Configuration

Serverless Emulator is configured via environment variables, which can be set in a `.env` file in the project root.

### Environment Variables

#### API Configuration
```
API_PORT=8080                    # Port for the API server
API_READ_TIMEOUT=600s            # HTTP read timeout
API_WRITE_TIMEOUT=600s           # HTTP write timeout
API_SHUTDOWN_TIMEOUT=30s         # Graceful shutdown timeout
API_ENVIRONMENT=development      # Environment (development, staging, production)
```

#### Database Configuration
```
POSTGRES_DSN="postgres://user:password@localhost:5432/serverless-emulator?sslmode=disable"
DB_MAX_OPEN_CONNS=25             # Maximum number of open connections
DB_MAX_IDLE_CONNS=25             # Maximum number of idle connections
DB_CONN_MAX_LIFETIME=1h          # Connection maximum lifetime
```

#### Redis Configuration
```
REDIS_ADDR=localhost:6379        # Redis address
REDIS_PASSWORD=                  # Redis password (if any)
REDIS_DB=0                       # Redis database
```

#### Docker Configuration
```
DOCKER_HOST=unix:///var/run/docker.sock  # Docker host
DOCKER_DEFAULT_MEMORY_LIMIT=128          # Default memory limit in MB
DOCKER_DEFAULT_CPU_LIMIT=1.0             # Default CPU limit (cores)
DOCKER_DEFAULT_TIMEOUT=600s              # Default function timeout
DOCKER_NETWORK=serverless-network        # Docker network to use
DOCKER_CONTAINER_PREFIX=fn-              # Container name prefix
```

#### Worker Configuration
```
WORKER_COUNT=5                   # Number of worker goroutines
WORKER_QUEUE_NAME=function_queue # Queue name for function execution
WORKER_MAX_RETRIES=3             # Maximum retry attempts
WORKER_PROCESSING_TIMEOUT=10m    # Processing timeout
```

#### AWS S3 Configuration (for function storage)
```
AWS_S3_BUCKET_ACCESS_KEY=        # S3 access key
AWS_S3_BUCKET_SECRET_KEY=        # S3 secret key
AWS_DEFAULT_REGION=us-east-1     # AWS region
AWS_S3_BUCKET=                   # S3 bucket name
```

#### Runtime Configuration
```
RUNTIME_MODE=docker              # Runtime mode (docker, ecs)
```

#### ECS Configuration (for cloud execution)
```
AWS_ACCESS_KEY_ID=               # AWS access key
AWS_SECRET_ACCESS_KEY=           # AWS secret key
AWS_DEFAULT_REGION=us-east-1     # AWS region
AWS_ECS_CLUSTER=                 # ECS cluster name
AWS_ECS_TASK_EXECUTION_ROLE_ARN= # ECS task execution role ARN
AWS_ECS_TASK_ROLE_ARN=           # ECS task role ARN
AWS_ECS_SUBNETS=                 # ECS subnet IDs (comma-separated)
AWS_ECS_SECURITY_GROUPS=         # ECS security group IDs (comma-separated)
AWS_EFS_FILESYSTEM_ID=           # EFS filesystem ID
AWS_EFS_ACCESS_POINT_ID=         # EFS access point ID
```

#### CodeBuild Configuration (for function building)
```
AWS_CODEBUILD_ENABLED=true       # Enable AWS CodeBuild
AWS_CODEBUILD_PROJECT_NAME=      # CodeBuild project name
AWS_CODEBUILD_REGION=us-east-1   # CodeBuild region
AWS_ECS_USE_CODEBUILD=true       # Use CodeBuild for function building
```

## Usage

### API Endpoints

#### Function Management

- `POST /api/functions` - Create a new function
- `GET /api/functions` - List all functions
- `GET /api/functions/{id}` - Get function details
- `PUT /api/functions/{id}` - Update a function
- `DELETE /api/functions/{id}` - Delete a function

#### Function Invocation

- `POST /api/functions/{id}/invoke` - Invoke a function synchronously
- `POST /api/functions/{id}/invoke-async` - Invoke a function asynchronously

#### Deployment

- `POST /api/functions/{id}/deploy` - Deploy a function
- `GET /api/functions/{id}/status` - Check deployment status

#### Logs

- `GET /api/functions/{id}/logs` - Get function execution logs
- `GET /api/functions/{id}/invocations/{requestId}/logs` - Get logs for a specific invocation

## Components Overview

### API Server (`internal/api`)

The API server handles HTTP requests and routes them to the appropriate handlers. It uses the Gin web framework for routing and middleware.

### Worker Pool (`internal/worker`)

The worker pool manages concurrent function executions. It uses a buffered channel to distribute work among worker goroutines, which process function invocations by creating and running containers.

### Runtime Clients (`internal/docker`, `internal/runtime`)

The runtime clients abstract the underlying execution environment:
- Docker client: Uses the Docker API to create, start, and manage containers locally
- ECS client: Uses AWS ECS API to run functions as ECS tasks in the cloud

### Database (`internal/db`)

The database stores function metadata, configurations, and execution logs. It uses PostgreSQL with the sqlx library for data access.

### Queue (`internal/queue`)

The queue manages asynchronous function invocations. It uses Redis with the go-redis library.

### Storage (`internal/storage`)

The storage component handles function code and dependency storage. It uses S3-compatible storage with the AWS SDK.

## Development

### Project Structure

```
serverless-emulator/
├── cmd/                      # Command-line applications
│   └── server/               # Main server application
├── internal/                 # Internal packages (not importable)
│   ├── api/                  # API server and handlers
│   ├── config/               # Configuration loading
│   ├── db/                   # Database access
│   ├── docker/               # Docker client implementation
│   ├── models/               # Data models
│   ├── queue/                # Queue implementation
│   ├── runtime/              # Runtime interface definitions
│   ├── storage/              # Storage implementation
│   ├── types/                # Shared type definitions
│   └── worker/               # Worker pool implementation
└── pkg/                      # Public packages (importable)
    └── logger/               # Logging package

```

### Building from Source

```bash
# Build the server
go build -o bin/server ./cmd/server

# Run tests
go test ./...
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.
