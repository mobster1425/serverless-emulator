#!/bin/bash
# Simple script to build Docker images for ECS on ARM Mac

if [ -z "$1" ] || [ -z "$2" ] || [ -z "$3" ]; then
  echo "Usage: ./build-image.sh <image_name> <runtime> <code_path>"
  echo "Example: ./build-image.sh my-function nodejs18 /path/to/function.zip"
  exit 1
fi

IMAGE_NAME=$1
RUNTIME=$2
CODE_PATH=$3
HANDLER=${4:-"index.handler"}

# Create temp directory
TEMP_DIR=$(mktemp -d)
echo "Created temp directory: $TEMP_DIR"

# Extract function code
echo "Extracting code from $CODE_PATH to $TEMP_DIR"
unzip -q "$CODE_PATH" -d "$TEMP_DIR"

# Copy the Dockerfile template
cp Dockerfile.amd64 "$TEMP_DIR/Dockerfile"

# Modify Dockerfile based on runtime
if [[ "$RUNTIME" == *"python"* ]]; then
  sed -i '' "s/node:18-alpine/python:3.8-alpine/g" "$TEMP_DIR/Dockerfile"
  sed -i '' "s/node index.js/python -m handler/g" "$TEMP_DIR/Dockerfile"
elif [[ "$RUNTIME" == *"go"* ]]; then
  sed -i '' "s/node:18-alpine/golang:1.18-alpine/g" "$TEMP_DIR/Dockerfile"
  sed -i '' "s/node index.js/.\/main/g" "$TEMP_DIR/Dockerfile"
fi

# Build the Docker image with platform explicitly set
echo "Building Docker image: $IMAGE_NAME"
docker build --platform=linux/amd64 -t "$IMAGE_NAME" "$TEMP_DIR"

# Push to ECR if AWS_ACCOUNT_ID is set
if [ ! -z "$AWS_ACCOUNT_ID" ] && [ ! -z "$AWS_REGION" ]; then
  echo "Pushing to ECR..."
  AWS_ECR_URI="$AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com"
  
  # Login to ECR
  aws ecr get-login-password --region "$AWS_REGION" | docker login --username AWS --password-stdin "$AWS_ECR_URI"
  
  # Tag image for ECR
  docker tag "$IMAGE_NAME" "$AWS_ECR_URI/$IMAGE_NAME"
  
  # Push image
  docker push "$AWS_ECR_URI/$IMAGE_NAME"
fi

# Clean up
rm -rf "$TEMP_DIR"
echo "Done!" 