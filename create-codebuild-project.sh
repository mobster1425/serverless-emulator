#!/bin/bash
set -e

# AWS CodeBuild Project creator script
# This script creates a CodeBuild project that will be used to build Docker images
# for the serverless-emulator functions on the native x86_64 architecture

# Set AWS region and account ID directly to avoid parsing issues
AWS_DEFAULT_REGION="us-east-1"
AWS_ACCOUNT_ID="113491453062"
AWS_S3_BUCKET="serverless-emulator"

echo "Using region: ${AWS_DEFAULT_REGION}"
echo "Using account ID: ${AWS_ACCOUNT_ID}"
echo "Using S3 bucket: ${AWS_S3_BUCKET}"

# Check if AWS CLI is installed
if ! command -v aws &> /dev/null; then
    echo "AWS CLI is not installed. Please install it and configure your credentials."
    exit 1
fi

# Set project name
PROJECT_NAME=serverless-function-builder

# Create service role for CodeBuild if needed
ROLE_NAME=codebuild-${PROJECT_NAME}-service-role

# Check if role exists
if ! aws iam get-role --role-name ${ROLE_NAME} &> /dev/null; then
    echo "Creating IAM role for CodeBuild..."
    
    # Create trust policy document
    cat > trust-policy.json << EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "codebuild.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF

    # Create the role
    aws iam create-role --role-name ${ROLE_NAME} \
        --assume-role-policy-document file://trust-policy.json
    
    # Attach necessary policies
    aws iam attach-role-policy --role-name ${ROLE_NAME} \
        --policy-arn arn:aws:iam::aws:policy/AmazonECRFullAccess
    
    aws iam attach-role-policy --role-name ${ROLE_NAME} \
        --policy-arn arn:aws:iam::aws:policy/AmazonS3FullAccess
    
    aws iam attach-role-policy --role-name ${ROLE_NAME} \
        --policy-arn arn:aws:iam::aws:policy/AWSCodeBuildAdminAccess
    
    aws iam attach-role-policy --role-name ${ROLE_NAME} \
        --policy-arn arn:aws:iam::aws:policy/CloudWatchLogsFullAccess
    
    aws iam attach-role-policy --role-name ${ROLE_NAME} \
        --policy-arn arn:aws:iam::aws:policy/AWSKeyManagementServicePowerUser
    
    # Add inline policy for Docker permission
    cat > docker-policy.json << EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ecr:BatchCheckLayerAvailability",
                "ecr:CompleteLayerUpload",
                "ecr:GetAuthorizationToken",
                "ecr:InitiateLayerUpload",
                "ecr:PutImage",
                "ecr:UploadLayerPart"
            ],
            "Resource": "*"
        }
    ]
}
EOF

    aws iam put-role-policy --role-name ${ROLE_NAME} \
        --policy-name DockerBuildPolicy \
        --policy-document file://docker-policy.json
        
    # Add logs policy for CloudWatch and S3 access
    cat > logs-policy.json << EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents",
                "logs:GetLogEvents",
                "logs:DescribeLogGroups",
                "logs:DescribeLogStreams"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "s3:PutObject",
                "s3:GetObject",
                "s3:GetObjectVersion",
                "s3:ListBucket",
                "s3:CreateBucket"
            ],
            "Resource": [
                "arn:aws:s3:::${S3_BUCKET}",
                "arn:aws:s3:::${S3_BUCKET}/*"
            ]
        }
    ]
}
EOF

    aws iam put-role-policy --role-name ${ROLE_NAME} \
        --policy-name LogsAndS3Policy \
        --policy-document file://logs-policy.json
    
    rm docker-policy.json
    rm logs-policy.json
    
    echo "IAM role created and policies attached"
    
    # Clean up
    rm trust-policy.json
fi

# Get role ARN
ROLE_ARN=$(aws iam get-role --role-name ${ROLE_NAME} --query "Role.Arn" --output text)
echo "Using role ARN: ${ROLE_ARN}"

# Check if S3 bucket exists
S3_BUCKET=$(aws s3api list-buckets --query "Buckets[?Name=='serverless-emulator'].Name" --output text)
if [[ -z "${S3_BUCKET}" ]]; then
    echo "Creating S3 bucket for build artifacts..."
    aws s3api create-bucket --bucket serverless-emulator --region ${AWS_DEFAULT_REGION} \
        --create-bucket-configuration LocationConstraint=${AWS_DEFAULT_REGION}
    S3_BUCKET="serverless-emulator"
fi
echo "Using S3 bucket: ${S3_BUCKET}"

# Create required S3 paths
echo "Creating required S3 paths..."
aws s3api put-object --bucket ${S3_BUCKET} --key codebuild/ --content-length 0
aws s3api put-object --bucket ${S3_BUCKET} --key codebuild/logs/ --content-length 0
aws s3api put-object --bucket ${S3_BUCKET} --key codebuild/source/ --content-length 0
echo "Created S3 paths in bucket ${S3_BUCKET}"

# Ensure CloudWatch Logs group exists
echo "Creating CloudWatch Logs group..."
aws logs create-log-group --log-group-name "/aws/codebuild/${PROJECT_NAME}" --region ${AWS_DEFAULT_REGION} || true
echo "CloudWatch Logs group created or already exists: /aws/codebuild/${PROJECT_NAME}"

# Check if CodeBuild project exists
echo "Checking if CodeBuild project ${PROJECT_NAME} exists..."
if aws codebuild batch-get-projects --names ${PROJECT_NAME} --query "projects[0].name" --output text &> /dev/null; then
    echo "CodeBuild project ${PROJECT_NAME} exists, deleting it..."
    aws codebuild delete-project --name ${PROJECT_NAME}
    echo "Deleted existing project ${PROJECT_NAME}"
fi

echo "Creating CodeBuild project ${PROJECT_NAME}..."

# Create project definition
cat > project-def.json << EOF
{
    "name": "${PROJECT_NAME}",
    "description": "Builds Docker images for serverless functions on x86_64 architecture",
    "source": {
        "type": "S3",
        "location": "${S3_BUCKET}/codebuild/source/source.zip"
    },
    "artifacts": {
        "type": "NO_ARTIFACTS"
    },
    "environment": {
        "type": "LINUX_CONTAINER",
        "image": "aws/codebuild/amazonlinux2-x86_64-standard:4.0",
        "computeType": "BUILD_GENERAL1_SMALL",
        "privilegedMode": true,
        "environmentVariables": [
            {
                "name": "AWS_DEFAULT_REGION",
                "value": "${AWS_DEFAULT_REGION}",
                "type": "PLAINTEXT"
            },
            {
                "name": "AWS_ACCOUNT_ID",
                "value": "${AWS_ACCOUNT_ID}",
                "type": "PLAINTEXT"
            },
            {
                "name": "DOCKER_BUILDKIT",
                "value": "1",
                "type": "PLAINTEXT"
            },
            {
                "name": "DOCKER_DEFAULT_PLATFORM", 
                "value": "linux/amd64",
                "type": "PLAINTEXT"
            }
        ]
    },
    "serviceRole": "${ROLE_ARN}",
    "timeoutInMinutes": 30,
    "queuedTimeoutInMinutes": 480,
    "encryptionKey": "arn:aws:kms:${AWS_DEFAULT_REGION}:${AWS_ACCOUNT_ID}:alias/aws/s3",
    "logsConfig": {
        "cloudWatchLogs": {
            "status": "ENABLED",
            "groupName": "/aws/codebuild/${PROJECT_NAME}",
            "streamName": "${PROJECT_NAME}"
        },
        "s3Logs": {
            "status": "ENABLED",
            "location": "${S3_BUCKET}/codebuild/logs/${PROJECT_NAME}"
        }
    }
}
EOF

# Create the project
aws codebuild create-project --cli-input-json file://project-def.json

echo "CodeBuild project created"

# Clean up
rm project-def.json

# Update .env file if needed
if ! grep -q "AWS_CODEBUILD_PROJECT_NAME" .env; then
    echo -e "\n# CodeBuild Configuration" >> .env
    echo "AWS_CODEBUILD_ENABLED=true" >> .env
    echo "AWS_CODEBUILD_PROJECT_NAME=${PROJECT_NAME}" >> .env
    echo "AWS_CODEBUILD_REGION=${AWS_DEFAULT_REGION}" >> .env
    echo "AWS_ECS_USE_CODEBUILD=true" >> .env
    
    echo "Updated .env file with CodeBuild configuration"
fi

echo "CodeBuild setup completed!"
echo "You can now use AWS CodeBuild to build Docker images for your serverless functions."
echo "The project is: ${PROJECT_NAME}" 