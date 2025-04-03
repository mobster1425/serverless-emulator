#!/bin/bash
set -e
PROJECT_NAME=serverless-function-builder
AWS_DEFAULT_REGION=us-east-1
S3_BUCKET=serverless-emulator
echo "Checking CodeBuild project ${PROJECT_NAME}..."
aws codebuild batch-get-projects --names ${PROJECT_NAME} --region ${AWS_DEFAULT_REGION}
echo "Checking S3 bucket structure..."
aws s3 ls s3://${S3_BUCKET}/codebuild/ --region ${AWS_DEFAULT_REGION}
aws s3 ls s3://${S3_BUCKET}/codebuild/logs/ --region ${AWS_DEFAULT_REGION}
aws s3 ls s3://${S3_BUCKET}/codebuild/source/ --region ${AWS_DEFAULT_REGION}
echo "Checking CloudWatch log group..."
aws logs describe-log-groups --log-group-name-prefix "/aws/codebuild/${PROJECT_NAME}" --region ${AWS_DEFAULT_REGION}
echo "Checking IAM role permissions..."
ROLE_NAME=codebuild-${PROJECT_NAME}-service-role
aws iam get-role --role-name ${ROLE_NAME} --region ${AWS_DEFAULT_REGION}
aws iam list-role-policies --role-name ${ROLE_NAME} --region ${AWS_DEFAULT_REGION}
echo "Verification complete."
