package docker

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"serverless-emulator/internal/runtime"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/codebuild"
	cbtypes "github.com/aws/aws-sdk-go-v2/service/codebuild/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/rs/zerolog"
)

// CodeBuildClient is a client for building Docker images using AWS CodeBuild
type CodeBuildClient struct {
	logger      zerolog.Logger
	cbClient    *codebuild.Client
	s3Client    *s3.Client
	region      string
	s3Bucket    string
	projectName string
}

// NewCodeBuildClient creates a new CodeBuild client
func NewCodeBuildClient(logger zerolog.Logger, region, s3Bucket, projectName string) (*CodeBuildClient, error) {
	logger = logger.With().Str("component", "codebuild_client").Logger()
	logger.Info().
		Str("region", region).
		Str("s3_bucket", s3Bucket).
		Str("project_name", projectName).
		Msg("Initializing CodeBuild client")

	// Load AWS configuration
	cfg, err := config.LoadDefaultConfig(context.Background(),
		config.WithRegion(region),
	)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to load AWS configuration")
		return nil, fmt.Errorf("failed to load AWS configuration: %w", err)
	}

	// Create CodeBuild client
	cbClient := codebuild.NewFromConfig(cfg)

	// Create S3 client
	s3Client := s3.NewFromConfig(cfg)

	return &CodeBuildClient{
		logger:      logger,
		cbClient:    cbClient,
		s3Client:    s3Client,
		region:      region,
		s3Bucket:    s3Bucket,
		projectName: projectName,
	}, nil
}

// BuildImage builds a Docker image using AWS CodeBuild
func (c *CodeBuildClient) BuildImage(ctx context.Context, opts *runtime.BuildImageOptions) (string, error) {
	c.logger.Info().
		Str("image", opts.ImageName).
		Str("project", c.projectName).
		Str("runtime", string(opts.Runtime)).
		Msg("Building image with AWS CodeBuild")

	// Extract function ID from BuildImageOptions or environment
	functionID := ""
	for _, env := range opts.Environment {
		if env.Key == "FUNCTION_ID" {
			functionID = env.Value
			break
		}
	}

	// If function ID not found in environment, extract from image name
	if functionID == "" {
		if strings.HasPrefix(opts.ImageName, "fn-") {
			functionID = strings.TrimPrefix(opts.ImageName, "fn-")
		} else {
			functionID = opts.ImageName
		}
	}

	c.logger.Info().
		Str("function_id", functionID).
		Str("image_name", opts.ImageName).
		Msg("Using function ID for ECR repository name")

	// Step 1: Extract the function code to a temporary directory
	tempDir, err := c.extractFunctionCode(ctx, opts.CodePath)
	if err != nil {
		c.logger.Error().Err(err).Msg("Failed to extract function code")
		return "", fmt.Errorf("failed to extract function code: %w", err)
	}
	defer os.RemoveAll(tempDir)

	// Step 2: Create Dockerfile
	if err := c.createDockerfile(tempDir, opts); err != nil {
		c.logger.Error().Err(err).Msg("Failed to create Dockerfile")
		return "", fmt.Errorf("failed to create Dockerfile: %w", err)
	}

	// Step 3: Create buildspec.yml
	if err := c.createBuildspec(tempDir, opts); err != nil {
		c.logger.Error().Err(err).Msg("Failed to create buildspec.yml")
		return "", fmt.Errorf("failed to create buildspec.yml: %w", err)
	}

	// Step 4: Create metadata files
	if err := c.createMetadataFiles(tempDir, opts); err != nil {
		c.logger.Error().Err(err).Msg("Failed to create metadata files")
		return "", fmt.Errorf("failed to create metadata files: %w", err)
	}

	// Step 5: Create source ZIP
	sourceZipPath := filepath.Join(os.TempDir(), fmt.Sprintf("%s-source.zip", opts.ImageName))
	defer os.Remove(sourceZipPath)

	if err := c.createSourceZip(tempDir, sourceZipPath); err != nil {
		c.logger.Error().Err(err).Msg("Failed to create source ZIP")
		return "", fmt.Errorf("failed to create source ZIP: %w", err)
	}

	// Step 6: Upload source ZIP to S3
	s3Key := fmt.Sprintf("codebuild/source/%s-source.zip", opts.ImageName)
	if err := c.uploadToS3(ctx, sourceZipPath, s3Key); err != nil {
		c.logger.Error().Err(err).Msg("Failed to upload source ZIP to S3")
		return "", fmt.Errorf("failed to upload source ZIP to S3: %w", err)
	}

	// Step 7: Start CodeBuild build
	buildID, err := c.startBuild(ctx, s3Key, opts)
	if err != nil {
		c.logger.Error().Err(err).Msg("Failed to start CodeBuild build")
		return "", fmt.Errorf("failed to start CodeBuild build: %w", err)
	}

	// Step 8: Wait for build to complete
	imageURI, err := c.waitForBuild(ctx, buildID)
	if err != nil {
		c.logger.Error().Err(err).Msg("Build failed")
		return "", fmt.Errorf("build failed: %w", err)
	}

	// Ensure the image URI uses the function ID for the repository name
	// This helps ensure consistency between the URI we return and what ECS will try to pull
	accountID := os.Getenv("AWS_ACCOUNT_ID")
	region := c.region

	// Check if the returned imageURI doesn't match our expected pattern with function ID
	expectedRepo := fmt.Sprintf("%s.dkr.ecr.%s.amazonaws.com/fn-%s", accountID, region, functionID)
	if !strings.HasPrefix(imageURI, expectedRepo) {
		// Construct a new URI using the function ID and latest tag
		newImageURI := fmt.Sprintf("%s:latest", expectedRepo)
		c.logger.Warn().
			Str("original_uri", imageURI).
			Str("corrected_uri", newImageURI).
			Msg("Correcting image URI to use function ID in repository name")
		imageURI = newImageURI
	}

	// Store the image URI in environment for ECS to use later
	if err := os.Setenv("CODEBUILD_IMAGE_URI_"+opts.ImageName, imageURI); err != nil {
		c.logger.Warn().
			Err(err).
			Str("image_uri", imageURI).
			Msg("Failed to set environment variable for image URI, container creation might fail")
	}

	return imageURI, nil
}

// extractFunctionCode extracts the function code to a temporary directory
func (c *CodeBuildClient) extractFunctionCode(ctx context.Context, codePath string) (string, error) {
	c.logger.Debug().Str("code_path", codePath).Msg("Extracting function code")

	// Check if code path is an S3 path or a local path
	if strings.HasPrefix(codePath, "s3://") {
		// Code is in S3, download it first
		c.logger.Info().Str("path", codePath).Msg("Code path is in S3")
		parts := strings.SplitN(strings.TrimPrefix(codePath, "s3://"), "/", 2)
		if len(parts) != 2 {
			return "", fmt.Errorf("invalid S3 path: %s", codePath)
		}
		bucket := parts[0]
		key := parts[1]

		// Create temporary file to download to
		tempFile, err := os.CreateTemp("", "function-code-*.zip")
		if err != nil {
			return "", fmt.Errorf("failed to create temp file: %w", err)
		}
		tempFilePath := tempFile.Name()
		tempFile.Close() // Close the file so it can be written to

		// Download from S3
		c.logger.Debug().
			Str("bucket", bucket).
			Str("key", key).
			Str("temp_file", tempFilePath).
			Msg("Downloading file from S3")

		// Get the object
		result, err := c.s3Client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: aws.String(bucket),
			Key:    aws.String(key),
		})
		if err != nil {
			return "", fmt.Errorf("failed to download from S3: %w", err)
		}
		defer result.Body.Close()

		// Write the body to the temp file
		tempFile, err = os.Create(tempFilePath) // Reopen the file
		if err != nil {
			return "", fmt.Errorf("failed to open temp file for writing: %w", err)
		}
		defer tempFile.Close()

		_, err = io.Copy(tempFile, result.Body)
		if err != nil {
			return "", fmt.Errorf("failed to write S3 object to file: %w", err)
		}
		tempFile.Close() // Make sure file is closed before extraction

		c.logger.Debug().
			Str("temp_file", tempFilePath).
			Msg("Downloaded S3 object to temp file")

		// Now extract from the downloaded zip
		return c.extractZip(tempFilePath)
	}

	// Local path, extract directly
	return c.extractZip(codePath)
}

// extractZip extracts a ZIP file to a temporary directory
func (c *CodeBuildClient) extractZip(zipPath string) (string, error) {
	c.logger.Debug().Str("zip_path", zipPath).Msg("Extracting ZIP file")

	// Create temporary directory for extraction
	tempDir, err := os.MkdirTemp("", "function-code-extracted-*")
	if err != nil {
		return "", fmt.Errorf("failed to create temp directory: %w", err)
	}

	// Open the ZIP file
	zipReader, err := zip.OpenReader(zipPath)
	if err != nil {
		// If it's not a valid ZIP file, try to handle it as a single file
		c.logger.Debug().
			Err(err).
			Str("zip_path", zipPath).
			Msg("Failed to open as ZIP, trying to handle as a single file")

		return c.handleSingleFile(zipPath)
	}
	defer zipReader.Close()

	// Extract each file
	for _, file := range zipReader.File {
		if err := c.extractZipFile(file, tempDir); err != nil {
			os.RemoveAll(tempDir)
			return "", fmt.Errorf("failed to extract file %s: %w", file.Name, err)
		}
	}

	return tempDir, nil
}

// handleSingleFile handles cases where the code is not a ZIP file but a single file
func (c *CodeBuildClient) handleSingleFile(filePath string) (string, error) {
	c.logger.Debug().Str("file_path", filePath).Msg("Handling as single file")

	// Create temporary directory for the file
	tempDir, err := os.MkdirTemp("", "function-code-single-*")
	if err != nil {
		return "", fmt.Errorf("failed to create temp directory: %w", err)
	}

	// Read file content
	content, err := os.ReadFile(filePath)
	if err != nil {
		os.RemoveAll(tempDir)
		return "", fmt.Errorf("failed to read file: %w", err)
	}

	// Create the file in the temp directory
	// Default to index.js for simplicity if we can't determine the file type
	outputFileName := "index.js"

	// Try to determine file type based on content
	if len(content) > 10 {
		// Check for Python file signature
		if strings.HasPrefix(string(content), "#!/usr/bin/env python") ||
			strings.Contains(string(content[:50]), "import ") ||
			strings.Contains(string(content[:50]), "from ") {
			outputFileName = "main.py"
		} else if strings.Contains(string(content[:50]), "package ") ||
			strings.Contains(string(content[:50]), "import \"") {
			outputFileName = "main.go"
		}
	}

	// Write the file
	outputPath := filepath.Join(tempDir, outputFileName)
	if err := os.WriteFile(outputPath, content, 0644); err != nil {
		os.RemoveAll(tempDir)
		return "", fmt.Errorf("failed to write file: %w", err)
	}

	c.logger.Debug().
		Str("output_file", outputPath).
		Msg("Created single file in temp directory")

	return tempDir, nil
}

// extractZipFile extracts a single file from a ZIP archive
func (c *CodeBuildClient) extractZipFile(file *zip.File, destDir string) error {
	// Ensure the file path is safe
	filePath := filepath.Join(destDir, file.Name)
	if !strings.HasPrefix(filePath, destDir+string(os.PathSeparator)) {
		return fmt.Errorf("illegal file path: %s", file.Name)
	}

	// Create parent directory if it doesn't exist
	if file.FileInfo().IsDir() {
		if err := os.MkdirAll(filePath, os.ModePerm); err != nil {
			return fmt.Errorf("failed to create directory: %w", err)
		}
		return nil
	}

	// Create parent directory for file
	if err := os.MkdirAll(filepath.Dir(filePath), os.ModePerm); err != nil {
		return fmt.Errorf("failed to create parent directory: %w", err)
	}

	// Open the file in the archive
	rc, err := file.Open()
	if err != nil {
		return fmt.Errorf("failed to open file in archive: %w", err)
	}
	defer rc.Close()

	// Create the file on disk
	outFile, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer outFile.Close()

	// Copy file contents
	_, err = io.Copy(outFile, rc)
	if err != nil {
		return fmt.Errorf("failed to copy file contents: %w", err)
	}

	return nil
}

// createDockerfile generates a Dockerfile for the function
func (c *CodeBuildClient) createDockerfile(tempDir string, opts *runtime.BuildImageOptions) error {
	c.logger.Debug().
		Str("temp_dir", tempDir).
		Str("runtime", string(opts.Runtime)).
		Str("handler", opts.Handler).
		Msg("Creating Dockerfile")

	// Determine base and slim images based on runtime
	var runtimeImage string
	var isGoRuntime bool

	switch opts.Runtime {
	case "nodejs14.x", "nodejs14":
		runtimeImage = "node:14-alpine3.16"
	case "nodejs16.x", "nodejs16":
		runtimeImage = "node:16-alpine3.17"
	case "nodejs18.x", "nodejs18":
		runtimeImage = "node:18-alpine3.17"
	case "nodejs20.x", "nodejs20":
		runtimeImage = "node:20-alpine3.18"
	case "python3.8":
		runtimeImage = "python:3.8-alpine"
	case "python3.9":
		runtimeImage = "python:3.9-alpine"
	case "python3.10":
		runtimeImage = "python:3.10-alpine"
	case "python3.11":
		runtimeImage = "python:3.11-alpine"
	case "go1.x", "go1.18", "go1.19", "go1.20", "go1.21":
		runtimeImage = "golang:1.18-alpine"
		isGoRuntime = true
	default:
		c.logger.Warn().
			Str("runtime", string(opts.Runtime)).
			Msg("Unsupported runtime, defaulting to nodejs18")
		runtimeImage = "node:18-alpine3.17"
	}

	var dockerfileContent string

	if isGoRuntime {
		// Use multi-stage build for Go runtimes
		dockerfileContent = `# Multi-stage build for Go serverless functions
FROM --platform=linux/amd64 golang:1.18-alpine AS builder

# Set environment variables
ENV CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64

WORKDIR /app

# Copy function code
COPY . .

# Build the function
RUN if [ -f "go.mod" ]; then \
      echo "Building Go function..." && \
      go mod download && \
      go build -ldflags="-s -w" -o /app/handler || \
        { echo "Go build failed with exit code $?"; exit 1; }; \
    else \
      echo "Error: go.mod not found"; \
      exit 1; \
    fi

# Use a smaller image for the final container
FROM --platform=linux/amd64 alpine:3.18

# Set environment variables
ENV HANDLER=` + opts.Handler + `

WORKDIR /app

# Copy only the compiled binary from the builder stage
COPY --from=builder /app/handler /app/handler

# Create a non-root user for better security
RUN addgroup -S appgroup && \
    adduser -S appuser -G appgroup && \
    chown -R appuser:appgroup /app && \
    chmod +x /app/handler

# Print directory contents for debugging
RUN ls -la /app

USER appuser

# Run the handler
CMD ["/app/handler"]`
	} else {
		// Create Dockerfile content with optimized multi-stage build and Alpine base images for non-Go runtimes
		dockerfileContent = fmt.Sprintf(`# Simple, optimized single-stage build for serverless functions
FROM --platform=linux/amd64 %s

# Set environment variables
ENV NODE_ENV=production
ENV PYTHONUNBUFFERED=1
ENV LAMBDA_TASK_ROOT=/app
ENV PATH="/app:${PATH}"
ENV HANDLER=%s

WORKDIR /app

# Copy function code
COPY . .

# Install dependencies based on runtime
RUN if [ -f "package.json" ]; then \
      echo "Installing npm dependencies..." && \
      npm config set registry https://registry.npmjs.org/ && \
      if [ -f "package-lock.json" ]; then \
        npm ci --production --no-optional --no-fund || \
          { echo "npm ci failed with exit code $?"; exit 1; }; \
      else \
        npm install --production --no-optional --no-fund || \
          { echo "npm install failed with exit code $?"; exit 1; }; \
      fi \
    fi && \
    if [ -f "requirements.txt" ]; then \
      echo "Installing Python dependencies..." && \
      pip install --no-cache-dir -r requirements.txt || \
        { echo "pip install failed with exit code $?"; exit 1; }; \
    fi && \
    echo "Cleaning up build artifacts to reduce image size..." && \
    rm -rf /var/cache/apk/* /tmp/* && \
    find /app -type f -name "*.c" -delete && \
    find /app -type f -name "*.h" -delete && \
    find /app -type f -name "*.o" -delete && \
    find /app -type d -name "__pycache__" -exec rm -rf {} +

# Create a non-root user for better security
RUN addgroup -S appgroup && \
    adduser -S appuser -G appgroup && \
    chown -R appuser:appgroup /app

# Print directory contents for debugging
RUN ls -la /app

USER appuser

# Run the handler
CMD ["sh", "-c", "if [ -f '/app/handler' ]; then /app/handler; else node -e 'require(\"/app/\"+process.env.HANDLER.split(\".\")[0])[process.env.HANDLER.split(\".\")[1]]()'; fi"]
`, runtimeImage, opts.Handler)
	}

	// Write Dockerfile
	dockerfilePath := filepath.Join(tempDir, "Dockerfile")
	if err := os.WriteFile(dockerfilePath, []byte(dockerfileContent), 0644); err != nil {
		return fmt.Errorf("failed to write Dockerfile: %w", err)
	}

	// Log the Dockerfile content for debugging
	c.logger.Debug().
		Str("dockerfile_path", dockerfilePath).
		Str("dockerfile_content", dockerfileContent).
		Msg("Created Dockerfile")

	return nil
}

// createBuildspec creates a buildspec.yml file for CodeBuild
func (c *CodeBuildClient) createBuildspec(tempDir string, opts *runtime.BuildImageOptions) error {
	c.logger.Debug().
		Str("temp_dir", tempDir).
		Msg("Creating buildspec.yml")

	// Get ECR repository URI
	accountID := os.Getenv("AWS_ACCOUNT_ID")
	region := c.region
	if accountID == "" {
		return fmt.Errorf("AWS_ACCOUNT_ID environment variable is required")
	}

	ecrRepoURI := fmt.Sprintf("%s.dkr.ecr.%s.amazonaws.com", accountID, region)

	// Extract build ID and function ID
	buildID := ""
	functionID := ""

	// Extract function ID from environment variables
	for _, env := range opts.Environment {
		if env.Key == "FUNCTION_ID" {
			functionID = env.Value
			break
		}
	}

	// Extract build ID from image name (which should be fn-XXX format)
	if strings.HasPrefix(opts.ImageName, "fn-") {
		buildID = strings.TrimPrefix(opts.ImageName, "fn-")
	} else {
		buildID = opts.ImageName
	}

	// If function ID is not set, use build ID as a fallback
	if functionID == "" {
		functionID = buildID
	}

	// Log the critical identifiers for debugging
	c.logger.Info().
		Str("image_name", opts.ImageName).
		Str("function_id", functionID).
		Str("build_id", buildID).
		Msg("Creating buildspec with these identifiers")

	// Create simple buildspec.yml with minimal formatting to avoid YAML syntax errors
	buildspecContent := `version: 0.2

phases:
  install:
    runtime-versions:
      docker: latest
    commands:
      - echo "Starting build process"
      - yum update -y
      - yum install -y jq procps-ng iputils bind-utils net-tools curl wget tar gzip
      - echo "Docker diagnostics before build"
      - docker version || true
      - docker info || true
  
  pre_build:
    commands:
      - echo "Setting up proper locale"
      - export LC_ALL=C.UTF-8
      - export LANG=C.UTF-8
      - locale || true
      
      - echo "ECR login"
`

	// Add region and ECR repo URI safely without complex string formatting
	buildspecContent += fmt.Sprintf("      - aws ecr get-login-password --region %s | docker login --username AWS --password-stdin %s || echo \"ECR login failed\"\n",
		region, ecrRepoURI)

	// Add repository creation - IMPORTANT: Use function ID consistently for the repository name
	buildspecContent += fmt.Sprintf("      - aws ecr describe-repositories --repository-names fn-%s || aws ecr create-repository --repository-name fn-%s\n",
		functionID, functionID)

	// Add build phase
	buildspecContent += `  
  build:
    commands:
      - echo "Building Docker image"
      - docker version | grep -i platform || true
      - echo "DOCKER_DEFAULT_PLATFORM=linux/amd64"
`
	// Add build command - Use consistent naming for the local image
	buildspecContent += fmt.Sprintf("      - docker build --no-cache --platform=linux/amd64 -t fn-%s:latest .\n", functionID)

	// Add tagging commands - IMPORTANT: Use the function ID in the repository name, but can have both function ID and build ID tags
	buildspecContent += fmt.Sprintf("      - docker tag fn-%s:latest %s/fn-%s:latest\n",
		functionID, ecrRepoURI, functionID)
	buildspecContent += fmt.Sprintf("      - docker tag fn-%s:latest %s/fn-%s:%s\n",
		functionID, ecrRepoURI, functionID, buildID)
	buildspecContent += fmt.Sprintf("      - docker tag fn-%s:latest %s/fn-%s:%s\n",
		functionID, ecrRepoURI, functionID, functionID)

	// Add post-build phase
	buildspecContent += `  
  post_build:
    commands:
      - echo "Post-build phase - Pushing images to ECR"
      - docker images
`
	// Add pushing commands - Use the function ID consistently in the repository name
	buildspecContent += fmt.Sprintf("      - docker push %s/fn-%s:latest\n", ecrRepoURI, functionID)
	buildspecContent += fmt.Sprintf("      - docker push %s/fn-%s:%s\n", ecrRepoURI, functionID, buildID)
	buildspecContent += fmt.Sprintf("      - docker push %s/fn-%s:%s\n", ecrRepoURI, functionID, functionID)

	// Add image detail files creation - IMPORTANT: Use function ID consistently in repository name
	buildspecContent += fmt.Sprintf("      - echo '{\"imageUri\":\"%s/fn-%s:latest\"}' > imageDetail.json\n",
		ecrRepoURI, functionID)
	buildspecContent += fmt.Sprintf("      - echo '{\"imageUri\":\"%s/fn-%s:%s\"}' > imageDetailWithBuildID.json\n",
		ecrRepoURI, functionID, buildID)
	buildspecContent += fmt.Sprintf("      - echo '{\"imageUri\":\"%s/fn-%s:%s\"}' > imageDetailWithFunctionID.json\n",
		ecrRepoURI, functionID, functionID)
	buildspecContent += `      - cat imageDetail.json
      - cat imageDetailWithBuildID.json
      - cat imageDetailWithFunctionID.json

artifacts:
  files:
    - imageDetail.json
    - imageDetailWithBuildID.json
    - imageDetailWithFunctionID.json
    - Dockerfile
    - debug.sh
    - function_id.txt
    - function_runtime.txt
    - function_handler.txt

cache:
  paths:
    - '/root/.npm/**/*'
    - '/root/.pip/**/*'`

	// Write buildspec.yml
	buildspecPath := filepath.Join(tempDir, "buildspec.yml")
	if err := os.WriteFile(buildspecPath, []byte(buildspecContent), 0644); err != nil {
		return fmt.Errorf("failed to write buildspec.yml: %w", err)
	}

	// Log the buildspec content for debugging
	c.logger.Debug().
		Str("buildspec_path", buildspecPath).
		Str("buildspec_content", buildspecContent).
		Msg("Created buildspec.yml")

	return nil
}

// createMetadataFiles creates metadata files for the build
func (c *CodeBuildClient) createMetadataFiles(tempDir string, opts *runtime.BuildImageOptions) error {
	c.logger.Debug().
		Str("temp_dir", tempDir).
		Msg("Creating metadata files")

	// Extract function ID from image name (assuming format: fn-functionID)
	functionID := strings.TrimPrefix(opts.ImageName, "fn-")
	if functionID == opts.ImageName {
		// If no prefix was removed, use the whole image name
		functionID = opts.ImageName
	}

	c.logger.Debug().
		Str("function_id", functionID).
		Str("image_name", opts.ImageName).
		Msg("Extracted function ID from image name")

	// Write function ID
	functionIDPath := filepath.Join(tempDir, "function_id.txt")
	if err := os.WriteFile(functionIDPath, []byte(functionID), 0644); err != nil {
		return fmt.Errorf("failed to write function_id.txt: %w", err)
	}

	// Write function runtime
	runtimePath := filepath.Join(tempDir, "function_runtime.txt")
	if err := os.WriteFile(runtimePath, []byte(string(opts.Runtime)), 0644); err != nil {
		return fmt.Errorf("failed to write function_runtime.txt: %w", err)
	}

	// Write function handler
	handlerPath := filepath.Join(tempDir, "function_handler.txt")
	if err := os.WriteFile(handlerPath, []byte(opts.Handler), 0644); err != nil {
		return fmt.Errorf("failed to write function_handler.txt: %w", err)
	}

	// Create a debug.sh script to help troubleshoot
	debugScriptPath := filepath.Join(tempDir, "debug.sh")
	debugScript := `#!/bin/bash
# Comprehensive debug script for AWS CodeBuild
# Set to exit on error and print commands
set -x

echo "==== START DEBUG INFO ===="
echo "Date: $(date)"
echo "Hostname: $(hostname)"
echo "OS Details: $(cat /etc/os-release 2>/dev/null || echo 'OS details not available')"

echo "==== DOCKER SERVICE STATUS ===="
# Check Docker daemon status in multiple ways
systemctl status docker || true
journalctl -u docker --no-pager -n 50 || true
ps aux | grep -i docker || true
ls -la /var/run/docker.sock || echo "Docker socket not found"
stat /var/run/docker.sock 2>/dev/null || echo "Cannot stat docker socket"
getent group docker || echo "Docker group not found"
id | grep docker || echo "Current user not in docker group"

echo "==== FILESYSTEM PERMISSIONS ===="
mount | grep -E 'noexec|nosuid' || echo "No restrictive mount options found"
ls -la /tmp/ | head -10 || echo "Cannot list /tmp"
ls -la /var/run/ | head -10 || echo "Cannot list /var/run"
ls -la / | head -10 || echo "Cannot list root directory"

echo "==== MEMORY & RESOURCES ===="
free -m || echo "free command failed"
cat /proc/meminfo 2>/dev/null | head -20 || echo "Cannot read meminfo"
cat /proc/cpuinfo 2>/dev/null | grep -E 'model name|processor' | head -5 || echo "Cannot read cpuinfo"
df -h || echo "df command failed"
ulimit -a || echo "ulimit command failed"

echo "==== NETWORK CONFIGURATION ===="
ifconfig || ip addr || echo "Network commands failed"
cat /etc/resolv.conf 2>/dev/null || echo "Cannot read resolv.conf"
ping -c 2 8.8.8.8 || echo "Cannot ping Google DNS"
netstat -tulpn || ss -tulpn || echo "Cannot show listening ports"
curl -v --max-time 5 https://docker.io || echo "Cannot connect to Docker Hub"

echo "==== DOCKER TESTS ===="
# Test if Docker works at all
docker version || echo "Docker version command failed"
docker info || echo "Docker info command failed"
docker ps || echo "Docker ps command failed"
docker images || echo "Docker images command failed"

# Test if Docker can run a simple container
echo "Trying to run a hello-world container:"
docker run --rm hello-world || echo "Docker hello-world failed with exit code $?"

# Try to debug any Docker socket issues
echo "Checking Docker socket permissions:"
sudo ls -la /var/run/docker.sock || ls -la /var/run/docker.sock || echo "Cannot access Docker socket"

echo "==== SELINUX & APPARMOR STATUS ===="
getenforce 2>/dev/null || echo "SELinux not detected"
sestatus 2>/dev/null || echo "SELinux status command not available"
aa-status 2>/dev/null || echo "AppArmor not detected"

echo "==== CODEBUILD ENVIRONMENT ===="
env | grep -i aws || echo "No AWS environment variables found"
env | grep -i docker || echo "No Docker environment variables found"
env | grep -i codebuild || echo "No CodeBuild environment variables found"

echo "==== SOURCE CODE ===="
echo "Directory structure:"
find . -type f -name "Dockerfile" -o -name "*.js" -o -name "*.py" -o -name "*.go" -o -name "*.json" | sort
echo "Current directory contents:"
ls -la

echo "==== BUILDSPEC AND DOCKERFILE ===="
echo "=== buildspec.yml ==="
cat buildspec.yml 2>/dev/null || echo "buildspec.yml not found"
echo "=== Dockerfile ==="
cat Dockerfile 2>/dev/null || echo "Dockerfile not found"

echo "==== FUNCTION INFO ===="
echo "Function ID: $(cat function_id.txt 2>/dev/null || echo 'Not found')"
echo "Runtime: $(cat function_runtime.txt 2>/dev/null || echo 'Not found')"
echo "Handler: $(cat function_handler.txt 2>/dev/null || echo 'Not found')"

echo "==== END DEBUG INFO ===="
`
	if err := os.WriteFile(debugScriptPath, []byte(debugScript), 0755); err != nil {
		return fmt.Errorf("failed to write debug.sh: %w", err)
	}

	c.logger.Debug().
		Str("function_id_path", functionIDPath).
		Str("runtime_path", runtimePath).
		Str("handler_path", handlerPath).
		Str("debug_script_path", debugScriptPath).
		Msg("Created metadata files")

	return nil
}

// createSourceZip creates a ZIP file of the build directory
func (c *CodeBuildClient) createSourceZip(sourceDir, outputPath string) error {
	c.logger.Debug().
		Str("source_dir", sourceDir).
		Str("output_path", outputPath).
		Msg("Creating source ZIP")

	// Create a new ZIP file
	zipFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create ZIP file: %w", err)
	}
	defer zipFile.Close()

	// Create a new ZIP writer
	zipWriter := zip.NewWriter(zipFile)
	defer zipWriter.Close()

	// Track files for debugging
	var files []string

	// Walk through the directory and add files to the ZIP
	err = filepath.Walk(sourceDir, func(filePath string, fileInfo os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip the output ZIP file itself
		if filePath == outputPath {
			return nil
		}

		// Create a new file header
		header, err := zip.FileInfoHeader(fileInfo)
		if err != nil {
			return fmt.Errorf("failed to create file header: %w", err)
		}

		// Set relative path
		relPath, err := filepath.Rel(sourceDir, filePath)
		if err != nil {
			return fmt.Errorf("failed to get relative path: %w", err)
		}

		// Use forward slashes for ZIP entries
		header.Name = strings.ReplaceAll(relPath, "\\", "/")

		// Set compression method
		header.Method = zip.Deflate

		// Skip directories in the ZIP
		if fileInfo.IsDir() {
			return nil
		}

		// Create file entry
		writer, err := zipWriter.CreateHeader(header)
		if err != nil {
			return fmt.Errorf("failed to create file entry: %w", err)
		}

		// Open source file
		file, err := os.Open(filePath)
		if err != nil {
			return fmt.Errorf("failed to open file: %w", err)
		}
		defer file.Close()

		// Copy content
		_, err = io.Copy(writer, file)
		if err != nil {
			return fmt.Errorf("failed to write file content: %w", err)
		}

		files = append(files, header.Name)
		return nil
	})

	if err != nil {
		return fmt.Errorf("failed to create ZIP: %w", err)
	}

	// Log the list of files added to the ZIP
	c.logger.Debug().
		Strs("files", files).
		Msg("Created source ZIP with files")

	// Get ZIP size for logging
	zipInfo, err := os.Stat(outputPath)
	if err == nil {
		c.logger.Debug().
			Int64("size", zipInfo.Size()).
			Msg("Source ZIP size")
	}

	return nil
}

// uploadToS3 uploads a file to S3
func (c *CodeBuildClient) uploadToS3(ctx context.Context, filePath, s3Key string) error {
	c.logger.Debug().
		Str("file_path", filePath).
		Str("s3_bucket", c.s3Bucket).
		Str("s3_key", s3Key).
		Msg("Uploading file to S3")

	// Open the file
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	// Get file size
	fileInfo, err := file.Stat()
	if err != nil {
		return fmt.Errorf("failed to get file info: %w", err)
	}

	// Use the upload manager for reliable uploads
	uploader := manager.NewUploader(c.s3Client)
	_, err = uploader.Upload(ctx, &s3.PutObjectInput{
		Bucket: aws.String(c.s3Bucket),
		Key:    aws.String(s3Key),
		Body:   file,
	})
	if err != nil {
		return fmt.Errorf("failed to upload to S3: %w", err)
	}

	c.logger.Info().
		Str("bucket", c.s3Bucket).
		Str("key", s3Key).
		Int64("size", fileInfo.Size()).
		Msg("File uploaded to S3")

	return nil
}

// startBuild starts a CodeBuild build
func (c *CodeBuildClient) startBuild(ctx context.Context, s3Key string, opts *runtime.BuildImageOptions) (string, error) {
	c.logger.Debug().
		Str("project_name", c.projectName).
		Str("s3_key", s3Key).
		Msg("Starting CodeBuild build")

	// Prepare environment variables
	envVars := []cbtypes.EnvironmentVariable{
		{
			Name:  aws.String("AWS_DEFAULT_REGION"),
			Value: aws.String(c.region),
			Type:  cbtypes.EnvironmentVariableTypePlaintext,
		},
		{
			Name:  aws.String("AWS_ACCOUNT_ID"),
			Value: aws.String(os.Getenv("AWS_ACCOUNT_ID")),
			Type:  cbtypes.EnvironmentVariableTypePlaintext,
		},
		{
			Name:  aws.String("DOCKER_BUILDKIT"),
			Value: aws.String("1"),
			Type:  cbtypes.EnvironmentVariableTypePlaintext,
		},
	}

	// Add function-specific environment variables
	if len(opts.Environment) > 0 {
		for _, env := range opts.Environment {
			envVars = append(envVars, cbtypes.EnvironmentVariable{
				Name:  aws.String(env.Key),
				Value: aws.String(env.Value),
				Type:  cbtypes.EnvironmentVariableTypePlaintext,
			})
		}
	}

	// Start the build
	buildInput := &codebuild.StartBuildInput{
		ProjectName:                  aws.String(c.projectName),
		SourceTypeOverride:           cbtypes.SourceTypeS3,
		SourceLocationOverride:       aws.String(fmt.Sprintf("%s/%s", c.s3Bucket, s3Key)),
		EnvironmentVariablesOverride: envVars,
	}

	// Log the full build input for debugging
	inputJSON, _ := json.MarshalIndent(buildInput, "", "  ")
	c.logger.Debug().
		RawJSON("build_input", inputJSON).
		Msg("CodeBuild start build input")

	// Start the build
	startResp, err := c.cbClient.StartBuild(ctx, buildInput)
	if err != nil {
		c.logger.Error().
			Err(err).
			Msg("Failed to start CodeBuild build")
		return "", fmt.Errorf("failed to start CodeBuild build: %w", err)
	}

	// Extract build ID
	if startResp.Build == nil || startResp.Build.Id == nil {
		return "", fmt.Errorf("received nil build ID from CodeBuild")
	}
	buildID := *startResp.Build.Id

	c.logger.Info().
		Str("build_id", buildID).
		Str("image", opts.ImageName).
		Msg("Started CodeBuild build")

	return buildID, nil
}

// waitForBuild waits for a CodeBuild build to complete
func (c *CodeBuildClient) waitForBuild(ctx context.Context, buildID string) (string, error) {
	c.logger.Info().
		Str("build_id", buildID).
		Msg("Waiting for CodeBuild build to complete")

	// Poll delay
	pollDelay := 5 * time.Second
	maxPolls := 60 // 5 minutes maximum wait time

	for i := 0; i < maxPolls; i++ {
		// Check if context is done
		select {
		case <-ctx.Done():
			return "", fmt.Errorf("context cancelled while waiting for build: %w", ctx.Err())
		default:
			// Continue
		}

		// Get build info
		resp, err := c.cbClient.BatchGetBuilds(ctx, &codebuild.BatchGetBuildsInput{
			Ids: []string{buildID},
		})
		if err != nil {
			c.logger.Error().
				Err(err).
				Str("build_id", buildID).
				Msg("Failed to get build status")
			return "", fmt.Errorf("failed to get build status: %w", err)
		}

		// Check for builds
		if len(resp.Builds) == 0 {
			c.logger.Warn().
				Str("build_id", buildID).
				Msg("No build found with the given ID")
			return "", fmt.Errorf("no build found with ID: %s", buildID)
		}

		// Get build status
		build := resp.Builds[0]
		status := build.BuildStatus
		if status == "" {
			c.logger.Warn().
				Str("build_id", buildID).
				Msg("Build status is empty")
			time.Sleep(pollDelay)
			continue
		}

		c.logger.Debug().
			Str("build_id", buildID).
			Str("status", string(status)).
			Int("poll_attempt", i+1).
			Msg("Current build status")

		// Check status
		switch status {
		case cbtypes.StatusTypeSucceeded:
			// Get the ECR image URI from the build output
			var imageURI string
			if build.Environment != nil && build.Environment.EnvironmentVariables != nil {
				for _, env := range build.Environment.EnvironmentVariables {
					if env.Name != nil && *env.Name == "AWS_ACCOUNT_ID" && env.Value != nil {
						accountID := *env.Value
						region := c.region
						// The image name is in the format: <accountID>.dkr.ecr.<region>.amazonaws.com/<imageName>:<functionID>
						// We need to extract the function ID from the BuildArtifacts
						if build.Artifacts != nil && build.Artifacts.Location != nil {
							// Parse the output artifact to get the image URI
							bucketName := ""
							keyPrefix := ""
							if strings.HasPrefix(*build.Artifacts.Location, "arn:") {
								// S3 ARN format
								parts := strings.Split(*build.Artifacts.Location, ":")
								if len(parts) > 5 {
									s3Parts := strings.SplitN(parts[5], "/", 2)
									if len(s3Parts) == 2 {
										bucketName = s3Parts[0]
										keyPrefix = s3Parts[1]
									}
								}
							} else {
								// Direct S3 path format
								parts := strings.SplitN(*build.Artifacts.Location, "/", 2)
								if len(parts) == 2 {
									bucketName = parts[0]
									keyPrefix = parts[1]
								}
							}

							// If we have bucket and key, try to get the imageDetail.json file
							if bucketName != "" && keyPrefix != "" {
								// First try to get imageDetailWithFunctionID.json (which has the most reliable tag for ECS)
								functionIDImageKey := keyPrefix + "/imageDetailWithFunctionID.json"
								functionIDResult, err := c.s3Client.GetObject(ctx, &s3.GetObjectInput{
									Bucket: aws.String(bucketName),
									Key:    aws.String(functionIDImageKey),
								})

								if err == nil && functionIDResult.Body != nil {
									defer functionIDResult.Body.Close()
									var functionIDImageDetail struct {
										ImageURI string `json:"imageUri"`
									}
									if err := json.NewDecoder(functionIDResult.Body).Decode(&functionIDImageDetail); err == nil && functionIDImageDetail.ImageURI != "" {
										imageURI = functionIDImageDetail.ImageURI
										c.logger.Info().
											Str("image_uri", imageURI).
											Msg("Found image URI in imageDetailWithFunctionID.json - using this as primary URI")
										break
									}
								}

								// If that fails, try to get imageDetailWithBuildID.json (second most reliable)
								buildIDImageKey := keyPrefix + "/imageDetailWithBuildID.json"
								buildIDResult, err := c.s3Client.GetObject(ctx, &s3.GetObjectInput{
									Bucket: aws.String(bucketName),
									Key:    aws.String(buildIDImageKey),
								})

								if err == nil && buildIDResult.Body != nil {
									defer buildIDResult.Body.Close()
									var buildIDImageDetail struct {
										ImageURI string `json:"imageUri"`
									}
									if err := json.NewDecoder(buildIDResult.Body).Decode(&buildIDImageDetail); err == nil && buildIDImageDetail.ImageURI != "" {
										imageURI = buildIDImageDetail.ImageURI
										c.logger.Info().
											Str("image_uri", imageURI).
											Msg("Found image URI in imageDetailWithBuildID.json - using this as secondary URI")
										break
									}
								}

								// Finally, try the standard imageDetail.json as a fallback
								imageDetailKey := keyPrefix + "/imageDetail.json"
								result, err := c.s3Client.GetObject(ctx, &s3.GetObjectInput{
									Bucket: aws.String(bucketName),
									Key:    aws.String(imageDetailKey),
								})
								if err == nil && result.Body != nil {
									defer result.Body.Close()
									var imageDetail struct {
										ImageURI string `json:"imageUri"`
									}
									if err := json.NewDecoder(result.Body).Decode(&imageDetail); err == nil && imageDetail.ImageURI != "" {
										imageURI = imageDetail.ImageURI
										c.logger.Info().
											Str("image_uri", imageURI).
											Msg("Found image URI in standard imageDetail.json - using as fallback")
									}
								}
							}
						}

						// If we still don't have imageURI, construct a default one
						if imageURI == "" {
							// If function ID is in the environment variables, use it
							functionID := ""
							for _, env := range build.Environment.EnvironmentVariables {
								if env.Name != nil && *env.Name == "FUNCTION_ID" && env.Value != nil {
									functionID = *env.Value
									break
								}
							}

							// If still not found, extract it from the buildspec or use a default
							if functionID == "" {
								// Try to extract from build ID as a fallback
								parts := strings.Split(buildID, ":")
								if len(parts) == 2 {
									functionID = parts[1]
								} else {
									functionID = "latest"
								}
							}

							imageURI = fmt.Sprintf("%s.dkr.ecr.%s.amazonaws.com/fn-%s:%s",
								accountID, region, functionID, functionID)
						}
						break
					}
				}
			}

			if imageURI == "" {
				c.logger.Warn().
					Str("build_id", buildID).
					Msg("Build succeeded but could not determine image URI")
				return "", fmt.Errorf("build succeeded but could not determine image URI")
			}

			c.logger.Info().
				Str("build_id", buildID).
				Str("image_uri", imageURI).
				Msg("Build completed successfully")
			return imageURI, nil

		case cbtypes.StatusTypeFailed, cbtypes.StatusTypeFault, cbtypes.StatusTypeTimedOut, cbtypes.StatusTypeStopped:
			// Extract build failure details
			failureDetails := "Unknown failure reason"
			logMessages := "No detailed logs were found or accessible."

			// Try to get more specific phase failure info
			if len(build.Phases) > 0 {
				for _, phase := range build.Phases {
					if phase.PhaseStatus == cbtypes.StatusTypeFailed && phase.PhaseType != "" {
						failureDetails = fmt.Sprintf("Failed during phase: %s", phase.PhaseType)
						if len(phase.Contexts) > 0 && phase.Contexts[0].Message != nil {
							failureDetails += fmt.Sprintf(" - %s", *phase.Contexts[0].Message)
						}
						break
					}
				}
			}

			// Check if log configuration exists
			if build.Logs != nil {
				logConfigured := false
				// Check for CloudWatch logs
				if build.Logs.CloudWatchLogs != nil && build.Logs.CloudWatchLogs.Status == cbtypes.LogsConfigStatusTypeEnabled &&
					build.Logs.CloudWatchLogs.GroupName != nil && build.Logs.CloudWatchLogs.StreamName != nil {
					logMessages = fmt.Sprintf("Check CloudWatch Logs: %s/%s",
						*build.Logs.CloudWatchLogs.GroupName,
						*build.Logs.CloudWatchLogs.StreamName)
					logConfigured = true
				}

				// Check for S3 logs
				if build.Logs.S3Logs != nil && build.Logs.S3Logs.Status == cbtypes.LogsConfigStatusTypeEnabled &&
					build.Logs.S3Logs.Location != nil {
					s3Location := *build.Logs.S3Logs.Location
					if logConfigured {
						logMessages += fmt.Sprintf(" | Also check S3 Logs: s3://%s", s3Location)
					} else {
						logMessages = fmt.Sprintf("Check S3 Logs: s3://%s", s3Location)
					}
					logConfigured = true
				}
				if !logConfigured {
					logMessages = "Logging appears to be disabled for this build."
				}
			} else {
				logMessages = "Log configuration details not available for this build."
			}

			// Log detailed build information for debugging
			buildJSON, _ := json.MarshalIndent(build, "", "  ")
			c.logger.Debug().
				RawJSON("build_details", buildJSON).
				Msg("Full build details of failed build")

			c.logger.Error().
				Str("build_id", buildID).
				Str("status", string(status)).
				Str("failure_details", failureDetails).
				Str("log_location_info", logMessages).
				Msg("Build failed")

			return "", fmt.Errorf("build failed with status %s: %s. %s",
				status, failureDetails, logMessages)

		case cbtypes.StatusTypeInProgress:
			c.logger.Debug().
				Str("build_id", buildID).
				Str("status", string(status)).
				Int("poll_attempt", i+1).
				Msg("Build in progress")
			time.Sleep(pollDelay)
			continue
		}
	}

	// Timeout
	c.logger.Error().
		Str("build_id", buildID).
		Int("max_polls", maxPolls).
		Dur("poll_delay", pollDelay).
		Msg("Build timed out")
	return "", fmt.Errorf("build timed out after %d polls", maxPolls)
}

// StartBuild starts a CodeBuild build
func (c *CodeBuildClient) StartBuild(ctx context.Context, sourceZipPath string, opts *runtime.BuildImageOptions) (string, string, error) {
	c.logger.Debug().
		Str("source_zip_path", sourceZipPath).
		Str("image_name", opts.ImageName).
		Msg("Starting CodeBuild build")

	// Upload source ZIP to S3
	sourceBucket := os.Getenv("CODEBUILD_SOURCE_BUCKET")
	if sourceBucket == "" {
		return "", "", fmt.Errorf("CODEBUILD_SOURCE_BUCKET environment variable is required")
	}

	// Extract function ID from image name (assuming format: fn-functionID)
	functionID := strings.TrimPrefix(opts.ImageName, "fn-")
	if functionID == opts.ImageName {
		// If no prefix was removed, use the whole image name
		functionID = opts.ImageName
	}

	sourceObjectKey := fmt.Sprintf("codebuild/source/source-%s.zip", functionID)

	// Open source ZIP file
	sourceZipFile, err := os.Open(sourceZipPath)
	if err != nil {
		return "", "", fmt.Errorf("failed to open source ZIP file: %w", err)
	}
	defer sourceZipFile.Close()

	// Upload to S3
	c.logger.Debug().
		Str("bucket", sourceBucket).
		Str("key", sourceObjectKey).
		Msg("Uploading source ZIP to S3")

	uploader := manager.NewUploader(c.s3Client)
	_, err = uploader.Upload(ctx, &s3.PutObjectInput{
		Bucket: aws.String(sourceBucket),
		Key:    aws.String(sourceObjectKey),
		Body:   sourceZipFile,
	})
	if err != nil {
		return "", "", fmt.Errorf("failed to upload source ZIP to S3: %w", err)
	}

	// Start build
	// Prepare environment variables
	envVars := []cbtypes.EnvironmentVariable{
		{
			Name:  aws.String("AWS_DEFAULT_REGION"),
			Value: aws.String(c.region),
			Type:  cbtypes.EnvironmentVariableTypePlaintext,
		},
		{
			Name:  aws.String("AWS_ACCOUNT_ID"),
			Value: aws.String(os.Getenv("AWS_ACCOUNT_ID")),
			Type:  cbtypes.EnvironmentVariableTypePlaintext,
		},
		{
			Name:  aws.String("DOCKER_BUILDKIT"),
			Value: aws.String("1"),
			Type:  cbtypes.EnvironmentVariableTypePlaintext,
		},
		{
			Name:  aws.String("FUNCTION_ID"),
			Value: aws.String(functionID),
			Type:  cbtypes.EnvironmentVariableTypePlaintext,
		},
		{
			Name:  aws.String("FUNCTION_RUNTIME"),
			Value: aws.String(string(opts.Runtime)),
			Type:  cbtypes.EnvironmentVariableTypePlaintext,
		},
		{
			Name:  aws.String("FUNCTION_HANDLER"),
			Value: aws.String(opts.Handler),
			Type:  cbtypes.EnvironmentVariableTypePlaintext,
		},
		{
			Name:  aws.String("IMAGE_NAME"),
			Value: aws.String(opts.ImageName),
			Type:  cbtypes.EnvironmentVariableTypePlaintext,
		},
	}

	c.logger.Debug().
		Str("project_name", c.projectName).
		Str("source_location", fmt.Sprintf("s3://%s/%s", sourceBucket, sourceObjectKey)).
		Msg("Starting build")

	input := &codebuild.StartBuildInput{
		ProjectName:                  aws.String(c.projectName),
		SourceTypeOverride:           cbtypes.SourceTypeS3,
		SourceLocationOverride:       aws.String(fmt.Sprintf("%s/%s", sourceBucket, sourceObjectKey)),
		EnvironmentVariablesOverride: envVars,
	}

	// Start the build
	result, err := c.cbClient.StartBuild(ctx, input)
	if err != nil {
		return "", "", fmt.Errorf("failed to start build: %w", err)
	}

	if result.Build == nil || result.Build.Id == nil {
		return "", "", fmt.Errorf("received nil build ID from CodeBuild")
	}

	buildID := *result.Build.Id
	buildARN := ""
	if result.Build.Arn != nil {
		buildARN = *result.Build.Arn
	}

	c.logger.Info().
		Str("build_id", buildID).
		Str("build_arn", buildARN).
		Msg("Build started")

	// Wait for build to complete
	time.Sleep(5 * time.Second) // Give it a moment to start

	c.logger.Debug().Msg("Waiting for build to complete")

	buildComplete := false
	var buildResult string
	var logMessages []string

	// Poll for build status every 5 seconds with timeout of 10 minutes
	timeout := time.After(10 * time.Minute)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for !buildComplete {
		select {
		case <-ticker.C:
			// Get build status
			buildInfo, err := c.cbClient.BatchGetBuilds(ctx, &codebuild.BatchGetBuildsInput{
				Ids: []string{buildID},
			})
			if err != nil {
				c.logger.Error().Err(err).Msg("Failed to get build status")
				continue
			}

			if len(buildInfo.Builds) == 0 {
				c.logger.Error().Msg("Build info not found")
				continue
			}

			build := buildInfo.Builds[0]
			currentPhase := ""
			if build.CurrentPhase != nil {
				currentPhase = *build.CurrentPhase
			}

			buildStatus := string(build.BuildStatus)

			c.logger.Debug().
				Str("build_id", buildID).
				Str("current_phase", currentPhase).
				Str("build_status", buildStatus).
				Msg("Build status update")

			// Try to get logs
			logs, logErr := c.getLogs(ctx, buildID)
			if logErr != nil {
				c.logger.Warn().Err(logErr).Msg("Failed to get build logs")
			} else {
				logMessages = logs
			}

			if buildStatus != string(cbtypes.StatusTypeInProgress) {
				buildComplete = true
				buildResult = buildStatus

				// Get more detailed logs now that the build is complete
				finalLogs, logErr := c.getLogs(ctx, buildID)
				if logErr != nil {
					c.logger.Warn().Err(logErr).Msg("Failed to get final build logs")
				} else {
					logMessages = finalLogs
				}
			}

		case <-timeout:
			c.logger.Error().Msg("Build timed out after 10 minutes")
			return "", "Build timed out after 10 minutes", fmt.Errorf("build timed out")
		}
	}

	// Process the result
	var imageUri string
	var errorMsg string

	switch buildResult {
	case string(cbtypes.StatusTypeSucceeded):
		imageUri = c.getImageUri(opts.ImageName)
		c.logger.Info().
			Str("image_uri", imageUri).
			Msg("Build succeeded")
	case string(cbtypes.StatusTypeFailed), string(cbtypes.StatusTypeFault), string(cbtypes.StatusTypeTimedOut), string(cbtypes.StatusTypeStopped):
		errorMsg = fmt.Sprintf("Build failed with status: %s", buildResult)
		if len(logMessages) > 0 {
			errorMsg = fmt.Sprintf("%s. Logs: %s", errorMsg, strings.Join(logMessages, "\n"))
		}
		c.logger.Error().
			Str("build_result", buildResult).
			Str("error", errorMsg).
			Msg("Build failed")
	default:
		errorMsg = fmt.Sprintf("Unknown build result: %s", buildResult)
		c.logger.Error().
			Str("build_result", buildResult).
			Msg("Unknown build result")
	}

	return imageUri, errorMsg, nil
}

// getLogs retrieves logs for a CodeBuild build
func (c *CodeBuildClient) getLogs(ctx context.Context, buildID string) ([]string, error) {
	c.logger.Debug().
		Str("build_id", buildID).
		Msg("Retrieving logs for build")

	// Get build info
	resp, err := c.cbClient.BatchGetBuilds(ctx, &codebuild.BatchGetBuildsInput{
		Ids: []string{buildID},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get build info: %w", err)
	}

	if len(resp.Builds) == 0 {
		return nil, fmt.Errorf("build info not found")
	}

	build := resp.Builds[0]

	// Check if logs are available
	if build.Logs == nil {
		return []string{"Logs not available in build information"}, nil
	}

	var logMessages []string

	// Try CloudWatch logs if available
	if build.Logs.CloudWatchLogs != nil &&
		build.Logs.CloudWatchLogs.Status == cbtypes.LogsConfigStatusTypeEnabled &&
		build.Logs.CloudWatchLogs.GroupName != nil &&
		build.Logs.CloudWatchLogs.StreamName != nil {

		logGroup := *build.Logs.CloudWatchLogs.GroupName
		logStream := *build.Logs.CloudWatchLogs.StreamName

		// Create CloudWatch Logs client using the AWS config from the same region
		cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(c.region))
		if err != nil {
			return []string{fmt.Sprintf("Failed to load AWS config: %v", err)}, nil
		}

		cwlClient := cloudwatchlogs.NewFromConfig(cfg)

		// Get logs from CloudWatch
		logsInput := &cloudwatchlogs.GetLogEventsInput{
			LogGroupName:  aws.String(logGroup),
			LogStreamName: aws.String(logStream),
			Limit:         aws.Int32(100), // Get last 100 messages
		}

		logsOutput, err := cwlClient.GetLogEvents(ctx, logsInput)
		if err != nil {
			c.logger.Warn().
				Err(err).
				Str("log_group", logGroup).
				Str("log_stream", logStream).
				Msg("Failed to get CloudWatch logs")

			logMessages = append(logMessages,
				fmt.Sprintf("Error retrieving CloudWatch logs from %s/%s: %v",
					logGroup, logStream, err))
		} else if logsOutput.Events != nil {
			for _, event := range logsOutput.Events {
				if event.Message != nil {
					logMessages = append(logMessages, *event.Message)
				}
			}
		}
	}

	// If no logs were found or accessible, add a reference to S3 logs if available
	if len(logMessages) == 0 && build.Logs.S3Logs != nil &&
		build.Logs.S3Logs.Status == cbtypes.LogsConfigStatusTypeEnabled &&
		build.Logs.S3Logs.Location != nil {

		s3Location := *build.Logs.S3Logs.Location
		logMessages = append(logMessages,
			fmt.Sprintf("No CloudWatch logs available. Check S3 logs at: s3://%s", s3Location))
	}

	// If still no logs, add a fallback message
	if len(logMessages) == 0 {
		logMessages = append(logMessages, "No logs were available for this build")
	}

	return logMessages, nil
}

// getImageUri constructs the ECR image URI
func (c *CodeBuildClient) getImageUri(imageName string) string {
	accountID := os.Getenv("AWS_ACCOUNT_ID")
	region := c.region

	if accountID == "" {
		c.logger.Warn().Msg("AWS_ACCOUNT_ID environment variable is not set")
		return ""
	}

	return fmt.Sprintf("%s.dkr.ecr.%s.amazonaws.com/%s:latest", accountID, region, imageName)
}
