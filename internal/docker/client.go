package docker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"io"
	"strings"

	"serverless-emulator/internal/config"
	"serverless-emulator/internal/types" // Add this import
	"serverless-emulator/pkg/logger"

	//"serverless-emulator/internal/worker"

	// ... other imports ...
	//"github.com/docker/docker/api/types" // Import types directly
	dockertypes "github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"

	//"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/registry"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"

	"serverless-emulator/internal/runtime" // Update import

	"encoding/base64"

	"github.com/docker/docker/pkg/archive"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
)

// Add the stringPtr helper function near the top of the file after the imports
func stringPtr(s string) *string {
	return &s
}

// Add this conversion function at the top level of the file
func convertToInternalBuildOptions(opts *runtime.BuildImageOptions) *BuildImageOptions {
	return &BuildImageOptions{
		ImageName:   opts.ImageName,
		CodePath:    opts.CodePath,
		Runtime:     opts.Runtime,
		Handler:     opts.Handler,
		Environment: opts.Environment,
		Timeout:     opts.Timeout,
		Memory:      opts.Memory,
		CPU:         opts.CPU,
		S3Client:    opts.S3Client,
		S3Bucket:    opts.S3Bucket,
	}
}

// Client wraps the Docker API client
type Client struct {
	docker    *client.Client
	ecsClient *ECSClient
	mode      string
	config    *config.DockerConfig
	logger    *logger.Logger
}

// NewClient creates a new Docker client
func NewClient(cfg *config.DockerConfig, logger *logger.Logger) (runtime.RuntimeClient, error) {
	// In ECS mode, we want to use an ECS client
	if cfg.Runtime.Mode == "ecs" {
		logger.Info().Msg("Using ECS client for Docker operations")

		// Initialize ECS client config
		ecsConfig := &ECSConfig{
			Cluster:                 cfg.Runtime.ECS.Cluster,
			Subnets:                 cfg.Runtime.ECS.Subnets,
			SecurityGroups:          cfg.Runtime.ECS.SecurityGroups,
			Region:                  cfg.Runtime.ECS.Region,
			TaskExecutionRoleArn:    cfg.Runtime.ECS.TaskExecutionRoleArn,
			TaskRoleArn:             cfg.Runtime.ECS.TaskRoleArn,
			DockerHubCredentialsArn: cfg.Runtime.ECS.DockerHubCredentialsArn,
			EFSFileSystemId:         cfg.Runtime.ECS.EFSFileSystemId,
			EFSAccessPointId:        cfg.Runtime.ECS.EFSAccessPointId,
		}

		return NewECSClient(ecsConfig, logger)
	}

	// For local Docker or other modes
	logger.Info().Str("mode", cfg.Runtime.Mode).Msg("Using local Docker client")

	// Create local Docker client with platform detection
	dockerClient, err := client.NewClientWithOpts(
		client.WithAPIVersionNegotiation(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create docker client: %w", err)
	}

	return &Client{
		docker: dockerClient,
		mode:   cfg.Runtime.Mode,
		config: cfg,
		logger: logger,
	}, nil
}

// Close closes the Docker client
func (c *Client) Close() error {
	return c.docker.Close()
}

// BuildImage builds a Docker image for the function
func (c *Client) BuildImage(ctx context.Context, opts *runtime.BuildImageOptions) error {
	c.logger.Debug().
		Str("image", opts.ImageName).
		Str("runtime", string(opts.Runtime)).
		Str("code_path", opts.CodePath).
		Str("handler", opts.Handler).
		Msg("Building function image")

	// Check if we should use AWS CodeBuild via environment variable
	useCodeBuild := os.Getenv("USE_CODEBUILD") == "true"

	// If CodeBuild is enabled via environment, log a message that it's not implemented in the client
	if useCodeBuild && c.mode == "ecs" {
		c.logger.Warn().
			Str("image", opts.ImageName).
			Msg("AWS CodeBuild integration enabled but not implemented for direct client. Use ECS mode.")
	}

	// Use the original Docker build logic
	c.logger.Info().
		Str("image", opts.ImageName).
		Msg("Using local Docker client to build image")

	// Create temp directory for function code
	tempDir, err := os.MkdirTemp("", "function-*")
	if err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer os.RemoveAll(tempDir)

	// Create a temporary zip file
	tempZipFile := filepath.Join(tempDir, "function.zip")

	// Check if the code path is an S3 path
	if strings.HasPrefix(opts.CodePath, "s3://") {
		c.logger.Debug().Str("s3_path", opts.CodePath).Msg("Found S3 path, downloading code file")

		// Extract bucket and key from S3 URL
		s3Path := strings.TrimPrefix(opts.CodePath, "s3://")
		parts := strings.SplitN(s3Path, "/", 2)
		if len(parts) != 2 {
			return fmt.Errorf("invalid S3 path format: %s", opts.CodePath)
		}

		s3Bucket := parts[0]
		s3Key := parts[1]

		c.logger.Debug().
			Str("s3_bucket", s3Bucket).
			Str("s3_key", s3Key).
			Msg("Parsed S3 path components")

		if opts.S3Client == nil {
			return fmt.Errorf("S3 client is required for S3 code paths")
		}

		// Download the file from S3
		codeBytes, err := opts.S3Client.DownloadFile(ctx, s3Key)
		if err != nil {
			return fmt.Errorf("failed to download code from S3: %w", err)
		}

		// Write the bytes to the temporary file
		if err := os.WriteFile(tempZipFile, codeBytes, 0644); err != nil {
			return fmt.Errorf("failed to write downloaded code to temp file: %w", err)
		}

		c.logger.Debug().
			Str("temp_zip_file", tempZipFile).
			Int("code_size", len(codeBytes)).
			Msg("Downloaded code from S3 to temporary file")
	} else {
		// Local file path
		tempZipFile = opts.CodePath
		c.logger.Debug().Str("local_path", tempZipFile).Msg("Using local code path")
	}

	// Extract function code to temp directory
	if err := extractZip(tempZipFile, tempDir); err != nil {
		return fmt.Errorf("failed to extract function code: %w", err)
	}

	// Add runner script directly to the temp directory
	runnerScript, err := getRunnerScript(opts.Runtime)
	if err != nil {
		return fmt.Errorf("failed to get runner script: %w", err)
	}

	runnerFilename := getRunnerFilename(opts.Runtime)
	if runnerFilename != "" {
		runnerPath := filepath.Join(tempDir, runnerFilename)
		if err := os.WriteFile(runnerPath, []byte(runnerScript), 0755); err != nil {
			return fmt.Errorf("failed to write runner script: %w", err)
		}
		c.logger.Debug().Str("runner_path", runnerPath).Msg("Added runner script to build context")
	}

	// Log the contents of the temp directory to verify code extraction
	c.logger.Debug().Str("temp_dir", tempDir).Msg("Created temp directory for function code")
	files, err := os.ReadDir(tempDir)
	if err != nil {
		c.logger.Error().Err(err).Str("temp_dir", tempDir).Msg("Failed to read temp directory")
	} else {
		fileNames := []string{}
		for _, file := range files {
			fileNames = append(fileNames, file.Name())
			// If this is index.js or main file for the function, log its contents
			if file.Name() == "index.js" || file.Name() == "main.go" || file.Name() == "main.py" || file.Name() == runnerFilename {
				content, err := os.ReadFile(filepath.Join(tempDir, file.Name()))
				if err != nil {
					c.logger.Error().Err(err).Str("file", file.Name()).Msg("Failed to read file content")
				} else {
					c.logger.Debug().
						Str("file", file.Name()).
						Str("content", string(content)).
						Msg("Function source code")
				}
			}
		}
		c.logger.Debug().Strs("files", fileNames).Msg("Contents of function code directory")
	}

	// Create Dockerfile in temp directory
	dockerfilePath := filepath.Join(tempDir, "Dockerfile")

	// Convert runtime options to internal type
	internalOpts := &BuildImageOptions{
		ImageName:   opts.ImageName,
		CodePath:    opts.CodePath,
		Runtime:     opts.Runtime,
		Handler:     opts.Handler,
		Environment: opts.Environment,
		Timeout:     opts.Timeout,
		Memory:      opts.Memory,
		CPU:         opts.CPU,
		S3Client:    opts.S3Client,
		S3Bucket:    opts.S3Bucket,
	}

	dockerfile, err := generateDockerfile(internalOpts)
	if err != nil {
		return fmt.Errorf("failed to generate Dockerfile: %w", err)
	}

	if err := os.WriteFile(dockerfilePath, []byte(dockerfile), 0644); err != nil {
		return fmt.Errorf("failed to write Dockerfile: %w", err)
	}

	c.logger.Debug().Msgf("Generated Dockerfile:\n%s", dockerfile)

	// Get AWS region from environment
	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = os.Getenv("AWS_DEFAULT_REGION")
		if region == "" {
			return fmt.Errorf("AWS_REGION or AWS_DEFAULT_REGION must be set")
		}
	}

	// Local image tag
	localImageTag := fmt.Sprintf("%s:latest", opts.ImageName)

	c.logger.Debug().
		Str("local_image_tag", localImageTag).
		Msg("Building with local image tag")

	// Pre-pull the base image for this architecture to ensure it exists
	baseImage := "node:18-alpine"
	if opts.Runtime == "python3.8" {
		baseImage = "python:3.8-alpine"
	} else if opts.Runtime == "go1.18" {
		baseImage = "golang:1.18-alpine"
	}

	c.logger.Info().Str("base_image", baseImage).Msg("Pulling base image before build")
	pullResp, err := c.docker.ImagePull(ctx, baseImage, dockertypes.ImagePullOptions{})
	if err != nil {
		c.logger.Warn().Err(err).Str("image", baseImage).Msg("Failed to pull base image, will try to build anyway")
	} else {
		io.Copy(io.Discard, pullResp)
		pullResp.Close()
		c.logger.Info().Str("base_image", baseImage).Msg("Successfully pulled base image")
	}

	// Disable BuildKit as it's causing issues
	os.Setenv("DOCKER_BUILDKIT", "0")

	// Check if we're running on ARM architecture
	isARM := false
	archCmd := exec.Command("uname", "-m")
	archOutput, err := archCmd.Output()
	if err == nil {
		arch := strings.TrimSpace(string(archOutput))
		isARM = strings.Contains(arch, "arm") || strings.Contains(arch, "aarch64")
		c.logger.Info().Str("architecture", arch).Bool("is_arm", isARM).Msg("Detected system architecture")
	}

	// On ARM Macs, always use CLI-based build with platform targeting
	if isARM {
		c.logger.Info().Msg("ARM architecture detected, using Docker CLI directly for cross-platform build")

		// Create direct docker build command with platform args
		buildCmd := exec.Command(
			"docker", "build",
			"--platform=linux/amd64",
			"-t", localImageTag,
			"-f", dockerfilePath,
			tempDir,
		)

		// Capture stdout and stderr
		var stdout, stderr bytes.Buffer
		buildCmd.Stdout = &stdout
		buildCmd.Stderr = &stderr

		// Log the command being run
		c.logger.Info().Str("command", buildCmd.String()).Msg("Running docker build command")

		// Run the command
		if err := buildCmd.Run(); err != nil {
			c.logger.Error().
				Err(err).
				Str("stderr", stderr.String()).
				Str("stdout", stdout.String()).
				Msg("Failed to build using direct Docker CLI")
			return fmt.Errorf("docker build command failed: %w", err)
		}

		c.logger.Info().
			Str("stdout", stdout.String()).
			Msg("Successfully built image using direct Docker CLI")

		// Verify the image exists
		verifyCmd := exec.Command("docker", "image", "inspect", localImageTag)
		if err := verifyCmd.Run(); err != nil {
			c.logger.Error().
				Err(err).
				Str("image", localImageTag).
				Msg("Image verification failed after CLI build")
			return fmt.Errorf("image build appeared to succeed but verification failed: %w", err)
		}

		c.logger.Info().
			Str("image", localImageTag).
			Msg("Successfully verified image exists after CLI build")

		// Skip ECR push if not in ECS mode
		if c.mode != "ecs" {
			return nil
		}

		// Initialize AWS config for ECR push
		awsCfg, err := awsconfig.LoadDefaultConfig(ctx,
			awsconfig.WithRegion(region),
		)
		if err != nil {
			c.logger.Warn().Err(err).Msg("Failed to load AWS config, ECS may not be able to pull the image")
			return nil
		}

		// Create ECR client
		ecrClient := ecr.NewFromConfig(awsCfg)

		// Get AWS account ID from the ECR repository
		result, err := ecrClient.GetAuthorizationToken(ctx, &ecr.GetAuthorizationTokenInput{})
		if err != nil {
			c.logger.Warn().Err(err).Msg("Failed to get ECR authorization token, skipping ECR push")
			return nil
		}

		if len(result.AuthorizationData) == 0 {
			c.logger.Warn().Msg("No ECR authorization data returned, skipping ECR push")
			return nil
		}

		// Extract registry URL from first auth data entry
		registryURL := *result.AuthorizationData[0].ProxyEndpoint
		registryURL = strings.TrimPrefix(registryURL, "https://")

		// Create the ECR repository URI
		ecrRepoURI := fmt.Sprintf("%s/%s", registryURL, opts.ImageName)

		// Tag the image for ECR
		tagCmd := exec.Command("docker", "tag", localImageTag, ecrRepoURI)
		var tagStdout, tagStderr bytes.Buffer
		tagCmd.Stdout = &tagStdout
		tagCmd.Stderr = &tagStderr

		if err := tagCmd.Run(); err != nil {
			c.logger.Error().
				Err(err).
				Str("stderr", tagStderr.String()).
				Msg("Failed to tag image for ECR")
			return fmt.Errorf("failed to tag image for ECR: %w", err)
		}

		c.logger.Info().
			Str("local_tag", localImageTag).
			Str("ecr_uri", ecrRepoURI).
			Msg("Successfully tagged image for ECR")

		// Login to ECR using the Docker CLI
		authToken, err := base64.StdEncoding.DecodeString(*result.AuthorizationData[0].AuthorizationToken)
		if err != nil {
			c.logger.Error().Err(err).Msg("Failed to decode ECR auth token")
			return fmt.Errorf("failed to decode ECR auth token: %w", err)
		}

		auth := strings.SplitN(string(authToken), ":", 2)
		if len(auth) != 2 {
			c.logger.Error().Msg("Invalid ECR auth token format")
			return fmt.Errorf("invalid ECR auth token format")
		}

		username, password := auth[0], auth[1]

		loginCmd := exec.Command("docker", "login", "--username", username, "--password-stdin", registryURL)
		loginCmd.Stdin = strings.NewReader(password)

		var loginStdout, loginStderr bytes.Buffer
		loginCmd.Stdout = &loginStdout
		loginCmd.Stderr = &loginStderr

		if err := loginCmd.Run(); err != nil {
			c.logger.Error().
				Err(err).
				Str("stderr", loginStderr.String()).
				Msg("Failed to login to ECR")
			return fmt.Errorf("failed to login to ECR: %w", err)
		}

		c.logger.Info().
			Str("registry", registryURL).
			Msg("Successfully logged in to ECR")

		// Push the image to ECR
		pushCmd := exec.Command("docker", "push", ecrRepoURI)
		var pushStdout, pushStderr bytes.Buffer
		pushCmd.Stdout = &pushStdout
		pushCmd.Stderr = &pushStderr

		if err := pushCmd.Run(); err != nil {
			c.logger.Error().
				Err(err).
				Str("stderr", pushStderr.String()).
				Msg("Failed to push image to ECR")
			return fmt.Errorf("failed to push image to ECR: %w", err)
		}

		c.logger.Info().
			Str("ecr_uri", ecrRepoURI).
			Msg("Successfully pushed image to ECR")

		return nil
	}

	// For non-ARM architectures, continue with the Docker API approach
	// Create build context
	buildContext, err := archive.TarWithOptions(tempDir, &archive.TarOptions{})
	if err != nil {
		return fmt.Errorf("failed to create build context: %w", err)
	}
	defer buildContext.Close()

	// Prepare build options with more debugging enabled
	buildOptions := dockertypes.ImageBuildOptions{
		Context:    buildContext,
		Dockerfile: "Dockerfile",
		Tags:       []string{localImageTag},
		Remove:     true,
		NoCache:    true,
		PullParent: true,
		// Add architecture-specific build args
		BuildArgs: map[string]*string{
			"TARGETARCH":     stringPtr("amd64"),
			"TARGETPLATFORM": stringPtr("linux/amd64"),
			"BUILDPLATFORM":  stringPtr("linux/amd64"),
		},
		// Use simpler build ID
		BuildID: fmt.Sprintf("serverless-%s", opts.ImageName),
		// Set platform explicitly
		Platform: "linux/amd64",
	}

	c.logger.Debug().
		Interface("build_options", buildOptions).
		Msg("Prepared build options")

	// For non-ARM architectures, try the Docker API first
	buildResponse, err := c.docker.ImageBuild(ctx, buildContext, buildOptions)
	if err != nil {
		c.logger.Info().Msg("Docker API build failed, falling back to Docker CLI")

		// Fall back to CLI build similar to ARM approach
		// Create direct docker build command with platform args
		buildCmd := exec.Command(
			"docker", "build",
			"--platform=linux/amd64",
			"-t", localImageTag,
			"-f", dockerfilePath,
			tempDir,
		)

		// Capture stdout and stderr
		var stdout, stderr bytes.Buffer
		buildCmd.Stdout = &stdout
		buildCmd.Stderr = &stderr

		// Run the command
		if err := buildCmd.Run(); err != nil {
			c.logger.Error().
				Err(err).
				Str("stderr", stderr.String()).
				Str("stdout", stdout.String()).
				Msg("Failed to build using direct Docker CLI")
			return fmt.Errorf("docker build command failed: %w", err)
		}

		c.logger.Info().
			Str("stdout", stdout.String()).
			Msg("Successfully built image using direct Docker CLI")

		// Verify the image exists
		verifyCmd := exec.Command("docker", "image", "inspect", localImageTag)
		if err := verifyCmd.Run(); err != nil {
			c.logger.Error().
				Err(err).
				Str("image", localImageTag).
				Msg("Image verification failed after CLI build")
			return fmt.Errorf("image build appeared to succeed but verification failed: %w", err)
		}

		c.logger.Info().
			Str("image", localImageTag).
			Msg("Successfully verified image exists after CLI build")

		return nil
	}

	// Handle the buildResponse
	defer buildResponse.Body.Close()

	// Read the entire build output for better debugging
	buildOutput, err := io.ReadAll(buildResponse.Body)
	if err != nil {
		return fmt.Errorf("error reading build output: %w", err)
	}

	buildOutputStr := string(buildOutput)
	c.logger.Debug().Msgf("Docker build output: %s", buildOutputStr)

	// Check for errors in the build output
	if strings.Contains(buildOutputStr, "\"error\"") {
		// Look for error messages in the JSON output
		for _, line := range strings.Split(buildOutputStr, "\n") {
			if strings.Contains(line, "\"error\"") {
				var errorLine struct {
					Error string `json:"error"`
				}
				if err := json.Unmarshal([]byte(line), &errorLine); err == nil && errorLine.Error != "" {
					c.logger.Error().Str("error", errorLine.Error).Msg("Build error")
					return fmt.Errorf("docker build failed: %s", errorLine.Error)
				}
			}
		}
		return fmt.Errorf("docker build encountered errors (see logs for details)")
	}

	// Verify the image was built using a more reliable method
	c.logger.Info().Str("image", localImageTag).Msg("Verifying image was built successfully")

	// Try multiple times to verify the image (with short delays)
	var imageInspect dockertypes.ImageInspect
	var inspectErr error

	for i := 0; i < 3; i++ {
		imageInspect, _, inspectErr = c.docker.ImageInspectWithRaw(ctx, localImageTag)
		if inspectErr == nil {
			break
		}
		c.logger.Warn().
			Err(inspectErr).
			Int("attempt", i+1).
			Str("image", localImageTag).
			Msg("Image not found yet, retrying...")
		time.Sleep(2 * time.Second)
	}

	if inspectErr != nil {
		c.logger.Error().Err(inspectErr).Str("image", localImageTag).Msg("Image not found after build")
		return fmt.Errorf("docker build completed but image not found: %s", localImageTag)
	}

	c.logger.Info().
		Str("image_id", imageInspect.ID).
		Str("tag", localImageTag).
		Msg("Successfully built image")

	return nil
}

// CreateContainer creates a new container for function execution
func (c *Client) CreateContainer(ctx context.Context, config *container.Config, hostConfig *container.HostConfig, name string) (container.CreateResponse, error) {
	if c.mode == "ecs" {
		return c.ecsClient.CreateContainer(ctx, config, hostConfig, name)
	}
	return c.docker.ContainerCreate(ctx, config, hostConfig, nil, nil, name)
}

// CreateContainerWithOptions is the old method, kept for compatibility with other parts of the code
func (c *Client) CreateContainerWithOptions(ctx context.Context, opts *CreateContainerOptions) (string, error) {
	c.logger.Debug().
		Str("image", opts.ImageName).
		Str("function_id", opts.FunctionID).
		Str("request_id", opts.RequestID).
		Msg("Creating container")

	// Format DockerHub username properly to match the image naming in BuildImage
	dockerHubUsername := strings.ToLower(strings.ReplaceAll(os.Getenv("DOCKERHUB_USERNAME"), "@", ""))
	imageName := fmt.Sprintf("%s/%s", dockerHubUsername, opts.ImageName)
	c.logger.Debug().
		Str("original_image", opts.ImageName).
		Str("full_image_name", imageName).
		Msg("Using full image name with DockerHub username prefix")

	// Prepare container configuration
	config := &container.Config{
		Image: imageName,
		Env:   prepareEnvironment(opts),
		Labels: map[string]string{
			"function_id": opts.FunctionID,
			"request_id":  opts.RequestID,
			"managed_by":  "serverless-emulator",
		},
	}

	// Host configuration with resource limits
	hostConfig := &container.HostConfig{
		Resources: container.Resources{
			Memory:    opts.Memory * 1024 * 1024, // Convert MB to bytes
			CPUPeriod: 100000,
			CPUQuota:  int64(opts.CPU * 100000),
		},
		NetworkMode: container.NetworkMode(c.config.NetworkName),
		AutoRemove:  true,
	}

	// Create container
	resp, err := c.CreateContainer(ctx, config, hostConfig, opts.RequestID)
	if err != nil {
		return "", err
	}

	return resp.ID, nil
}

// StartContainer starts a container
func (c *Client) StartContainer(ctx context.Context, containerID string) error {
	// Log container information before starting
	container, err := c.docker.ContainerInspect(ctx, containerID)
	if err != nil {
		c.logger.Warn().Err(err).Str("container_id", containerID).Msg("Failed to inspect container before starting")
	} else {
		c.logger.Debug().
			Str("container_id", containerID).
			Str("image", container.Config.Image).
			Strs("env", container.Config.Env).
			Strs("cmd", container.Config.Cmd).
			Msg("Starting container with configuration")
	}

	// Start the container
	if err := c.docker.ContainerStart(ctx, containerID, dockertypes.ContainerStartOptions{}); err != nil {
		c.logger.Error().Err(err).Str("container_id", containerID).Msg("Failed to start container")
		return fmt.Errorf("failed to start container: %w", err)
	}

	c.logger.Debug().Str("container_id", containerID).Msg("Container started successfully")
	return nil
}

// StopContainer stops a container
func (c *Client) StopContainer(ctx context.Context, containerID string) error {
	// Convert timeout to seconds as an integer
	timeoutSeconds := int(10)
	opts := container.StopOptions{
		Timeout: &timeoutSeconds,
	}
	if err := c.docker.ContainerStop(ctx, containerID, opts); err != nil {
		return fmt.Errorf("failed to stop container: %w", err)
	}
	return nil
}

// RemoveContainer removes a container
func (c *Client) RemoveContainer(ctx context.Context, containerID string) error {
	// Add debugging logs
	c.logger.Info().
		Str("container_id", containerID).
		Str("container_id_length", fmt.Sprintf("%d", len(containerID))).
		Str("client_mode", c.mode).
		Msg("RemoveContainer called in docker client")

	// If using ECS client, delegate to it
	if c.mode == "ecs" && c.ecsClient != nil {
		c.logger.Info().
			Str("container_id", containerID).
			Msg("Delegating to ECS client")
		return c.ecsClient.RemoveContainer(ctx, containerID)
	}

	// If we're using Docker mode
	c.logger.Info().
		Str("container_id", containerID).
		Msg("Using local Docker client to remove container")

	opts := dockertypes.ContainerRemoveOptions{
		RemoveVolumes: true,
		Force:         true,
	}
	if err := c.docker.ContainerRemove(ctx, containerID, opts); err != nil {
		return fmt.Errorf("failed to remove container: %w", err)
	}
	return nil
}

// ContainerLogs retrieves container logs as a ReadCloser
func (c *Client) ContainerLogs(ctx context.Context, containerID string) (io.ReadCloser, error) {
	opts := dockertypes.ContainerLogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Follow:     false,
	}

	logs, err := c.docker.ContainerLogs(ctx, containerID, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to get container logs: %w", err)
	}

	return logs, nil
}

// GetContainerLogs retrieves parsed container logs (can be used when you need separated stdout/stderr)
func (c *Client) GetContainerLogs(ctx context.Context, containerID string) (*ContainerLogs, error) {
	opts := dockertypes.ContainerLogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Follow:     false,
	}

	logs, err := c.docker.ContainerLogs(ctx, containerID, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to get container logs: %w", err)
	}
	defer logs.Close()

	// Split stdout and stderr
	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)
	if _, err := stdcopy.StdCopy(stdout, stderr, logs); err != nil {
		return nil, fmt.Errorf("failed to split container logs: %w", err)
	}

	return &ContainerLogs{
		Stdout: stdout.String(),
		Stderr: stderr.String(),
	}, nil
}

// ContainerWait waits for a container to finish
func (c *Client) ContainerWait(ctx context.Context, containerID string, condition container.WaitCondition) (<-chan types.ContainerWaitResponse, <-chan error) {
	// Create our custom channels
	statusCh := make(chan types.ContainerWaitResponse, 1)
	errCh := make(chan error, 1)

	c.logger.Debug().
		Str("container_id", containerID).
		Str("condition", string(condition)).
		Msg("Waiting for container to finish")

	// Get Docker's wait channels
	dockerStatusCh, dockerErrCh := c.docker.ContainerWait(ctx, containerID, condition)

	// Convert between types in a goroutine
	go func() {
		defer close(statusCh)
		defer close(errCh)

		select {
		case status := <-dockerStatusCh:
			// Convert Docker's response to our type
			customStatus := types.ContainerWaitResponse{
				StatusCode: status.StatusCode,
			}

			c.logger.Debug().
				Str("container_id", containerID).
				Int64("status_code", status.StatusCode).
				Msg("Container finished with status code")

			// Capture logs for non-zero exit codes
			if status.StatusCode != 0 {
				logsCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()

				logs, err := c.docker.ContainerLogs(logsCtx, containerID, dockertypes.ContainerLogsOptions{
					ShowStdout: true,
					ShowStderr: true,
					Tail:       "100",
				})
				if err == nil {
					defer logs.Close()
					// Capture stdout and stderr
					stdout := new(bytes.Buffer)
					stderr := new(bytes.Buffer)
					stdcopy.StdCopy(stdout, stderr, logs)

					c.logger.Error().
						Str("container_id", containerID).
						Int64("status_code", status.StatusCode).
						Str("stdout", stdout.String()).
						Str("stderr", stderr.String()).
						Msg("Container failed with non-zero exit code")
				} else {
					c.logger.Error().Err(err).Str("container_id", containerID).Msg("Failed to capture logs for failed container")
				}
			}

			if status.Error != nil {
				customStatus.Error = &struct {
					Message string `json:"Message"`
				}{
					Message: status.Error.Message,
				}
				c.logger.Error().
					Str("container_id", containerID).
					Str("error_message", status.Error.Message).
					Msg("Container wait returned an error")
			}
			statusCh <- customStatus
		case err := <-dockerErrCh:
			c.logger.Error().
				Err(err).
				Str("container_id", containerID).
				Msg("Error waiting for container")
			errCh <- err
		case <-ctx.Done():
			c.logger.Warn().
				Err(ctx.Err()).
				Str("container_id", containerID).
				Msg("Context cancelled while waiting for container")
			errCh <- ctx.Err()
		}
	}()

	return statusCh, errCh
}

// RemoveImage removes a Docker image
func (c *Client) RemoveImage(ctx context.Context, imageName string) error {
	_, err := c.docker.ImageRemove(ctx, imageName, dockertypes.ImageRemoveOptions{
		Force:         true,
		PruneChildren: true,
	})
	if err != nil {
		return fmt.Errorf("failed to remove image: %w", err)
	}
	return nil
}

// PruneImages removes unused images
func (c *Client) PruneImages(ctx context.Context) error {
	_, err := c.docker.ImagesPrune(ctx, filters.NewArgs())
	if err != nil {
		return fmt.Errorf("failed to prune images: %w", err)
	}
	return nil
}

// Ping checks Docker daemon connectivity
func (c *Client) Ping(ctx context.Context) error {
	_, err := c.docker.Ping(ctx)
	return err
}

// GetContainerStats gets container resource usage statistics
func (c *Client) GetContainerStats(ctx context.Context, containerID string) (*dockertypes.StatsJSON, error) {
	stats, err := c.docker.ContainerStats(ctx, containerID, false)
	if err != nil {
		return nil, fmt.Errorf("failed to get container stats: %w", err)
	}
	defer stats.Body.Close()

	var statsJSON dockertypes.StatsJSON
	if err := json.NewDecoder(stats.Body).Decode(&statsJSON); err != nil {
		return nil, fmt.Errorf("failed to decode container stats: %w", err)
	}

	return &statsJSON, nil
}

func prepareEnvironment(opts *CreateContainerOptions) []string {
	env := []string{
		fmt.Sprintf("FUNCTION_NAME=%s", opts.FunctionID),
		fmt.Sprintf("REQUEST_ID=%s", opts.RequestID),
		fmt.Sprintf("FUNCTION_HANDLER=%s", opts.Handler),
		fmt.Sprintf("FUNCTION_TIMEOUT=%d", opts.Timeout),
		fmt.Sprintf("FUNCTION_MEMORY=%d", opts.Memory),
	}

	// Add request data
	if opts.Payload != nil {
		env = append(env, fmt.Sprintf("FUNCTION_INPUT=%s", string(opts.Payload)))
	}

	// Add headers
	for k, v := range opts.Headers {
		env = append(env, fmt.Sprintf("HEADER_%s=%s", normalizeEnvKey(k), v))
	}

	// Add query parameters
	for k, v := range opts.QueryParams {
		env = append(env, fmt.Sprintf("QUERY_%s=%s", normalizeEnvKey(k), v))
	}

	// Add path parameters
	for k, v := range opts.PathParams {
		env = append(env, fmt.Sprintf("PATH_%s=%s", normalizeEnvKey(k), v))
	}

	// Add HTTP method
	env = append(env, fmt.Sprintf("HTTP_METHOD=%s", opts.Method))

	// Add custom environment variables
	for k, v := range opts.Environment {
		env = append(env, fmt.Sprintf("%s=%s", k, v))
	}

	return env
}

func normalizeEnvKey(key string) string {
	// Convert to uppercase and replace invalid characters
	return strings.ToUpper(strings.ReplaceAll(key, "-", "_"))
}

func convertBuildOptions(opts *runtime.BuildImageOptions) *BuildImageOptions {
	return &BuildImageOptions{
		ImageName:   opts.ImageName,
		CodePath:    opts.CodePath,
		Runtime:     opts.Runtime,
		Handler:     opts.Handler,
		Environment: opts.Environment,
		Timeout:     opts.Timeout,
		Memory:      opts.Memory,
		CPU:         opts.CPU,
		S3Client:    opts.S3Client,
		S3Bucket:    opts.S3Bucket,
	}
}

// Add this helper function
func (c *Client) verifyDockerHubAuth(ctx context.Context) error {
	username := os.Getenv("DOCKERHUB_USERNAME")
	password := os.Getenv("DOCKERHUB_PASSWORD")

	if username == "" || password == "" {
		return fmt.Errorf("Docker Hub credentials not found in environment")
	}

	c.logger.Debug().
		Str("username", username).
		Msg("Verifying Docker Hub authentication")

	authConfig := registry.AuthConfig{
		Username: username,
		Password: password,
	}

	_, err := c.docker.RegistryLogin(ctx, authConfig)
	return err
}

// IsDockerHubEnabled returns true if DockerHub is enabled in the configuration
func (c *Client) IsDockerHubEnabled() bool {
	// Check if DOCKERHUB_USERNAME is set
	username := os.Getenv("DOCKERHUB_USERNAME")
	return username != ""
}

// GetDockerHubUsername returns the DockerHub username from configuration
func (c *Client) GetDockerHubUsername() string {
	// Format username to match our existing implementation
	return strings.ToLower(strings.ReplaceAll(os.Getenv("DOCKERHUB_USERNAME"), "@", ""))
}

// ECS client implementation of these methods

// IsDockerHubEnabled for ECS client
func (e *ECSClient) IsDockerHubEnabled() bool {
	// We don't want to use DockerHub with ECS anymore
	return false
}

// GetDockerHubUsername for ECS client
func (e *ECSClient) GetDockerHubUsername() string {
	// This should be retrieved from environment or configuration
	return os.Getenv("DOCKERHUB_USERNAME")
}

// CleanupResources performs cleanup of resources based on the runtime mode
func (c *Client) CleanupResources(ctx context.Context) error {
	if c.config.Runtime.Mode == "ecs" {
		// Get the ECSClient instance from the factory
		ecsConfig := &ECSConfig{
			Cluster:                 c.config.Runtime.ECS.Cluster,
			Subnets:                 c.config.Runtime.ECS.Subnets,
			SecurityGroups:          c.config.Runtime.ECS.SecurityGroups,
			Region:                  c.config.Runtime.ECS.Region,
			TaskExecutionRoleArn:    c.config.Runtime.ECS.TaskExecutionRoleArn,
			TaskRoleArn:             c.config.Runtime.ECS.TaskRoleArn,
			DockerHubCredentialsArn: c.config.Runtime.ECS.DockerHubCredentialsArn,
			EFSFileSystemId:         c.config.Runtime.ECS.EFSFileSystemId,
			EFSAccessPointId:        c.config.Runtime.ECS.EFSAccessPointId,
		}

		ecsClient, err := NewECSClient(ecsConfig, c.logger)
		if err != nil {
			return fmt.Errorf("failed to create ECS client for cleanup: %w", err)
		}

		return ecsClient.CleanupResources(ctx)
	}

	// For local Docker, just prune images
	c.logger.Info().Msg("Cleaning up Docker resources")
	return c.PruneImages(ctx)
}

// Additional helper functions can be added here
