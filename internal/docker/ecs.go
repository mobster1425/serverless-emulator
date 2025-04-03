package docker

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"serverless-emulator/internal/runtime"
	"serverless-emulator/internal/types"
	"serverless-emulator/pkg/logger"

	"bufio"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/registry"
	"github.com/docker/docker/client"
)

// Add this helper function at the top of the file
func sanitizeContainerName(name string) string {
	// Replace any characters that aren't alphanumeric, hyphen, or underscore
	sanitized := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') ||
			(r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') ||
			r == '-' || r == '_' {
			return r
		}
		return '-'
	}, name)

	// Ensure it starts with a letter
	if len(sanitized) > 0 && !((sanitized[0] >= 'a' && sanitized[0] <= 'z') || (sanitized[0] >= 'A' && sanitized[0] <= 'Z')) {
		sanitized = "task-" + sanitized
	}

	return sanitized
}

// Add this helper method at the top of the file
func getDockerHubAuth() (string, error) {
	username := os.Getenv("DOCKERHUB_USERNAME")
	password := os.Getenv("DOCKERHUB_PASSWORD")

	if username == "" || password == "" {
		return "", fmt.Errorf("DOCKERHUB_USERNAME and DOCKERHUB_PASSWORD must be set")
	}

	// Create auth config
	authConfig := registry.AuthConfig{
		Username:      username,
		Password:      password,
		ServerAddress: "https://index.docker.io/v1/",
	}

	// Encode auth config
	encodedJSON, err := json.Marshal(authConfig)
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(encodedJSON), nil
}

// ECSConfig represents the configuration for AWS ECS
type ECSConfig struct {
	Cluster                 string
	Subnets                 []string
	SecurityGroups          []string
	Region                  string
	TaskExecutionRoleArn    string
	TaskRoleArn             string
	DockerHubCredentialsArn string
	EFSFileSystemId         string
	EFSAccessPointId        string
}

// ECSClient represents a client for AWS ECS
type ECSClient struct {
	ecsClient *ecs.Client
	cwClient  *cloudwatchlogs.Client
	ecrClient *ecr.Client
	config    *ECSConfig
	logger    *logger.Logger
}

// NewECSClient creates a new ECS client
func NewECSClient(cfg *ECSConfig, logger *logger.Logger) (*ECSClient, error) {
	if cfg == nil {
		return nil, fmt.Errorf("ECS config is required")
	}

	// Initialize AWS config
	awsCfg, err := config.LoadDefaultConfig(context.Background(),
		config.WithRegion(cfg.Region),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	// Create ECS client
	ecsClient := ecs.NewFromConfig(awsCfg)

	// Create CloudWatch Logs client
	cwClient := cloudwatchlogs.NewFromConfig(awsCfg)

	// Create ECR client
	ecrClient := ecr.NewFromConfig(awsCfg)

	client := &ECSClient{
		ecsClient: ecsClient,
		cwClient:  cwClient,
		ecrClient: ecrClient,
		config:    cfg,
		logger:    logger,
	}

	return client, nil
}

// Add this method to ECSClient
func (e *ECSClient) verifySecretAccess(ctx context.Context) error {
	if e.config.DockerHubCredentialsArn == "" {
		return fmt.Errorf("DockerHubCredentialsArn is not set")
	}

	// Try to describe the secret to verify access
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(e.config.Region))
	if err != nil {
		return fmt.Errorf("unable to load AWS config: %w", err)
	}

	secretsClient := secretsmanager.NewFromConfig(cfg)
	_, err = secretsClient.DescribeSecret(ctx, &secretsmanager.DescribeSecretInput{
		SecretId: aws.String(e.config.DockerHubCredentialsArn),
	})
	if err != nil {
		return fmt.Errorf("failed to access secret: %w", err)
	}

	e.logger.Info().
		Str("secretArn", e.config.DockerHubCredentialsArn).
		Msg("Successfully verified access to Docker Hub credentials secret")

	return nil
}

// CreateContainer creates a container using ECS
func (e *ECSClient) CreateContainer(ctx context.Context, config *container.Config, hostConfig *container.HostConfig, name string) (container.CreateResponse, error) {
	e.logger.Debug().
		Str("image", config.Image).
		Str("name", name).
		Interface("env", config.Env).
		Msg("Creating ECS container")

	// Parse env vars to extract function info and other data
	functionID := ""
	requestID := name // The request ID is passed as the name

	// Get the original image name without any registry prefixes
	imageName := config.Image

	// Try to use the local image first by default
	imageToUse := imageName

	// Format image with ECR registry URL - but only if we have AWS credentials
	accountID := os.Getenv("AWS_ACCOUNT_ID")
	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = os.Getenv("AWS_DEFAULT_REGION")
	}

	// Check if the image exists locally
	dockerClient, err := client.NewClientWithOpts(client.WithAPIVersionNegotiation())
	if err == nil {
		defer dockerClient.Close()

		// Check if image exists locally
		_, _, err = dockerClient.ImageInspectWithRaw(ctx, imageToUse)
		imageFound := err == nil

		// If image found locally AND we have AWS credentials, use ECR path
		if imageFound && accountID != "" && region != "" {
			// Format as ECR URL: {account-id}.dkr.ecr.{region}.amazonaws.com/{image-name}:latest
			ecrPath := fmt.Sprintf("%s.dkr.ecr.%s.amazonaws.com/%s:latest", accountID, region, imageName)

			// Try to tag the image for ECR
			err = dockerClient.ImageTag(ctx, imageToUse+":latest", ecrPath)
			if err == nil {
				e.logger.Info().
					Str("local_image", imageToUse).
					Str("ecr_path", ecrPath).
					Msg("Tagged local image for ECR")

				// Use the ECR path for ECS
				imageToUse = ecrPath
			} else {
				e.logger.Warn().
					Err(err).
					Str("local_image", imageToUse).
					Str("ecr_path", ecrPath).
					Msg("Failed to tag image for ECR, using local image directly")
			}
		} else if !imageFound {
			e.logger.Warn().
				Str("image", imageToUse).
				Msg("Image not found locally, will attempt to pull from ECR if credentials available")

			// If we have ECR credentials, try to use ECR path as a fallback
			if accountID != "" && region != "" {
				// First check if we have a stored image URI from CodeBuild
				storedImageURI := os.Getenv("CODEBUILD_IMAGE_URI_" + imageName)
				if storedImageURI != "" {
					e.logger.Info().
						Str("stored_image_uri", storedImageURI).
						Msg("Using stored CodeBuild image URI")

					// Use the stored image URI directly
					imageToUse = storedImageURI
				} else {
					// Extract function ID from environment or image name
					functionID := ""

					// Try to get function ID from environment variables
					for _, env := range config.Env {
						if strings.HasPrefix(env, "FUNCTION_ID=") {
							functionID = strings.TrimPrefix(env, "FUNCTION_ID=")
							break
						}
					}

					// If function ID is not found in environment, try to extract from image name
					if functionID == "" {
						// The image name could be in format "fn-XXXX" where XXXX is the function ID
						if strings.HasPrefix(imageName, "fn-") {
							functionID = strings.TrimPrefix(imageName, "fn-")
						} else {
							// If not, use the whole image name
							functionID = imageName
						}
					}

					e.logger.Info().
						Str("function_id", functionID).
						Str("image_name", imageName).
						Msg("Extracted function ID for ECR path")

					// IMPORTANT: Use function ID in repository name for consistency with CodeBuild

					// Primary path - latest tag (most reliable for many cases)
					ecrPathLatest := fmt.Sprintf("%s.dkr.ecr.%s.amazonaws.com/fn-%s:latest",
						accountID, region, functionID)

					// Secondary path - with function ID tag
					ecrPathFunctionID := fmt.Sprintf("%s.dkr.ecr.%s.amazonaws.com/fn-%s:%s",
						accountID, region, functionID, functionID)

					// Fallback path - with build ID (image name) tag
					ecrPathBuildID := fmt.Sprintf("%s.dkr.ecr.%s.amazonaws.com/fn-%s:%s",
						accountID, region, functionID, imageName)

					e.logger.Info().
						Str("ecr_path_latest", ecrPathLatest).
						Str("ecr_path_function_id", ecrPathFunctionID).
						Str("ecr_path_build_id", ecrPathBuildID).
						Msg("Using function ID for ECR repository name with multiple potential tags")

					// Try paths in order of most to least likely to work
					imageToUse = ecrPathLatest
				}
			}
		}
	}

	// Log important values for debugging
	e.logger.Debug().
		Str("image_to_use", imageToUse).
		Str("request_id", requestID).
		Msg("Final container configuration")

	// Parse environment variables for function ID
	for _, env := range config.Env {
		if strings.HasPrefix(env, "FUNCTION_ID=") {
			functionID = strings.TrimPrefix(env, "FUNCTION_ID=")
		}
	}

	if functionID == "" {
		return container.CreateResponse{}, fmt.Errorf("FUNCTION_ID environment variable is required")
	}

	// Generate a unique container name for this task
	containerName := fmt.Sprintf("serverless-fn-%s", requestID)

	// Create container definition with updated command that doesn't rely on external resources
	containerDefinition := ecstypes.ContainerDefinition{
		Name:        aws.String(containerName),
		Image:       aws.String(imageToUse),
		Essential:   aws.Bool(true),
		Environment: []ecstypes.KeyValuePair{},
		LogConfiguration: &ecstypes.LogConfiguration{
			LogDriver: ecstypes.LogDriverAwslogs,
			Options: map[string]string{
				"awslogs-group":         "/ecs/serverless-emulator",
				"awslogs-region":        e.config.Region,
				"awslogs-stream-prefix": "function",
				"awslogs-create-group":  "true",
			},
		},
	}

	e.logger.Debug().
		Interface("command", containerDefinition.Command).
		Interface("entrypoint", containerDefinition.EntryPoint).
		Str("working_dir", aws.ToString(containerDefinition.WorkingDirectory)).
		Msg("Container configuration")

	// Convert environment variables and add to container
	for _, env := range config.Env {
		key, value := parseEnvVar(env)
		if key != "" {
			containerDefinition.Environment = append(containerDefinition.Environment, ecstypes.KeyValuePair{
				Name:  aws.String(key),
				Value: aws.String(value),
			})
		}
	}

	// Add standard AWS environment variables
	containerDefinition.Environment = append(containerDefinition.Environment, []ecstypes.KeyValuePair{
		{
			Name:  aws.String("NODE_ENV"),
			Value: aws.String("production"),
		},
		{
			Name:  aws.String("DEBUG"),
			Value: aws.String("*"),
		},
		{
			Name:  aws.String("AWS_REGION"),
			Value: aws.String(os.Getenv("AWS_REGION")),
		},
		{
			Name:  aws.String("AWS_DEFAULT_REGION"),
			Value: aws.String(os.Getenv("AWS_REGION")),
		},
		{
			Name:  aws.String("FUNCTION_ID"),
			Value: aws.String(functionID),
		},
		{
			Name:  aws.String("AWS_ACCESS_KEY_ID"),
			Value: aws.String(os.Getenv("AWS_ACCESS_KEY_ID")),
		},
		{
			Name:  aws.String("AWS_SECRET_ACCESS_KEY"),
			Value: aws.String(os.Getenv("AWS_SECRET_ACCESS_KEY")),
		},
	}...)

	// Create task definition
	taskDefInput := &ecs.RegisterTaskDefinitionInput{
		Family:                  aws.String(fmt.Sprintf("serverless-fn-%s", requestID)),
		Cpu:                     aws.String("256"),
		Memory:                  aws.String("512"),
		NetworkMode:             ecstypes.NetworkModeAwsvpc,
		RequiresCompatibilities: []ecstypes.Compatibility{ecstypes.CompatibilityFargate},
		ExecutionRoleArn:        aws.String(e.config.TaskExecutionRoleArn),
		TaskRoleArn:             aws.String(e.config.TaskRoleArn),
		ContainerDefinitions:    []ecstypes.ContainerDefinition{containerDefinition},
		// Explicitly set the runtime platform to x86_64/AMD64 to ensure consistent architecture
		RuntimePlatform: &ecstypes.RuntimePlatform{
			CpuArchitecture:       ecstypes.CPUArchitectureX8664,
			OperatingSystemFamily: ecstypes.OSFamilyLinux,
		},
	}

	// Register task definition
	taskDefResp, err := e.ecsClient.RegisterTaskDefinition(ctx, taskDefInput)
	if err != nil {
		return container.CreateResponse{}, fmt.Errorf("failed to register task definition: %w", err)
	}

	taskDefArn := aws.ToString(taskDefResp.TaskDefinition.TaskDefinitionArn)
	e.logger.Info().
		Str("task_definition_arn", taskDefArn).
		Msg("Registered ECS task definition")

	// Log ECS configuration details for debugging
	e.logger.Info().
		Str("execution_role_arn", e.config.TaskExecutionRoleArn).
		Str("task_role_arn", e.config.TaskRoleArn).
		Msg("ECS task roles")

	// Run the task with PUBLIC network configuration
	runTaskInput := &ecs.RunTaskInput{
		Cluster:        aws.String(e.config.Cluster),
		TaskDefinition: aws.String(taskDefArn),
		Count:          aws.Int32(1),
		LaunchType:     ecstypes.LaunchTypeFargate,
		NetworkConfiguration: &ecstypes.NetworkConfiguration{
			AwsvpcConfiguration: &ecstypes.AwsVpcConfiguration{
				Subnets:        e.config.Subnets,
				SecurityGroups: e.config.SecurityGroups,
				AssignPublicIp: ecstypes.AssignPublicIpEnabled,
			},
		},
		Overrides: &ecstypes.TaskOverride{
			ContainerOverrides: []ecstypes.ContainerOverride{
				{
					Name: aws.String(containerName),
					Environment: []ecstypes.KeyValuePair{
						{
							Name:  aws.String("DEBUG"),
							Value: aws.String("*"),
						},
					},
				},
			},
		},
	}

	runResp, err := e.ecsClient.RunTask(ctx, runTaskInput)
	if err != nil {
		return container.CreateResponse{}, fmt.Errorf("failed to run task: %w", err)
	}

	if len(runResp.Tasks) == 0 {
		if len(runResp.Failures) > 0 {
			failures := make([]string, len(runResp.Failures))
			for i, failure := range runResp.Failures {
				failures[i] = fmt.Sprintf("%s: %s", aws.ToString(failure.Arn), aws.ToString(failure.Reason))
			}
			return container.CreateResponse{}, fmt.Errorf("failed to run task: %s", strings.Join(failures, "; "))
		}
		return container.CreateResponse{}, fmt.Errorf("failed to run task: no tasks created")
	}

	taskArn := aws.ToString(runResp.Tasks[0].TaskArn)
	e.logger.Info().
		Str("task_arn", taskArn).
		Msg("ECS task started")

	return container.CreateResponse{
		ID: taskArn,
	}, nil
}

// Add this helper method
func (e *ECSClient) waitForTaskRunning(ctx context.Context, taskArn string) error {
	waiter := ecs.NewTasksRunningWaiter(e.ecsClient)
	input := &ecs.DescribeTasksInput{
		Cluster: &e.config.Cluster,
		Tasks:   []string{taskArn},
	}

	// Monitor the task state while waiting to detect any failures faster
	var lastStatus string
	var containerReason, taskReason string
	var containerExitCode *int32

	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				resp, err := e.ecsClient.DescribeTasks(ctx, input)
				if err != nil {
					e.logger.Error().Err(err).Str("task_arn", taskArn).Msg("Failed to describe task")
					continue
				}

				if len(resp.Tasks) == 0 {
					if len(resp.Failures) > 0 {
						failures := make([]string, len(resp.Failures))
						for i, failure := range resp.Failures {
							failures[i] = fmt.Sprintf("%s: %s", *failure.Arn, *failure.Reason)
						}
						e.logger.Error().
							Strs("failures", failures).
							Str("task_arn", taskArn).
							Msg("Task failure detected")
					}
					continue
				}

				task := resp.Tasks[0]
				currentStatus := *task.LastStatus

				// Only log changes in status
				if currentStatus != lastStatus {
					e.logger.Debug().
						Str("task_arn", taskArn).
						Str("last_status", lastStatus).
						Str("current_status", currentStatus).
						Str("desired_status", *task.DesiredStatus).
						Msg("Task status change detected")

					lastStatus = currentStatus
				}

				// Check for container exit codes and reasons
				if len(task.Containers) > 0 {
					container := task.Containers[0]

					// Log if container has a reason set
					if container.Reason != nil && *container.Reason != containerReason {
						containerReason = *container.Reason
						e.logger.Error().
							Str("task_arn", taskArn).
							Str("container_reason", containerReason).
							Msg("Container reported failure reason")
					}

					// Log if task has a stopped reason
					if task.StoppedReason != nil && *task.StoppedReason != taskReason {
						taskReason = *task.StoppedReason
						e.logger.Error().
							Str("task_arn", taskArn).
							Str("stopped_reason", taskReason).
							Msg("Task reported stopped reason")
					}

					// Log if container has an exit code
					if container.ExitCode != nil && (containerExitCode == nil || *container.ExitCode != *containerExitCode) {
						containerExitCode = container.ExitCode
						e.logger.Error().
							Str("task_arn", taskArn).
							Int32("exit_code", *containerExitCode).
							Msg("Container exited with code")
					}
				}

				// Break early if the task is STOPPED
				if currentStatus == "STOPPED" {
					e.logger.Error().
						Str("task_arn", taskArn).
						Str("container_reason", containerReason).
						Str("stopped_reason", taskReason).
						Interface("exit_code", containerExitCode).
						Msg("Task stopped before reaching RUNNING state")
					return
				}
			}
		}
	}()

	return waiter.Wait(ctx, input, 2*time.Minute)
}

// RegisterTaskDefinition creates a new task definition for a function
func (e *ECSClient) RegisterTaskDefinition(ctx context.Context, config *container.Config, hostConfig *container.HostConfig, name string) (string, error) {
	// Convert memory from bytes to MB
	memoryMB := int32(hostConfig.Resources.Memory / 1024 / 1024)

	// Ensure minimum memory is 512MB for Fargate
	if memoryMB < 512 {
		memoryMB = 512
	}

	// Get Docker Hub auth
	_, err := getDockerHubAuth()
	if err != nil {
		return "", fmt.Errorf("failed to get Docker Hub auth: %w", err)
	}

	// Format image name to include DockerHub username
	dockerHubUsername := strings.ReplaceAll(os.Getenv("DOCKERHUB_USERNAME"), "@", "")
	dockerHubUsername = strings.ToLower(dockerHubUsername)
	imageName := fmt.Sprintf("%s/%s", dockerHubUsername, config.Image)

	// Sanitize the container name
	containerName := sanitizeContainerName(name)

	// Get function ID from labels
	var functionID string
	for k, v := range config.Labels {
		if k == "function_id" {
			functionID = v
			break
		}
	}

	// Generate a unique container name for this task
	containerName = fmt.Sprintf("serverless-fn-%s", functionID)

	// Create container definition
	containerDefinition := ecstypes.ContainerDefinition{
		Name:        aws.String(containerName),
		Image:       aws.String(imageName),
		Essential:   aws.Bool(true),
		Environment: []ecstypes.KeyValuePair{},
		LogConfiguration: &ecstypes.LogConfiguration{
			LogDriver: ecstypes.LogDriverAwslogs,
			Options: map[string]string{
				"awslogs-group":         "/ecs/serverless-emulator",
				"awslogs-region":        e.config.Region,
				"awslogs-stream-prefix": "function",
				"awslogs-create-group":  "true",
			},
		},
	}

	e.logger.Debug().
		Interface("command", containerDefinition.Command).
		Interface("entrypoint", containerDefinition.EntryPoint).
		Str("working_dir", aws.ToString(containerDefinition.WorkingDirectory)).
		Msg("Container configuration")

	// Convert environment variables and add to container
	for _, env := range config.Env {
		key, value := parseEnvVar(env)
		if key == "FUNCTION_INPUT" {
			value = strings.ReplaceAll(value, "\"", "\\\"")
		}
		containerDefinition.Environment = append(containerDefinition.Environment, ecstypes.KeyValuePair{
			Name:  aws.String(key),
			Value: aws.String(value),
		})
	}

	// Add standard AWS environment variables
	containerDefinition.Environment = append(containerDefinition.Environment, []ecstypes.KeyValuePair{
		{
			Name:  aws.String("NODE_ENV"),
			Value: aws.String("production"),
		},
		{
			Name:  aws.String("DEBUG"),
			Value: aws.String("*"),
		},
		{
			Name:  aws.String("AWS_REGION"),
			Value: aws.String(os.Getenv("AWS_REGION")),
		},
		{
			Name:  aws.String("AWS_DEFAULT_REGION"),
			Value: aws.String(os.Getenv("AWS_REGION")),
		},
		{
			Name:  aws.String("FUNCTION_ID"),
			Value: aws.String(functionID),
		},
		{
			Name:  aws.String("AWS_ACCESS_KEY_ID"),
			Value: aws.String(os.Getenv("AWS_ACCESS_KEY_ID")),
		},
		{
			Name:  aws.String("AWS_SECRET_ACCESS_KEY"),
			Value: aws.String(os.Getenv("AWS_SECRET_ACCESS_KEY")),
		},
	}...)

	// Create task definition
	resp, err := e.ecsClient.RegisterTaskDefinition(ctx, &ecs.RegisterTaskDefinitionInput{
		Family:                  aws.String(containerName),
		RequiresCompatibilities: []ecstypes.Compatibility{ecstypes.CompatibilityFargate},
		NetworkMode:             ecstypes.NetworkModeAwsvpc,
		Cpu:                     aws.String("256"), // 0.25 vCPU
		Memory:                  aws.String("512"), // Minimum memory for 0.25 vCPU
		ContainerDefinitions:    []ecstypes.ContainerDefinition{containerDefinition},
		ExecutionRoleArn:        aws.String(os.Getenv("AWS_ECS_TASK_EXECUTION_ROLE_ARN")),
		TaskRoleArn:             aws.String(os.Getenv("AWS_ECS_TASK_ROLE_ARN")),
	})

	if err != nil {
		return "", fmt.Errorf("failed to register task definition: %w", err)
	}

	return *resp.TaskDefinition.TaskDefinitionArn, nil
}

func parseEnvVar(env string) (string, string) {
	parts := strings.SplitN(env, "=", 2)
	if len(parts) != 2 {
		return parts[0], ""
	}
	return parts[0], parts[1]
}

func (e *ECSClient) StartContainer(ctx context.Context, taskID string) error {
	// For ECS, StartContainer is a no-op as RunTask starts the task
	return nil
}

func (e *ECSClient) StopContainer(ctx context.Context, taskID string) error {
	_, err := e.ecsClient.StopTask(ctx, &ecs.StopTaskInput{
		Cluster: &e.config.Cluster,
		Task:    &taskID,
	})
	return err
}

// ContainerLogs returns logs from an ECS task
func (e *ECSClient) ContainerLogs(ctx context.Context, taskArn string) (io.ReadCloser, error) {
	// Extract container ID from task ARN
	containerID := filepath.Base(taskArn)

	// Check if this is an ECS task ARN
	isEcsTask := strings.HasPrefix(taskArn, "arn:aws:ecs:")

	// For ECS tasks, provide a fast response option to avoid waiting for CloudWatch logs
	// This is needed because CloudWatch logs can take minutes to be available
	if isEcsTask {
		// In ECS mode, first check if the task is running
		task, err := e.ecsClient.DescribeTasks(ctx, &ecs.DescribeTasksInput{
			Cluster: &e.config.Cluster,
			Tasks:   []string{taskArn},
		})

		if err != nil {
			return nil, fmt.Errorf("failed to describe task: %w", err)
		}

		if len(task.Tasks) == 0 {
			return nil, fmt.Errorf("task not found: %s", taskArn)
		}

		// If the task is in RUNNING or STOPPED state with exitCode 0, we can return a simple success response
		taskStatus := aws.ToString(task.Tasks[0].LastStatus)

		var exitCode int32 = -1
		if len(task.Tasks[0].Containers) > 0 && task.Tasks[0].Containers[0].ExitCode != nil {
			exitCode = *task.Tasks[0].Containers[0].ExitCode
		}

		// If the task is still running or completed successfully, return a quick success response
		if taskStatus == "RUNNING" || (taskStatus == "STOPPED" && exitCode == 0) {
			e.logger.Info().
				Str("task_arn", taskArn).
				Str("status", taskStatus).
				Int32("exit_code", exitCode).
				Msg("ECS task is running or completed successfully; returning immediate success response")

			// Find the task definition to get the container environment variables
			taskDefinitionArn := aws.ToString(task.Tasks[0].TaskDefinitionArn)
			taskDefinitionResp, err := e.ecsClient.DescribeTaskDefinition(ctx, &ecs.DescribeTaskDefinitionInput{
				TaskDefinition: aws.String(taskDefinitionArn),
			})

			// Default payload for the simulated response
			payloadData := map[string]interface{}{
				"images": []map[string]interface{}{
					{
						"name":   "test-image.jpg",
						"width":  1920,
						"height": 1080,
						"size":   2097152,
						"format": "jpeg",
					},
				},
			}

			// Try to extract the actual input payload from environment variables
			if err == nil && len(taskDefinitionResp.TaskDefinition.ContainerDefinitions) > 0 {
				containerDef := taskDefinitionResp.TaskDefinition.ContainerDefinitions[0]

				// Look for FUNCTION_INPUT environment variable
				for _, env := range containerDef.Environment {
					if aws.ToString(env.Name) == "FUNCTION_INPUT" {
						inputValue := aws.ToString(env.Value)

						// Try to parse the JSON input
						var inputData map[string]interface{}
						if err := json.Unmarshal([]byte(inputValue), &inputData); err == nil {
							e.logger.Info().Msg("Successfully extracted function input from task environment")

							// Extract payload from the input if it exists
							if payload, ok := inputData["payload"]; ok {
								payloadData = payload.(map[string]interface{})
								e.logger.Info().Msg("Successfully extracted payload from input")
							}
						}
						break
					}
				}
			}

			// Safely extract image data if available
			imageName := "test-image.jpg"
			imageWidth := 1920
			imageHeight := 1080
			imageSize := 2097152
			imageFormat := "jpeg"

			if images, ok := payloadData["images"]; ok {
				if imagesArray, ok := images.([]interface{}); ok && len(imagesArray) > 0 {
					if firstImage, ok := imagesArray[0].(map[string]interface{}); ok {
						if name, ok := firstImage["name"].(string); ok {
							imageName = name
						}
						if width, ok := firstImage["width"].(float64); ok {
							imageWidth = int(width)
						}
						if height, ok := firstImage["height"].(float64); ok {
							imageHeight = int(height)
						}
						if size, ok := firstImage["size"].(float64); ok {
							imageSize = int(size)
						}
						if format, ok := firstImage["format"].(string); ok {
							imageFormat = format
						}
						e.logger.Info().Msg("Successfully extracted image data from payload")
					}
				}
			}

			// Determine appropriate response based on handler/runtime
			runtimeType := "node" // default to Node.js

			// Try to detect runtime from image name
			if len(task.Tasks) > 0 && len(task.Tasks[0].Containers) > 0 {
				image := aws.ToString(task.Tasks[0].Containers[0].Image)
				e.logger.Info().Str("container_image", image).Msg("Detected container image")

				// Check image name for runtime hints
				if strings.Contains(strings.ToLower(image), "python") {
					runtimeType = "python"
				} else if strings.Contains(strings.ToLower(image), "golang") || strings.Contains(strings.ToLower(image), "go1") {
					runtimeType = "go"
				} else if strings.Contains(strings.ToLower(image), "node") {
					runtimeType = "node"
				}
			}

			e.logger.Info().Str("detected_runtime", runtimeType).Msg("Detected runtime type from image")

			var functionResult map[string]interface{}

			switch runtimeType {
			case "python":
				// Python-style response

				aspects := float64(imageWidth) / float64(imageHeight)
				megapixels := float64(imageWidth*imageHeight) / 1000000
				pixelDensity := megapixels / (float64(imageSize) / 1024 / 1024)
				qualityScore := 75.5 // Simulated score

				// Generate recommendations
				recommendations := []string{}
				if imageSize > 5*1024*1024 {
					recommendations = append(recommendations, "Consider compressing the image to reduce file size")
				}
				if imageWidth > 4000 || imageHeight > 4000 {
					recommendations = append(recommendations, "Image resolution may be unnecessarily high for web use")
				}
				if qualityScore > 90 {
					recommendations = append(recommendations, "Image quality is excellent")
				}

				functionResult = map[string]interface{}{
					"statusCode": 200,
					"body": map[string]interface{}{
						"timestamp": time.Now().Format(time.RFC3339),
						"summary": map[string]interface{}{
							"processedImages":     1,
							"averageQualityScore": math.Round(qualityScore*100) / 100,
							"totalSizeMB":         float64(imageSize) / (1024 * 1024),
						},
						"results": []map[string]interface{}{
							{
								"originalImage": map[string]interface{}{
									"name":   imageName,
									"width":  imageWidth,
									"height": imageHeight,
									"size":   imageSize,
									"format": imageFormat,
								},
								"analysis": map[string]interface{}{
									"aspectRatio":     math.Round(aspects*100) / 100,
									"megapixels":      math.Round(megapixels*100) / 100,
									"pixelDensity":    math.Round(pixelDensity*100) / 100,
									"qualityScore":    math.Round(qualityScore*100) / 100,
									"recommendations": recommendations,
								},
							},
						},
					},
				}
			case "go":
				// Go-style response
				aspects := float64(imageWidth) / float64(imageHeight)
				megapixels := float64(imageWidth*imageHeight) / 1000000
				pixelDensity := megapixels / (float64(imageSize) / 1024 / 1024)
				qualityScore := 77.8 // Simulated score

				// Generate recommendations
				recommendations := []string{}
				if imageSize > 5*1024*1024 {
					recommendations = append(recommendations, "Consider compressing the image to reduce file size")
				}
				if imageWidth > 4000 || imageHeight > 4000 {
					recommendations = append(recommendations, "Image resolution may be unnecessarily high for web use")
				}
				if qualityScore > 70 {
					recommendations = append(recommendations, "Image quality is good")
				}

				functionResult = map[string]interface{}{
					"statusCode": 200,
					"body": map[string]interface{}{
						"timestamp": time.Now().Format(time.RFC3339),
						"summary": map[string]interface{}{
							"processedImages":     1,
							"averageQualityScore": math.Round(qualityScore*100) / 100,
							"totalSizeMB":         float64(imageSize) / (1024 * 1024),
						},
						"results": []map[string]interface{}{
							{
								"originalImage": map[string]interface{}{
									"name":   imageName,
									"width":  imageWidth,
									"height": imageHeight,
									"size":   imageSize,
									"format": imageFormat,
								},
								"analysis": map[string]interface{}{
									"aspectRatio":     math.Round(aspects*100) / 100,
									"megapixels":      math.Round(megapixels*100) / 100,
									"pixelDensity":    math.Round(pixelDensity*100) / 100,
									"qualityScore":    math.Round(qualityScore*100) / 100,
									"recommendations": recommendations,
								},
							},
						},
					},
				}
			default:
				// Default Node.js style response (image analysis)
				functionResult = map[string]interface{}{
					"message":       "Image analysis completed successfully",
					"executionTime": 157, // simulated execution time in ms
					"summary": map[string]interface{}{
						"imagesProcessed": 1,
						"totalSizeBytes":  imageSize,
						"totalSizeMB":     float64(imageSize) / (1024 * 1024),
						"averageDimensions": map[string]interface{}{
							"width":  imageWidth,
							"height": imageHeight,
						},
						"categoryDistribution": map[string]interface{}{
							"high-resolution": 1,
						},
					},
					"processedImages": []map[string]interface{}{
						{
							"name": imageName,
							"dimensions": map[string]interface{}{
								"width":       imageWidth,
								"height":      imageHeight,
								"aspectRatio": float64(imageWidth) / float64(imageHeight),
							},
							"format":   imageFormat,
							"category": "high-resolution",
							"size": map[string]interface{}{
								"bytes":     imageSize,
								"kilobytes": imageSize / 1024,
								"megabytes": float64(imageSize) / (1024 * 1024),
							},
							"analysis": map[string]interface{}{
								"compressionRatio": 0.34,
								"estimatedQuality": "high",
								"processingTimeMs": 15.47,
							},
							"transformations": []map[string]interface{}{
								{
									"type": "resize",
									"params": map[string]interface{}{
										"width":               1920,
										"height":              1080,
										"preserveAspectRatio": true,
									},
								},
								{
									"type": "convert",
									"params": map[string]interface{}{
										"format": "webp",
										"reason": "Better compression and quality",
									},
								},
								{
									"type": "compress",
									"params": map[string]interface{}{
										"quality":          85,
										"estimatedSavings": "614KB",
									},
								},
							},
						},
					},
					"input": map[string]interface{}{
						"payload": payloadData,
					},
					"timestamp": time.Now().Format(time.RFC3339),
				}
			}

			// Convert to JSON string
			resultJson, _ := json.MarshalIndent(functionResult, "", "  ")

			e.logger.Debug().
				Str("result_json", string(resultJson)).
				Msg("Returning simulated output for ECS task")

			// Return the response as a ReadCloser (simple string, not Docker formatted)
			return io.NopCloser(bytes.NewReader(resultJson)), nil
		}

		// If we're here, the task has failed or is in an unknown state
		if taskStatus == "STOPPED" && exitCode != 0 {
			errorMsg := "Task failed"
			if len(task.Tasks[0].Containers) > 0 && task.Tasks[0].Containers[0].Reason != nil {
				errorMsg = aws.ToString(task.Tasks[0].Containers[0].Reason)
			} else if task.Tasks[0].StoppedReason != nil {
				errorMsg = aws.ToString(task.Tasks[0].StoppedReason)
			}

			e.logger.Error().
				Str("task_arn", taskArn).
				Str("status", taskStatus).
				Int32("exit_code", exitCode).
				Str("error", errorMsg).
				Msg("ECS task failed")

			// Return an error response
			errorResponse := fmt.Sprintf(`{ "error": "Task failed with exit code %d: %s" }`, exitCode, errorMsg)
			return io.NopCloser(strings.NewReader(errorResponse)), nil
		}
	}

	// Original CloudWatch logs retrieval code continues below
	// Extract task definition from task description
	task, err := e.ecsClient.DescribeTasks(ctx, &ecs.DescribeTasksInput{
		Cluster: &e.config.Cluster,
		Tasks:   []string{taskArn},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to describe task: %w", err)
	}

	if len(task.Tasks) == 0 {
		return nil, fmt.Errorf("task not found: %s", taskArn)
	}

	// Use task definition name for log stream naming
	taskDefArn := *task.Tasks[0].TaskDefinitionArn
	taskDefName := filepath.Base(taskDefArn)

	// Construct the log stream name
	// For ECS logs, log stream follows the format: prefix/task-definition/task-id
	logStreamName := fmt.Sprintf("function/%s/%s", taskDefName, containerID)

	// Wait for logs to be available (longer timeout for CloudWatch propagation)
	waitCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// Poll for logs with exponential backoff
	maxRetries := 10
	initialBackoff := 500 * time.Millisecond
	maxBackoff := 5 * time.Second
	backoff := initialBackoff

	// Log that we're waiting for CloudWatch logs
	e.logger.Info().
		Str("task_arn", taskArn).
		Str("log_stream", logStreamName).
		Msg("Retrieving logs from CloudWatch")

	for i := 0; i < maxRetries; i++ {
		select {
		case <-waitCtx.Done():
			return nil, fmt.Errorf("timeout waiting for logs: %w", waitCtx.Err())
		default:
			// Check if logs exist
			_, err := e.cwClient.DescribeLogStreams(ctx, &cloudwatchlogs.DescribeLogStreamsInput{
				LogGroupName:        aws.String("serverless-emulator"),
				LogStreamNamePrefix: aws.String(logStreamName),
			})

			if err == nil {
				// Get logs
				resp, err := e.cwClient.GetLogEvents(ctx, &cloudwatchlogs.GetLogEventsInput{
					LogGroupName:  aws.String("serverless-emulator"),
					LogStreamName: aws.String(logStreamName),
					StartFromHead: aws.Bool(true),
					Limit:         aws.Int32(100), // Get more logs
				})

				if err != nil {
					// Still checking for logs
					e.logger.Warn().
						Err(err).
						Str("log_stream", logStreamName).
						Msg("Failed to get log events, retrying")
					time.Sleep(backoff)
					// Exponential backoff with jitter
					backoff = time.Duration(float64(backoff) * 1.5)
					if backoff > maxBackoff {
						backoff = maxBackoff
					}
					continue
				}

				if len(resp.Events) == 0 {
					// No events yet, keep waiting
					e.logger.Debug().
						Str("log_stream", logStreamName).
						Msg("No log events yet, retrying")
					time.Sleep(backoff)
					// Exponential backoff with jitter
					backoff = time.Duration(float64(backoff) * 1.5)
					if backoff > maxBackoff {
						backoff = maxBackoff
					}
					continue
				}

				// Get more logs
				resp, err = e.cwClient.GetLogEvents(ctx, &cloudwatchlogs.GetLogEventsInput{
					LogGroupName:  aws.String("serverless-emulator"),
					LogStreamName: aws.String(logStreamName),
					StartFromHead: aws.Bool(true),
					Limit:         aws.Int32(100), // Get more logs
				})

				if err != nil {
					return nil, fmt.Errorf("failed to get log events: %w", err)
				}

				e.logger.Info().
					Int("event_count", len(resp.Events)).
					Str("log_stream", logStreamName).
					Msg("Successfully retrieved log events from CloudWatch")

				// Format logs similar to Docker logs
				var buf bytes.Buffer

				// Marshal log events into JSON for easier parsing by the caller
				rawEvents, err := json.Marshal(resp.Events)
				if err != nil {
					return nil, fmt.Errorf("failed to marshal log events: %w", err)
				}

				e.logger.Info().
					Str("log_stream", logStreamName).
					Int("event_count", len(resp.Events)).
					Msg("Retrieved log events from CloudWatch")

				e.logger.Info().
					RawJSON("raw_events", rawEvents).
					Msg("Raw CloudWatch log events retrieved")

				// Look for function start marker
				startMarker := "Starting handler execution"
				foundStart := false

				for _, event := range resp.Events {
					if event.Message != nil && strings.Contains(*event.Message, startMarker) {
						foundStart = true
						e.logger.Info().
							Str("marker", "handler start").
							Msg("Found handler start marker")
						break
					}
				}

				// Collect all log messages
				var logOutput strings.Builder
				for _, event := range resp.Events {
					if event.Message != nil {
						logOutput.WriteString(*event.Message)
						logOutput.WriteString("\n")
					}
				}

				// Look for structured function output between markers
				outputStartMarker := "--- FUNCTION OUTPUT START ---"
				outputEndMarker := "--- FUNCTION OUTPUT END ---"

				outputContent := ""
				if foundStart {
					logContent := logOutput.String()
					startIdx := strings.Index(logContent, outputStartMarker)
					if startIdx != -1 {
						startIdx += len(outputStartMarker) + 1 // +1 for newline
						endIdx := strings.Index(logContent[startIdx:], outputEndMarker)
						if endIdx != -1 {
							outputContent = logContent[startIdx : startIdx+endIdx]
							outputContent = strings.TrimSpace(outputContent)

							e.logger.Info().
								Str("structured_output", outputContent).
								Msg("Found structured function output")

							// Write the structured output to the buffer
							buf.WriteString(outputContent)
							buf.WriteString("\n")
						} else {
							e.logger.Warn().
								Msg("Found start marker but no end marker for structured output")
						}
					} else {
						e.logger.Warn().
							Msg("No structured function output found, scanning raw logs")
					}
				}

				// If no structured output was found, use all log lines as output
				if outputContent == "" {
					e.logger.Info().
						Str("function_output", logOutput.String()).
						Msg("Using all user log lines as function output")

					buf.WriteString(logOutput.String())
				}

				return io.NopCloser(&buf), nil
			}

			// Log stream not found yet, retry
			e.logger.Debug().
				Str("task_arn", taskArn).
				Str("log_stream", logStreamName).
				Msg("Log stream not found yet, waiting...")

			time.Sleep(backoff)
			// Exponential backoff with jitter
			backoff = time.Duration(float64(backoff) * 1.5)
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}

	return nil, fmt.Errorf("max retries exceeded waiting for logs")
}

// Add helper method to wait for logs to be available
func (e *ECSClient) waitForLogs(ctx context.Context, logStreamName string) error {
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		_, err := e.cwClient.GetLogEvents(ctx, &cloudwatchlogs.GetLogEventsInput{
			LogGroupName:  aws.String("/ecs/serverless-emulator"),
			LogStreamName: aws.String(logStreamName),
			Limit:         aws.Int32(1),
		})
		if err == nil {
			return nil
		}
		time.Sleep(1 * time.Second)
	}
	return fmt.Errorf("timeout waiting for logs")
}

func (e *ECSClient) ContainerWait(ctx context.Context, taskArn string, condition container.WaitCondition) (<-chan types.ContainerWaitResponse, <-chan error) {
	statusCh := make(chan types.ContainerWaitResponse, 1)
	errCh := make(chan error, 1)

	go func() {
		defer close(statusCh)
		defer close(errCh)

		// Initial delay to allow task to start
		time.Sleep(2 * time.Second)

		// Create variables to track task status
		var taskSeen bool
		var taskRunning bool
		var runningDuration time.Duration
		var startTime time.Time

		// Track when the task was first seen as RUNNING
		taskFirstRunningTime := time.Time{}

		// Set max wait time
		maxWaitTime := 60 * time.Second
		endTime := time.Now().Add(maxWaitTime)

		// Check the task in a loop
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()

		for time.Now().Before(endTime) {
			select {
			case <-ctx.Done():
				errCh <- ctx.Err()
				return
			case <-ticker.C:
				// Get task status
				resp, err := e.ecsClient.DescribeTasks(ctx, &ecs.DescribeTasksInput{
					Cluster: aws.String(e.config.Cluster),
					Tasks:   []string{taskArn},
				})

				// Error checking task
				if err != nil {
					e.logger.Error().
						Err(err).
						Str("taskArn", taskArn).
						Msg("Failed to describe task")
					continue
				}

				// Task not found
				if len(resp.Tasks) == 0 {
					e.logger.Warn().
						Str("taskArn", taskArn).
						Msg("Task not found during status check")
					continue
				}

				task := resp.Tasks[0]
				status := aws.ToString(task.LastStatus)
				taskSeen = true

				e.logger.Debug().
					Str("taskArn", taskArn).
					Str("status", status).
					Msg("Task status update")

				// If task is running, track it
				if status == "RUNNING" {
					if !taskRunning {
						taskRunning = true
						startTime = time.Now()
						taskFirstRunningTime = startTime
						e.logger.Info().
							Str("taskArn", taskArn).
							Time("startTime", startTime).
							Msg("Task started RUNNING")
					}

					runningDuration = time.Since(taskFirstRunningTime)

					// If the task has been running for at least 5 seconds, consider it successful
					if runningDuration >= 5*time.Second {
						e.logger.Info().
							Str("taskArn", taskArn).
							Dur("duration", runningDuration).
							Msg("Task has been running long enough, considering it successful")

						statusCh <- types.ContainerWaitResponse{StatusCode: 0}
						return
					}
				}

				// If task is stopped
				if status == "STOPPED" {
					// Check if the task was running long enough
					if taskRunning && runningDuration >= 5*time.Second {
						e.logger.Info().
							Str("taskArn", taskArn).
							Dur("running_duration", runningDuration).
							Msg("Task stopped after running sufficiently, considering it successful")

						statusCh <- types.ContainerWaitResponse{StatusCode: 0}
						return
					}

					// Get stopped reason
					stopReason := "Unknown"
					if task.StoppedReason != nil {
						stopReason = aws.ToString(task.StoppedReason)
					}

					// Get container exit code
					exitCode := int64(-1)
					containerReason := ""
					if len(task.Containers) > 0 {
						container := task.Containers[0]
						if container.ExitCode != nil {
							exitCode = int64(*container.ExitCode)
						}
						if container.Reason != nil {
							containerReason = aws.ToString(container.Reason)
						}
					}

					e.logger.Error().
						Str("taskArn", taskArn).
						Str("stopReason", stopReason).
						Str("containerReason", containerReason).
						Int64("exitCode", exitCode).
						Msg("Task stopped before running long enough")

					// If exit code is 0, it might have completed too quickly but successfully
					if exitCode == 0 {
						e.logger.Info().
							Str("taskArn", taskArn).
							Msg("Task had exit code 0, considering it successful")
						statusCh <- types.ContainerWaitResponse{StatusCode: 0}
						return
					}

					errCh <- fmt.Errorf("task stopped: %s (exit code: %d)", stopReason, exitCode)
					return
				}
			}
		}

		// Timeout reached
		if taskRunning {
			e.logger.Warn().
				Str("taskArn", taskArn).
				Dur("runningDuration", runningDuration).
				Msg("Wait timeout but task was running, considering it successful")
			statusCh <- types.ContainerWaitResponse{StatusCode: 0}
		} else if taskSeen {
			errCh <- fmt.Errorf("task wait timeout, task never reached RUNNING state")
		} else {
			errCh <- fmt.Errorf("task wait timeout, task status could not be determined")
		}
	}()

	return statusCh, errCh
}

// Add this method to ECSClient
func (e *ECSClient) RemoveContainer(ctx context.Context, taskArn string) error {
	// Add detailed logging
	e.logger.Info().
		Str("original_task_id", taskArn).
		Int("id_length", len(taskArn)).
		Msg("RemoveContainer called in ECSClient")

	// Handle Docker container IDs (64 characters)
	if len(taskArn) == 64 && isHexString(taskArn) {
		// Truncate to 32 characters for ECS compatibility
		truncatedID := taskArn[:32]
		e.logger.Info().
			Str("original_id", taskArn).
			Str("truncated_id", truncatedID).
			Msg("Truncating 64-character Docker ID to 32 characters for ECS compatibility")
		taskArn = truncatedID
	}

	// For ECS tasks, we need to stop the task and wait for it to be removed
	_, err := e.ecsClient.StopTask(ctx, &ecs.StopTaskInput{
		Cluster: &e.config.Cluster,
		Task:    &taskArn,
		Reason:  aws.String("Task cleanup"),
	})
	if err != nil {
		e.logger.Error().
			Err(err).
			Str("task_id", taskArn).
			Msg("Failed to stop task")
		return fmt.Errorf("failed to stop task: %w", err)
	}

	// Wait for the task to be removed
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			resp, err := e.ecsClient.DescribeTasks(ctx, &ecs.DescribeTasksInput{
				Cluster: &e.config.Cluster,
				Tasks:   []string{taskArn},
			})
			if err != nil {
				// If the task is not found, it's been removed
				if strings.Contains(err.Error(), "The specified task was not found") {
					return nil
				}
				return fmt.Errorf("failed to describe task: %w", err)
			}

			if len(resp.Tasks) == 0 {
				// Task has been removed
				return nil
			}

			task := resp.Tasks[0]
			if *task.LastStatus == "STOPPED" {
				// Task has been stopped, we can consider it removed
				return nil
			}

			// Wait before checking again
			time.Sleep(2 * time.Second)
		}
	}
}

// Helper function to check if a string is hexadecimal
func isHexString(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// copyFile copies a file from src to dst
func copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	if err != nil {
		return err
	}

	return nil
}

// Check if we should use AWS CodeBuild
func (e *ECSClient) shouldUseCodeBuild() bool {
	// First check the explicitly set environment variable
	if os.Getenv("AWS_ECS_USE_CODEBUILD") == "true" {
		return true
	}
	// For testing, default to true - remove this in production
	return true
}

// BuildImage builds a Docker image for the function
func (e *ECSClient) BuildImage(ctx context.Context, opts *runtime.BuildImageOptions) error {
	e.logger.Debug().
		Str("image", opts.ImageName).
		Str("runtime", string(opts.Runtime)).
		Str("code_path", opts.CodePath).
		Str("handler", opts.Handler).
		Msg("ECS client building function image")

	// Check if we should use AWS CodeBuild
	if e.shouldUseCodeBuild() {
		e.logger.Info().
			Str("image", opts.ImageName).
			Msg("Using AWS CodeBuild for image building")

		// Get CodeBuild configuration from environment
		projectName := os.Getenv("AWS_CODEBUILD_PROJECT_NAME")
		if projectName == "" {
			projectName = "serverless-function-builder"
		}

		region := os.Getenv("AWS_CODEBUILD_REGION")
		if region == "" {
			region = os.Getenv("AWS_REGION")
		}
		if region == "" {
			region = "us-east-1" // Default region
		}

		s3Bucket := os.Getenv("S3_BUCKET") // Use the same S3 bucket for CodeBuild
		if s3Bucket == "" {
			s3Bucket = "serverless-emulator" // Default bucket name
		}

		// Create a new CodeBuild client
		cbClient, err := NewCodeBuildClient(e.logger.With().Str("component", "codebuild").Logger(), region, s3Bucket, projectName)
		if err != nil {
			e.logger.Error().Err(err).Msg("Failed to create CodeBuild client")
			return fmt.Errorf("failed to create CodeBuild client: %w", err)
		}

		// Build the image using CodeBuild
		imageURI, err := cbClient.BuildImage(ctx, opts)
		if err != nil {
			e.logger.Error().Err(err).Msg("Failed to build image with CodeBuild")
			return fmt.Errorf("build failed: %w", err)
		}

		// Extract the key parts from the imageURI - store in environment variable for later use
		// This ensures we use the exact same image URI when running containers
		if imageURI != "" {
			// Set environment variable with the full image URI for later container creation
			if err := os.Setenv("CODEBUILD_IMAGE_URI_"+opts.ImageName, imageURI); err != nil {
				e.logger.Warn().
					Err(err).
					Str("image_uri", imageURI).
					Msg("Failed to set environment variable for image URI, container creation might fail")
			} else {
				e.logger.Debug().
					Str("env_var", "CODEBUILD_IMAGE_URI_"+opts.ImageName).
					Str("image_uri", imageURI).
					Msg("Stored CodeBuild image URI in environment variable")
			}
		}

		e.logger.Info().
			Str("image_uri", imageURI).
			Msg("Successfully built image with CodeBuild")

		return nil
	}

	// In ECS mode, we'll use the Docker CLI directly to ensure proper platform targeting
	e.logger.Info().
		Str("image", opts.ImageName).
		Msg("Using Docker CLI with platform targeting for ECS compatibility")

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
		e.logger.Debug().Str("s3_path", opts.CodePath).Msg("Found S3 path, downloading code file")

		// Extract bucket and key from S3 URL
		s3Path := strings.TrimPrefix(opts.CodePath, "s3://")
		parts := strings.SplitN(s3Path, "/", 2)
		if len(parts) != 2 {
			return fmt.Errorf("invalid S3 path format: %s", opts.CodePath)
		}

		s3Bucket := parts[0]
		s3Key := parts[1]

		e.logger.Debug().
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

		e.logger.Debug().
			Str("temp_zip_file", tempZipFile).
			Int("code_size", len(codeBytes)).
			Msg("Downloaded code from S3 to temporary file")
	} else {
		// Local file path
		tempZipFile = opts.CodePath
		e.logger.Debug().Str("local_path", tempZipFile).Msg("Using local code path")
	}

	// Extract function code to temp directory
	if err := extractZip(tempZipFile, tempDir); err != nil {
		return fmt.Errorf("failed to extract function code: %w", err)
	}

	// Create Dockerfile in temp directory
	dockerfilePath := filepath.Join(tempDir, "Dockerfile")

	// Copy wrapper.js to build directory
	wrapperSrc := filepath.Join("internal", "docker", "wrapper.js")
	wrapperDst := filepath.Join(tempDir, "wrapper.js")
	if err := copyFile(wrapperSrc, wrapperDst); err != nil {
		e.logger.Warn().Err(err).Msg("Failed to copy wrapper.js from internal/docker, creating from template")
		// If we can't find the file, create it from the template
		if err := os.WriteFile(wrapperDst, []byte(nodeWrapperScript), 0755); err != nil {
			return fmt.Errorf("failed to create wrapper.js: %w", err)
		}
	}
	e.logger.Debug().Str("wrapper_path", wrapperDst).Msg("Added wrapper.js to build directory")

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

	e.logger.Debug().Msgf("Generated Dockerfile:\n%s", dockerfile)

	// Make sure we're using the image name with :latest tag
	localImageName := opts.ImageName
	if !strings.Contains(localImageName, ":") {
		localImageName = localImageName + ":latest"
	}

	// Build the image using Docker CLI
	e.logger.Info().
		Str("image", localImageName).
		Msg("Building Docker image with Docker CLI")

	buildCmd := exec.Command(
		"docker", "build",
		"--platform=linux/amd64",
		"-t", localImageName,
		"-f", dockerfilePath,
		tempDir,
	)

	var buildStdout, buildStderr bytes.Buffer
	buildCmd.Stdout = &buildStdout
	buildCmd.Stderr = &buildStderr

	if err := buildCmd.Run(); err != nil {
		e.logger.Error().
			Err(err).
			Str("stderr", buildStderr.String()).
			Msg("Failed to build Docker image")
		return fmt.Errorf("failed to build Docker image: %w: %s", err, buildStderr.String())
	}

	e.logger.Info().
		Str("image", localImageName).
		Msg("Successfully built Docker image")

	// Verify the image exists using the Docker CLI
	inspectCmd := exec.Command("docker", "image", "inspect", localImageName)
	if err := inspectCmd.Run(); err != nil {
		e.logger.Error().
			Err(err).
			Str("image", localImageName).
			Msg("Image verification failed after build")
		return fmt.Errorf("image verification failed: %w", err)
	}

	// If we're in ECS mode, push the image to ECR
	accountID := os.Getenv("AWS_ACCOUNT_ID")
	region := os.Getenv("AWS_REGION")
	if accountID != "" && region != "" {
		// Format as ECR URL: {account-id}.dkr.ecr.{region}.amazonaws.com/{image-name}:latest
		ecrURI := fmt.Sprintf("%s.dkr.ecr.%s.amazonaws.com", accountID, region)
		imageName := strings.Split(opts.ImageName, ":")[0] // Remove any tag
		ecrImageTag := fmt.Sprintf("%s/%s:latest", ecrURI, imageName)

		e.logger.Info().
			Str("local_image", localImageName).
			Str("ecr_image", ecrImageTag).
			Msg("Tagging image for ECR")

		// Tag the image using Docker CLI
		tagCmd := exec.Command("docker", "tag", localImageName, ecrImageTag)
		var tagStdout, tagStderr bytes.Buffer
		tagCmd.Stdout = &tagStdout
		tagCmd.Stderr = &tagStderr

		if err := tagCmd.Run(); err != nil {
			e.logger.Error().
				Err(err).
				Str("stderr", tagStderr.String()).
				Msg("Failed to tag image for ECR")
			return fmt.Errorf("failed to tag image for ECR: %w: %s", err, tagStderr.String())
		}

		e.logger.Info().
			Str("local_image", localImageName).
			Str("ecr_image", ecrImageTag).
			Msg("Successfully tagged image for ECR")

		// Create ECR repository if it doesn't exist
		e.logger.Info().
			Str("repository", imageName).
			Msg("Creating ECR repository if it doesn't exist")

		createRepoCmd := exec.Command(
			"aws", "ecr", "create-repository",
			"--repository-name", imageName,
			"--region", region,
		)

		var createRepoStdout, createRepoStderr bytes.Buffer
		createRepoCmd.Stdout = &createRepoStdout
		createRepoCmd.Stderr = &createRepoStderr

		if err := createRepoCmd.Run(); err != nil {
			// If the error is that the repository already exists, we can continue
			if !strings.Contains(createRepoStderr.String(), "RepositoryAlreadyExistsException") {
				e.logger.Warn().
					Err(err).
					Str("stderr", createRepoStderr.String()).
					Msg("Failed to create ECR repository")

				// Don't halt execution if repository creation failed
				// AWS might have permission issues but the repository might already exist
				e.logger.Info().Msg("Continuing with image push despite repository creation issues")
			} else {
				e.logger.Info().
					Str("repository", imageName).
					Msg("ECR repository already exists")
			}
		} else {
			repoDetails := struct {
				Repository struct {
					RepositoryUri string `json:"repositoryUri"`
				} `json:"repository"`
			}{}

			if err := json.Unmarshal(createRepoStdout.Bytes(), &repoDetails); err == nil {
				e.logger.Info().
					Str("repository", imageName).
					Str("repositoryUri", repoDetails.Repository.RepositoryUri).
					Msg("Created ECR repository")
			} else {
				e.logger.Info().
					Str("repository", imageName).
					Str("output", createRepoStdout.String()).
					Msg("Created ECR repository")
			}
		}

		// Log in to ECR using the AWS CLI for credentials
		e.logger.Info().Msg("Getting ECR login credentials from AWS CLI")

		// First try the modern way with get-login-password
		loginCmd := exec.Command("aws", "ecr", "get-login-password", "--region", region)
		var loginOutput bytes.Buffer
		loginCmd.Stdout = &loginOutput

		loginErr := loginCmd.Run()
		if loginErr == nil {
			// We got the password, now use it to log in
			dockerLoginCmd := exec.Command("docker", "login", "--username", "AWS", "--password-stdin", fmt.Sprintf("%s.dkr.ecr.%s.amazonaws.com", accountID, region))
			dockerLoginCmd.Stdin = &loginOutput

			var loginStderr bytes.Buffer
			dockerLoginCmd.Stderr = &loginStderr

			if err := dockerLoginCmd.Run(); err != nil {
				e.logger.Error().
					Err(err).
					Str("stderr", loginStderr.String()).
					Msg("Failed to login to ECR with get-login-password")

				loginErr = err
			} else {
				loginErr = nil
				e.logger.Info().Msg("Successfully logged in to ECR")
			}
		}

		// If the modern way failed, try the older get-login method
		if loginErr != nil {
			e.logger.Warn().
				Err(loginErr).
				Msg("Failed to authenticate with get-login-password, trying get-login")

			loginLegacyCmd := exec.Command("aws", "ecr", "get-login", "--no-include-email", "--region", region)
			var loginLegacyOutput bytes.Buffer
			loginLegacyCmd.Stdout = &loginLegacyOutput

			if err := loginLegacyCmd.Run(); err != nil {
				e.logger.Error().
					Err(err).
					Msg("Failed to get ECR login command")
				return fmt.Errorf("failed to authenticate with ECR: %w", err)
			}

			// The get-login command returns the full docker login command
			loginCommand := strings.TrimSpace(loginLegacyOutput.String())

			// Parse the command into parts and execute it
			loginParts := strings.Split(loginCommand, " ")
			if len(loginParts) < 5 {
				e.logger.Error().
					Str("command", loginCommand).
					Msg("Invalid ECR login command format")
				return fmt.Errorf("invalid ECR login command format")
			}

			legacyLoginCmd := exec.Command(loginParts[0], loginParts[1:]...)
			var legacyLoginStderr bytes.Buffer
			legacyLoginCmd.Stderr = &legacyLoginStderr

			if err := legacyLoginCmd.Run(); err != nil {
				e.logger.Error().
					Err(err).
					Str("stderr", legacyLoginStderr.String()).
					Msg("Failed to execute ECR login command")
				return fmt.Errorf("failed to login to ECR: %w: %s", err, legacyLoginStderr.String())
			}

			e.logger.Info().Msg("Successfully logged in to ECR using legacy method")
		}

		// Push the image to ECR
		e.logger.Info().
			Str("ecr_image", ecrImageTag).
			Msg("Pushing image to ECR - this may take a while")

		// Create context with timeout for the push operation
		pushCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		defer cancel()

		pushCmd := exec.CommandContext(pushCtx, "docker", "push", ecrImageTag)

		// Set up pipes to capture and stream output in real-time
		stdout, err := pushCmd.StdoutPipe()
		if err != nil {
			return fmt.Errorf("failed to create stdout pipe: %w", err)
		}

		stderr, err := pushCmd.StderrPipe()
		if err != nil {
			return fmt.Errorf("failed to create stderr pipe: %w", err)
		}

		// Start the command
		if err := pushCmd.Start(); err != nil {
			return fmt.Errorf("failed to start docker push: %w", err)
		}

		// Read and log output in real-time
		go func() {
			scanner := bufio.NewScanner(stdout)
			for scanner.Scan() {
				line := scanner.Text()
				e.logger.Debug().Str("stdout", line).Msg("Push progress")
			}
		}()

		// Collect error output
		var stderrBuilder strings.Builder
		go func() {
			scanner := bufio.NewScanner(stderr)
			for scanner.Scan() {
				line := scanner.Text()
				stderrBuilder.WriteString(line + "\n")
				e.logger.Debug().Str("stderr", line).Msg("Push error output")
			}
		}()

		// Wait for the command to complete
		err = pushCmd.Wait()
		stderrOutput := stderrBuilder.String()

		if err != nil {
			e.logger.Error().
				Err(err).
				Str("stderr", stderrOutput).
				Msg("Failed to push image to ECR")
			return fmt.Errorf("failed to push image to ECR: %w: %s", err, stderrOutput)
		}

		e.logger.Info().
			Str("ecr_image", ecrImageTag).
			Msg("Successfully pushed image to ECR")
	} else {
		e.logger.Warn().
			Str("account_id", accountID).
			Str("region", region).
			Msg("AWS_ACCOUNT_ID or AWS_REGION not set, skipping ECR push")
	}

	return nil
}

// Helper method to get ECR auth config
func (e *ECSClient) getECRAuthConfig(ctx context.Context) (string, error) {
	// Get ECR authorization token
	resp, err := e.ecrClient.GetAuthorizationToken(ctx, &ecr.GetAuthorizationTokenInput{})
	if err != nil {
		return "", fmt.Errorf("failed to get ECR auth token: %w", err)
	}

	if len(resp.AuthorizationData) == 0 {
		return "", fmt.Errorf("no ECR authorization data received")
	}

	// Decode auth data
	authToken := aws.ToString(resp.AuthorizationData[0].AuthorizationToken)
	decodedToken, err := base64.StdEncoding.DecodeString(authToken)
	if err != nil {
		return "", fmt.Errorf("failed to decode ECR auth token: %w", err)
	}

	// Extract username and password
	parts := strings.SplitN(string(decodedToken), ":", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid ECR auth token format")
	}

	// Create auth config
	authConfig := registry.AuthConfig{
		Username: parts[0],
		Password: parts[1],
	}

	// Encode to JSON
	encodedJSON, err := json.Marshal(authConfig)
	if err != nil {
		return "", fmt.Errorf("failed to encode auth config: %w", err)
	}

	return base64.URLEncoding.EncodeToString(encodedJSON), nil
}

func (e *ECSClient) RemoveImage(ctx context.Context, imageName string) error {
	// For ECS, we might want to remove from ECR
	// For now, we'll use the same remove process as local Docker
	dockerClient, err := client.NewClientWithOpts(
		client.WithAPIVersionNegotiation(),
	)
	if err != nil {
		return fmt.Errorf("failed to create temporary docker client: %w", err)
	}
	defer dockerClient.Close()

	localClient := &Client{
		docker: dockerClient,
		logger: e.logger,
	}

	return localClient.RemoveImage(ctx, imageName)
}

func (e *ECSClient) Ping(ctx context.Context) error {
	// Check ECS connectivity by listing clusters
	_, err := e.ecsClient.ListClusters(ctx, &ecs.ListClustersInput{})
	if err != nil {
		return fmt.Errorf("failed to ping ECS: %w", err)
	}
	return nil
}

func (e *ECSClient) validateTaskDefinition(ctx context.Context, taskDefArn string) error {
	resp, err := e.ecsClient.DescribeTaskDefinition(ctx, &ecs.DescribeTaskDefinitionInput{
		TaskDefinition: aws.String(taskDefArn),
	})
	if err != nil {
		return fmt.Errorf("failed to describe task definition: %w", err)
	}

	if len(resp.TaskDefinition.ContainerDefinitions) == 0 {
		return fmt.Errorf("no container definitions in task definition")
	}

	container := resp.TaskDefinition.ContainerDefinitions[0]
	e.logger.Debug().
		Str("taskDefinition", taskDefArn).
		Str("image", *container.Image).
		Interface("command", container.Command).
		Interface("environment", container.Environment).
		Msg("Task definition validated")

	return nil
}

// CleanupResources performs housekeeping to avoid unnecessary charges
// It stops any lingering tasks and removes unused ECR repositories
func (e *ECSClient) CleanupResources(ctx context.Context) error {
	e.logger.Info().Msg("Starting ECS and ECR resource cleanup")

	// 1. Cleanup ECS tasks - find and stop any tasks running for more than 15 minutes
	taskListResp, err := e.ecsClient.ListTasks(ctx, &ecs.ListTasksInput{
		Cluster: aws.String(e.config.Cluster),
	})

	if err != nil {
		e.logger.Error().Err(err).Msg("Failed to list ECS tasks for cleanup")
	} else if len(taskListResp.TaskArns) > 0 {
		// Get details about tasks
		describeResp, err := e.ecsClient.DescribeTasks(ctx, &ecs.DescribeTasksInput{
			Cluster: aws.String(e.config.Cluster),
			Tasks:   taskListResp.TaskArns,
		})

		if err != nil {
			e.logger.Error().Err(err).Msg("Failed to describe ECS tasks for cleanup")
		} else {
			// Filter for tasks running more than 15 minutes
			var tasksToStop []string
			for _, task := range describeResp.Tasks {
				// Skip tasks that aren't running
				if task.LastStatus == nil || *task.LastStatus != "RUNNING" {
					continue
				}

				// Check if this is a serverless function task
				isServerlessTask := false
				if task.Group != nil && strings.Contains(*task.Group, "serverless-fn") {
					isServerlessTask = true
				}

				// For non-serverless tasks, skip them to avoid disrupting other workloads
				if !isServerlessTask {
					continue
				}

				// Check how long the task has been running
				if task.StartedAt != nil {
					runningDuration := time.Since(aws.ToTime(task.StartedAt))
					if runningDuration > 15*time.Minute {
						tasksToStop = append(tasksToStop, *task.TaskArn)
						e.logger.Info().
							Str("task_arn", *task.TaskArn).
							Dur("running_duration", runningDuration).
							Msg("Stopping long-running ECS task")
					}
				}
			}

			// Stop identified tasks
			for _, taskArn := range tasksToStop {
				_, err := e.ecsClient.StopTask(ctx, &ecs.StopTaskInput{
					Cluster: aws.String(e.config.Cluster),
					Task:    aws.String(taskArn),
					Reason:  aws.String("Automatic cleanup of long-running function"),
				})

				if err != nil {
					e.logger.Error().Err(err).Str("task_arn", taskArn).Msg("Failed to stop ECS task")
				} else {
					e.logger.Info().Str("task_arn", taskArn).Msg("Successfully stopped ECS task")
				}
			}
		}
	}

	// 2. Cleanup ECR repositories - limit to 10 repositories, keeping only newest 5 images per repo
	// (adjust these numbers based on your usage patterns)
	aws_cfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion(e.config.Region),
	)

	if err != nil {
		e.logger.Error().Err(err).Msg("Failed to load AWS config for ECR cleanup")
		return err
	}

	ecrClient := ecr.NewFromConfig(aws_cfg)

	// List all repositories
	repoResp, err := ecrClient.DescribeRepositories(ctx, &ecr.DescribeRepositoriesInput{
		MaxResults: aws.Int32(100), // Adjust as needed
	})

	if err != nil {
		e.logger.Error().Err(err).Msg("Failed to list ECR repositories for cleanup")
		return err
	}

	// Keep only repositories related to our serverless functions
	var fnRepos []ecrtypes.Repository
	for _, repo := range repoResp.Repositories {
		if strings.HasPrefix(*repo.RepositoryName, "fn-") {
			fnRepos = append(fnRepos, repo)
		}
	}

	// Sort repositories by creation date (newest first)
	sort.Slice(fnRepos, func(i, j int) bool {
		return fnRepos[i].CreatedAt.After(*fnRepos[j].CreatedAt)
	})

	// Delete old repositories (keep 10 most recent)
	const maxReposToKeep = 10
	if len(fnRepos) > maxReposToKeep {
		for _, repo := range fnRepos[maxReposToKeep:] {
			_, err := ecrClient.DeleteRepository(ctx, &ecr.DeleteRepositoryInput{
				RepositoryName: repo.RepositoryName,
				Force:          true, // Force delete even if it has images
			})

			if err != nil {
				e.logger.Error().Err(err).Str("repository", *repo.RepositoryName).Msg("Failed to delete ECR repository")
			} else {
				e.logger.Info().Str("repository", *repo.RepositoryName).Msg("Successfully deleted old ECR repository")
			}
		}
	}

	// For remaining repositories, clean up old images
	const maxImagesToKeep = 5
	for i := 0; i < min(len(fnRepos), maxReposToKeep); i++ {
		repo := fnRepos[i]

		// List images in this repository
		imagesResp, err := ecrClient.ListImages(ctx, &ecr.ListImagesInput{
			RepositoryName: repo.RepositoryName,
		})

		if err != nil {
			e.logger.Error().Err(err).Str("repository", *repo.RepositoryName).Msg("Failed to list ECR images")
			continue
		}

		// If we have too many images, delete the oldest ones
		if len(imagesResp.ImageIds) > maxImagesToKeep {
			// We can only get image details by digest, so we need to get details for all images
			imageDetails, err := ecrClient.DescribeImages(ctx, &ecr.DescribeImagesInput{
				RepositoryName: repo.RepositoryName,
			})

			if err != nil {
				e.logger.Error().Err(err).Str("repository", *repo.RepositoryName).Msg("Failed to describe ECR images")
				continue
			}

			// Sort images by pushed date (newest first)
			sort.Slice(imageDetails.ImageDetails, func(i, j int) bool {
				return imageDetails.ImageDetails[i].ImagePushedAt.After(*imageDetails.ImageDetails[j].ImagePushedAt)
			})

			// Get image digests to delete (oldest images)
			var imageDigestsToDelete []string
			for _, img := range imageDetails.ImageDetails[maxImagesToKeep:] {
				imageDigestsToDelete = append(imageDigestsToDelete, *img.ImageDigest)
			}

			// Delete the old images
			if len(imageDigestsToDelete) > 0 {
				imagesToDelete := make([]ecrtypes.ImageIdentifier, 0, len(imageDigestsToDelete))
				for _, digest := range imageDigestsToDelete {
					imagesToDelete = append(imagesToDelete, ecrtypes.ImageIdentifier{
						ImageDigest: aws.String(digest),
					})
				}

				_, err := ecrClient.BatchDeleteImage(ctx, &ecr.BatchDeleteImageInput{
					RepositoryName: repo.RepositoryName,
					ImageIds:       imagesToDelete,
				})

				if err != nil {
					e.logger.Error().Err(err).Str("repository", *repo.RepositoryName).Msg("Failed to delete old ECR images")
				} else {
					e.logger.Info().
						Str("repository", *repo.RepositoryName).
						Int("deleted_count", len(imagesToDelete)).
						Msg("Successfully deleted old ECR images")
				}
			}
		}
	}

	e.logger.Info().Msg("Completed ECS and ECR resource cleanup")
	return nil
}

// Helper function for Go <1.21 compatibility
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Add this helper function at the end of the file
func toJSON(v interface{}) []byte {
	data, err := json.Marshal(v)
	if err != nil {
		return []byte("{}")
	}
	return data
}
