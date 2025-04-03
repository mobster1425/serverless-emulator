package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"

	//	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"serverless-emulator/internal/config"
	"serverless-emulator/internal/models"
	"serverless-emulator/pkg/logger"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/pkg/stdcopy"
)

// WorkerPool manages a pool of workers for function execution
type WorkerPool struct {
	workers  []*Worker
	jobQueue chan *models.WorkerJob
	db       DB
	docker   RuntimeClient
	logger   *logger.Logger
	config   *config.WorkerConfig
	metrics  *WorkerMetrics
	wg       sync.WaitGroup
	ctx      context.Context
	cancel   context.CancelFunc
}

// Worker represents a single worker in the pool
type Worker struct {
	id       int
	pool     *WorkerPool
	jobQueue chan *models.WorkerJob
	logger   *logger.Logger
}

// WorkerMetrics tracks worker pool statistics
type WorkerMetrics struct {
	mu              sync.RWMutex
	activeWorkers   int
	completedJobs   uint64
	failedJobs      uint64
	averageLatency  time.Duration
	totalExecutions uint64
	resourceMetrics map[string]*ResourceMetrics
}

// ResourceMetrics tracks resource usage for functions
type ResourceMetrics struct {
	executions uint64
}

// NewWorkerPool creates a new worker pool
func NewWorkerPool(cfg *config.WorkerConfig, db DB, docker RuntimeClient, logger *logger.Logger) *WorkerPool {
	ctx, cancel := context.WithCancel(context.Background())

	pool := &WorkerPool{
		jobQueue: make(chan *models.WorkerJob, cfg.QueueSize),
		db:       db,
		docker:   docker,
		logger:   logger,
		config:   cfg,
		ctx:      ctx,
		cancel:   cancel,
		metrics:  newWorkerMetrics(),
	}

	return pool
}

// Start initializes and starts the worker pool
func (p *WorkerPool) Start() error {
	p.logger.Info().Msgf("Starting worker pool with %d workers", p.config.NumWorkers)

	// Initialize workers
	for i := 0; i < p.config.NumWorkers; i++ {
		worker := &Worker{
			id:       i,
			pool:     p,
			jobQueue: p.jobQueue,
			logger:   p.logger.WithField("worker_id", i),
		}
		p.workers = append(p.workers, worker)

		// Start worker
		p.wg.Add(1)
		go worker.start()
	}

	return nil
}

// Stop gracefully shuts down the worker pool
func (p *WorkerPool) Stop() error {
	p.logger.Info().Msg("Shutting down worker pool...")
	p.cancel()

	// Wait for all workers to finish with timeout
	done := make(chan struct{})
	go func() {
		p.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		p.logger.Info().Msg("Worker pool shutdown completed")
		return nil
	case <-time.After(p.config.ShutdownTimeout):
		return fmt.Errorf("worker pool shutdown timed out")
	}
}

// Submit adds a new job to the worker pool
func (p *WorkerPool) Submit(job *models.WorkerJob) {
	select {
	case p.jobQueue <- job:
		return
	case <-p.ctx.Done():
		p.logger.Error().Msg("worker pool is shutting down")
		return
	default:
		if !job.Async {
			p.logger.Error().Msg("worker pool is at capacity")
			return
		}
		// For async jobs, try with timeout
		select {
		case p.jobQueue <- job:
			return
		case <-time.After(p.config.QueueTimeout):
			p.logger.Error().Msg("queue is full")
			return
		}
	}
}

// GetMetrics returns current worker pool metrics
func (p *WorkerPool) GetMetrics() *WorkerMetrics {
	return p.metrics
}

// Worker methods

func (w *Worker) start() {
	defer w.pool.wg.Done()

	w.logger.Debug().Msg("Worker started")

	for {
		select {
		case job := <-w.jobQueue:
			w.processJob(job)
		case <-w.pool.ctx.Done():
			w.logger.Debug().Msg("Worker shutting down")
			return
		}
	}
}

func (w *Worker) processJob(job *models.WorkerJob) {
	w.logger.Debug().
		Interface("job", job).
		Msg("Processing job")

	startTime := time.Now()
	w.pool.metrics.incrementActiveWorkers()
	defer w.pool.metrics.decrementActiveWorkers()

	// Create execution context with longer timeout
	ctx, cancel := context.WithTimeout(w.pool.ctx, time.Duration(job.Timeout+30)*time.Second)
	defer cancel()

	// Add more buffer time to the container timeout
	containerTimeout := time.Duration(job.Timeout+60) * time.Second

	// Add debug logging
	w.logger.Debug().
		Str("function_id", job.FunctionID).
		Str("request_id", job.RequestID).
		Int("timeout", job.Timeout).
		Dur("container_timeout", containerTimeout).
		Msg("Starting function execution")

	// Update function log status
	if err := w.pool.db.UpdateFunctionLogStatus(ctx, job.RequestID, models.ExecutionStatusRunning); err != nil {
		w.handleExecutionError(job, err)
		return
	}

	// Prepare container configuration
	imageName := job.ImageName

	// Debug log the payload and environment
	w.logger.Debug().
		Str("function_id", job.FunctionID).
		Str("image_name", imageName).
		Str("payload", string(job.InvocationMessage.Payload)).
		Msg("Function invocation details")

	// Wrap the input in an event envelope
	// This ensures compatibility with functions that expect event.payload structure
	var rawInput interface{}
	if err := json.Unmarshal(job.InvocationMessage.Payload, &rawInput); err != nil {
		w.logger.Error().Err(err).Msg("Failed to parse function input")
		// If we can't parse it, just use it as is
		rawInput = string(job.InvocationMessage.Payload)
	}

	eventEnvelope := map[string]interface{}{
		"payload": rawInput,
	}

	// Convert back to JSON
	wrappedInput, err := json.Marshal(eventEnvelope)
	if err != nil {
		w.logger.Error().Err(err).Msg("Failed to wrap function input")
		wrappedInput = job.InvocationMessage.Payload
	}

	w.logger.Debug().
		Str("original_input", string(job.InvocationMessage.Payload)).
		Str("wrapped_input", string(wrappedInput)).
		Msg("Wrapped function input in payload envelope")

	containerConfig := &container.Config{
		Image: imageName,
		Env: []string{
			fmt.Sprintf("FUNCTION_HANDLER=%s", job.Handler),
			fmt.Sprintf("REQUEST_ID=%s", job.RequestID),
			fmt.Sprintf("FUNCTION_ID=%s", job.FunctionID),
			fmt.Sprintf("FUNCTION_TIMEOUT=%d", job.Timeout),
			fmt.Sprintf("FUNCTION_INPUT=%s", string(wrappedInput)),
			"DEBUG=*",
			"NODE_ENV=production",
		},
		WorkingDir: "/app",
		Cmd:        []string{"node", "runner.js"},
		// Add health check
		Healthcheck: &container.HealthConfig{
			Test:     []string{"CMD-SHELL", "node -e 'process.exit(0)'"},
			Interval: 10 * time.Second,
			Timeout:  5 * time.Second,
			Retries:  3,
		},
	}

	hostConfig := &container.HostConfig{
		Resources: container.Resources{
			Memory:    job.Memory * 1024 * 1024,
			CPUPeriod: 100000,
			CPUQuota:  int64(job.CPU * 100000),
		},
		AutoRemove:     false,
		NetworkMode:    "none",
		ReadonlyRootfs: true,
		LogConfig: container.LogConfig{
			Type: "json-file",
			Config: map[string]string{
				"max-size": "10m",
				"max-file": "1",
			},
		},
	}

	// Add debug logging for container configuration
	w.logger.Debug().
		Interface("containerConfig", containerConfig).
		Interface("hostConfig", hostConfig).
		Msg("Container configuration")

	// Create container with the buffered timeout
	resp, err := w.pool.docker.CreateContainer(ctx, containerConfig, hostConfig, job.RequestID)
	if err != nil {
		w.logger.Error().
			Err(err).
			Str("image", job.ImageName).
			Str("request_id", job.RequestID).
			Msg("Failed to create container")
		w.handleExecutionError(job, fmt.Errorf("failed to create container: %w", err))
		return
	}

	containerID := resp.ID
	defer func() {
		// Check if this is an ECS task or a Docker container for longer cleanup
		isEcsTask := strings.HasPrefix(containerID, "arn:aws:ecs:")
		isDockerContainerId := len(containerID) == 64 && isHexString(containerID)

		// Use a much longer timeout for ECS tasks (5 minutes)
		cleanupTimeout := 10 * time.Second
		if isEcsTask || isDockerContainerId {
			cleanupTimeout = 5 * time.Minute
			w.logger.Info().
				Str("container_id", containerID).
				Bool("is_ecs_task", isEcsTask).
				Bool("is_docker_id", isDockerContainerId).
				Dur("timeout", cleanupTimeout).
				Msg("Using extended timeout for container cleanup")
		}

		// Use a background context for container removal, not tied to the function execution
		removeCtx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
		defer cancel()

		// Execute container removal in a goroutine to prevent blocking function completion
		go func() {
			w.logger.Info().
				Str("container_id", containerID).
				Msg("Starting background container removal")

			if err := w.pool.docker.RemoveContainer(removeCtx, containerID); err != nil {
				w.logger.Warn().Err(err).Str("container_id", containerID).Msg("Failed to remove container")
			} else {
				w.logger.Info().Str("container_id", containerID).Msg("Successfully removed container")
			}
		}()
	}()

	// Start container
	if err := w.pool.docker.StartContainer(ctx, containerID); err != nil {
		w.handleExecutionError(job, fmt.Errorf("failed to start container: %w", err))
		return
	}

	// Wait for container with timeout
	statusCh, errCh := w.pool.docker.ContainerWait(ctx, containerID, container.WaitConditionNotRunning)

	// Add timeout channel
	timeoutCh := time.After(containerTimeout)

	select {
	case err := <-errCh:
		w.logger.Error().
			Err(err).
			Str("container_id", containerID).
			Msg("Container wait error")
		w.handleExecutionError(job, err)
		return
	case status := <-statusCh:
		// Get logs regardless of status code
		logs, logErr := w.pool.docker.ContainerLogs(ctx, containerID)
		if logErr == nil {
			defer logs.Close()

			// Special case for ECS tasks - check if this is an ECS ARN
			isEcsTask := strings.HasPrefix(containerID, "arn:aws:ecs:")
			if isEcsTask {
				w.logger.Info().Str("task_arn", containerID).Msg("Processing ECS task response")

				// Get the task payload from container logs - this is just to get the payload for ECS tasks
				payload := getRawLogsContent(logs)
				w.logger.Debug().Str("ecs_response", payload).Msg("Raw ECS response")

				// Create direct success response with payload from container logs
				duration := time.Since(startTime)
				finishedAt := time.Now()
				durationMs := int(duration.Milliseconds())

				// Try to extract payload from the ECS response
				var responseData map[string]interface{}
				var result interface{} = map[string]interface{}{
					"message": "Function executed successfully",
					"output":  "Function output from ECS task",
				}

				// Parse the log content to find the payload
				if err := json.Unmarshal([]byte(payload), &responseData); err == nil {
					w.logger.Info().Msg("Successfully parsed JSON from ECS response")

					// Try to locate useful fields in the response
					if _, ok := responseData["output"]; ok {
						result = responseData
						w.logger.Info().Msg("Found output field in ECS response")
					} else if body, ok := responseData["body"]; ok {
						result = body
						w.logger.Info().Msg("Found body field in ECS response")
					} else if _, ok := responseData["message"]; ok {
						result = responseData
						w.logger.Info().Msg("Found message field in ECS response")
					}
				} else {
					// Try to look for JSON in the content
					startIdx := strings.Index(payload, "{")
					endIdx := strings.LastIndex(payload, "}")
					if startIdx >= 0 && endIdx > startIdx {
						jsonStr := payload[startIdx : endIdx+1]
						if err := json.Unmarshal([]byte(jsonStr), &responseData); err == nil {
							result = responseData
							w.logger.Info().Msg("Found embedded JSON in ECS response")
						}
					}
				}

				// Create function response
				response := &models.FunctionResponse{
					RequestID:  job.RequestID,
					Status:     models.ExecutionStatusCompleted,
					StartedAt:  startTime,
					FinishedAt: &finishedAt,
					Duration:   &durationMs,
					Result:     result,
				}

				// Update function log
				if err := w.pool.db.UpdateFunctionLog(ctx, &models.FunctionLog{
					RequestID:  job.RequestID,
					Status:     models.ExecutionStatusCompleted,
					FinishedAt: response.FinishedAt,
					Duration:   response.Duration,
					Stdout:     &payload,
				}); err != nil {
					w.logger.Error().Err(err).Str("request_id", job.RequestID).Msg("Failed to update function log")
				}

				// Send response if synchronous invocation
				if !job.Async {
					job.ResponseChan <- response
				}
				return
			}

			// Create buffers for stdout and stderr
			stdout := new(bytes.Buffer)
			stderr := new(bytes.Buffer)

			// Use Docker's stdcopy to properly handle the multiplexed stream
			_, _ = stdcopy.StdCopy(stdout, stderr, logs)

			// Log the full output for debugging
			w.logger.Debug().
				Str("stdout", stdout.String()).
				Str("stderr", stderr.String()).
				Int64("status_code", status.StatusCode).
				Msg("Container logs")

			// If failed, handle the error with logs
			if status.StatusCode != 0 {
				w.handleExecutionError(job, fmt.Errorf("function failed with status code: %d, logs: %s",
					status.StatusCode, stdout.String()))
				return
			}

			// Process the logs for successful execution
			// Get the log content as string
			stdoutStr := stdout.String()
			stderrStr := stderr.String()

			// Parse the response from stdout
			var functionResponse struct {
				StatusCode int               `json:"statusCode"`
				Headers    map[string]string `json:"headers"`
				Body       interface{}       `json:"body"`
			}

			// Default response in case we can't parse JSON
			functionResponse.StatusCode = 200

			// Try to extract a valid JSON from the output
			logLines := strings.Split(strings.TrimSpace(stdoutStr), "\n")
			foundJson := false

			// First look for the special function output marker from CloudWatch logs
			for i, line := range logLines {
				if strings.TrimSpace(line) == "--- Function Output ---" && i < len(logLines)-1 {
					// Next line should contain the JSON output
					jsonLine := logLines[i+1]
					w.logger.Debug().Str("json_line", jsonLine).Msg("Found function output marker")

					if err := json.Unmarshal([]byte(jsonLine), &functionResponse); err == nil {
						w.logger.Info().Msg("Successfully parsed JSON from function output marker")
						foundJson = true
						break
					} else {
						w.logger.Warn().Err(err).Str("json_line", jsonLine).Msg("Failed to parse JSON after marker")
					}
				}
			}

			// If no marker found, try each line from the end to find valid JSON
			if !foundJson {
				w.logger.Debug().Msg("No output marker found, searching all log lines")
				for i := len(logLines) - 1; i >= 0; i-- {
					line := logLines[i]
					// Skip empty lines
					if strings.TrimSpace(line) == "" {
						continue
					}

					// Only try lines that look like JSON
					if strings.HasPrefix(strings.TrimSpace(line), "{") && strings.HasSuffix(strings.TrimSpace(line), "}") {
						w.logger.Debug().Str("potential_json", line).Msg("Found potential JSON line")

						// Try to parse JSON as our standard response first
						if err := json.Unmarshal([]byte(line), &functionResponse); err == nil {
							w.logger.Info().Msg("Successfully parsed JSON from log line")
							foundJson = true
							break
						}

						// If that fails, check for ECS response format (output+result fields)
						var ecsResponse struct {
							Output string      `json:"output"`
							Result interface{} `json:"result"`
						}

						if err := json.Unmarshal([]byte(line), &ecsResponse); err == nil {
							w.logger.Info().Msg("Successfully parsed ECS response format JSON")

							// Try to extract the function result from the result field
							if ecsResponse.Result != nil {
								resultBytes, err := json.Marshal(ecsResponse.Result)
								if err == nil {
									// Try to parse as function response
									if err := json.Unmarshal(resultBytes, &functionResponse); err == nil {
										w.logger.Info().Msg("Successfully extracted function response from ECS result")
										foundJson = true
										break
									}

									// If direct mapping fails, use the result as the body
									functionResponse.Body = ecsResponse.Result
									functionResponse.StatusCode = 200
									w.logger.Info().Msg("Using ECS result as function body")
									foundJson = true
									break
								}
							}

							// If all else fails, use the output as the body
							functionResponse.Body = map[string]interface{}{
								"message": "Function executed successfully",
								"output":  ecsResponse.Output,
							}
							functionResponse.StatusCode = 200
							w.logger.Info().Msg("Using ECS output as function body")
							foundJson = true
							break
						}
					}
				}
			}

			// If no valid JSON found, use the full output as the result body
			if !foundJson {
				w.logger.Info().
					Str("stdout", stdoutStr).
					Msg("No valid JSON response found, using raw output")

				// First, check if there's a FUNCTION OUTPUT marker in the logs
				functionOutput := ""
				logLines := strings.Split(stdoutStr, "\n")

				// Look for output between markers
				var outputLines []string
				inOutputSection := false

				for _, line := range logLines {
					trimmedLine := strings.TrimSpace(line)
					if strings.Contains(trimmedLine, "--- FUNCTION OUTPUT ---") {
						inOutputSection = true
						continue
					} else if inOutputSection {
						if strings.Contains(trimmedLine, "----------------------") {
							break
						}
						outputLines = append(outputLines, trimmedLine)
					}
				}

				// If we found marked output, use that
				if len(outputLines) > 0 {
					w.logger.Info().
						Strs("output_lines", outputLines).
						Msg("Found output between function output markers")

					// Join the output lines
					functionOutput = strings.Join(outputLines, "\n")
					trimmedOutput := strings.TrimSpace(functionOutput)

					// Check if the output is valid JSON
					if strings.HasPrefix(trimmedOutput, "{") && strings.HasSuffix(trimmedOutput, "}") {
						var jsonOutput interface{}
						if err := json.Unmarshal([]byte(trimmedOutput), &jsonOutput); err == nil {
							w.logger.Info().Msg("Output section contains valid JSON")
							functionResponse.Body = jsonOutput
							foundJson = true
						} else {
							w.logger.Info().Err(err).Msg("Output section is not valid JSON")
						}
					}
				}

				// If we still haven't found valid JSON, try alternatives
				if !foundJson {
					// Look for "Execution successful:" pattern
					for _, line := range logLines {
						if strings.Contains(line, "Execution successful:") {
							parts := strings.SplitN(line, "Execution successful:", 2)
							if len(parts) > 1 {
								jsonStr := strings.TrimSpace(parts[1])
								if strings.HasPrefix(jsonStr, "{") && strings.HasSuffix(jsonStr, "}") {
									var jsonOutput interface{}
									if err := json.Unmarshal([]byte(jsonStr), &jsonOutput); err == nil {
										w.logger.Info().Msg("Found JSON after 'Execution successful:'")
										functionResponse.Body = jsonOutput
										foundJson = true
										break
									}
								}
							}
						}
					}
				}

				// If still no JSON, look for any complete JSON object in the logs
				if !foundJson {
					for _, line := range logLines {
						trimmedLine := strings.TrimSpace(line)
						if strings.HasPrefix(trimmedLine, "{") && strings.HasSuffix(trimmedLine, "}") {
							var jsonOutput interface{}
							if err := json.Unmarshal([]byte(trimmedLine), &jsonOutput); err == nil {
								// Check if it has fields we expect from our function
								jsonMap, isMap := jsonOutput.(map[string]interface{})
								if isMap {
									// Check for typical fields our handler would include
									if _, hasMessage := jsonMap["message"]; hasMessage {
										if _, hasInput := jsonMap["input"]; hasInput {
											w.logger.Info().Msg("Found likely function response JSON with message and input fields")
											functionResponse.Body = jsonOutput
											foundJson = true
											break
										}
									}
									// Try with timestamp field too
									if _, hasTimestamp := jsonMap["timestamp"]; hasTimestamp {
										w.logger.Info().Msg("Found likely function response JSON with timestamp field")
										functionResponse.Body = jsonOutput
										foundJson = true
										break
									}
								}

								// If we didn't find specific fields but have valid JSON, log it
								w.logger.Info().Msg("Found JSON object in logs, may not be function output")
							}
						}
					}
				}

				// If we still don't have JSON, extract the meaningful log lines
				if !foundJson {
					// Extract only non-empty and non-system messages
					var nonEmptyLines []string
					for _, line := range logLines {
						trimmedLine := strings.TrimSpace(line)
						if trimmedLine == "" {
							continue
						}

						// Skip system messages
						if strings.Contains(trimmedLine, "Lambda internal") ||
							strings.Contains(trimmedLine, "INIT_START") ||
							strings.Contains(trimmedLine, "AWS_") {
							continue
						}

						// Skip log timestamps and metadata
						if strings.HasPrefix(trimmedLine, "[20") && strings.Contains(trimmedLine, "Z]") {
							// This is likely a timestamp prefix, extract the message part
							parts := strings.SplitN(trimmedLine, "] ", 2)
							if len(parts) > 1 {
								// Add the message part without the timestamp
								nonEmptyLines = append(nonEmptyLines, parts[1])
							} else {
								// If we can't split, keep the original line
								nonEmptyLines = append(nonEmptyLines, trimmedLine)
							}
						} else {
							nonEmptyLines = append(nonEmptyLines, trimmedLine)
						}
					}

					// Use the filtered output
					output := strings.Join(nonEmptyLines, "\n")
					functionResponse.Body = map[string]interface{}{
						"message": "Function executed successfully",
						"output":  output,
					}
				}

				// Update metrics
				duration := time.Since(startTime)
				w.pool.metrics.recordExecution(job.FunctionID, duration)

				finishedAt := time.Now()
				durationMs := int(duration.Milliseconds())

				// Create function response
				response := &models.FunctionResponse{
					RequestID:  job.RequestID,
					Status:     models.ExecutionStatusCompleted,
					StartedAt:  startTime,
					FinishedAt: &finishedAt,
					Duration:   &durationMs,
					Result:     functionResponse.Body,
				}

				// Update function log with both stdout and stderr
				if err := w.pool.db.UpdateFunctionLog(ctx, &models.FunctionLog{
					RequestID:  job.RequestID,
					Status:     models.ExecutionStatusCompleted,
					FinishedAt: response.FinishedAt,
					Duration:   response.Duration,
					Stdout:     &stdoutStr,
					Stderr:     &stderrStr,
				}); err != nil {
					w.logger.Error().Err(err).Str("request_id", job.RequestID).Msg("Failed to update function log")
				}

				// Send response if synchronous invocation
				if !job.Async {
					job.ResponseChan <- response
				}

				w.logger.Debug().
					Str("raw_logs", stdoutStr).
					Msg("Raw stdout logs received from container")

				w.logger.Debug().
					Interface("function_response", functionResponse).
					Msg("Parsed function response before returning")

				return
			} else {
				// Failed to get logs
				w.logger.Error().
					Err(logErr).
					Str("container_id", containerID).
					Int64("status_code", status.StatusCode).
					Msg("Failed to get container logs")

				if status.StatusCode != 0 {
					w.handleExecutionError(job, fmt.Errorf("function failed with status code: %d", status.StatusCode))
				} else {
					// Even with no logs, if the exit code was 0, we should return a success
					duration := time.Since(startTime)
					finishedAt := time.Now()
					durationMs := int(duration.Milliseconds())

					// Create basic success response
					response := &models.FunctionResponse{
						RequestID:  job.RequestID,
						Status:     models.ExecutionStatusCompleted,
						StartedAt:  startTime,
						FinishedAt: &finishedAt,
						Duration:   &durationMs,
						Result:     map[string]interface{}{"message": "Function executed successfully"},
					}

					// Update function log
					if err := w.pool.db.UpdateFunctionLog(ctx, &models.FunctionLog{
						RequestID:  job.RequestID,
						Status:     models.ExecutionStatusCompleted,
						FinishedAt: response.FinishedAt,
						Duration:   response.Duration,
					}); err != nil {
						w.logger.Error().Err(err).Str("request_id", job.RequestID).Msg("Failed to update function log")
					}

					// Send response if synchronous invocation
					if !job.Async {
						job.ResponseChan <- response
					}
				}
				return
			}
		}
	case <-timeoutCh:
		w.handleExecutionError(job, fmt.Errorf("function execution timed out after %v seconds", job.Timeout))
		return
	}
}

func (w *Worker) handleExecutionError(job *models.WorkerJob, err error) {
	w.logger.Error().Err(err).
		Str("function_id", job.FunctionID).
		Str("request_id", job.RequestID).
		Msg("Function execution failed")

	w.pool.metrics.incrementFailedJobs()

	// Update function log
	errMsg := err.Error()
	now := time.Now()
	if dbErr := w.pool.db.UpdateFunctionLog(context.Background(), &models.FunctionLog{
		RequestID:    job.RequestID,
		Status:       models.ExecutionStatusFailed,
		FinishedAt:   &now,
		ErrorMessage: &errMsg,
	}); dbErr != nil {
		w.logger.Error().Err(dbErr).Str("request_id", job.RequestID).Msg("Failed to update function log")
	}

	// Send error if synchronous invocation
	if !job.Async {
		job.ErrorChan <- err
	}
}

func (w *Worker) prepareEnvironment(job *models.WorkerJob) []string {
	env := []string{
		fmt.Sprintf("FUNCTION_HANDLER=%s", job.Handler),
		fmt.Sprintf("REQUEST_ID=%s", job.RequestID),
	}

	// Add custom environment variables
	for _, e := range job.Environment {
		env = append(env, fmt.Sprintf("%s=%s", e.Key, e.Value))
	}

	return env
}

// Metrics methods

func newWorkerMetrics() *WorkerMetrics {
	return &WorkerMetrics{
		resourceMetrics: make(map[string]*ResourceMetrics),
	}
}

func (m *WorkerMetrics) incrementActiveWorkers() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.activeWorkers++
}

func (m *WorkerMetrics) decrementActiveWorkers() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.activeWorkers--
}

func (m *WorkerMetrics) incrementFailedJobs() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failedJobs++
}

func (m *WorkerMetrics) recordExecution(functionID string, duration time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.completedJobs++
	m.totalExecutions++

	// Update average latency
	m.averageLatency = time.Duration((float64(m.averageLatency)*float64(m.totalExecutions-1) + float64(duration)) / float64(m.totalExecutions))

	// Track per-function metrics
	if _, exists := m.resourceMetrics[functionID]; !exists {
		m.resourceMetrics[functionID] = &ResourceMetrics{}
	}
	m.resourceMetrics[functionID].executions++
}

// RemoveContainer removes a container with an extended timeout for ECS tasks
func (p *WorkerPool) RemoveContainer(ctx context.Context, containerID string) error {
	// Add detailed debugging
	p.logger.Info().
		Str("container_id", containerID).
		Str("container_id_length", fmt.Sprintf("%d", len(containerID))).
		Str("runtime_mode", os.Getenv("RUNTIME_MODE")).
		Str("force_local", os.Getenv("FORCE_LOCAL_EXECUTION")).
		Msg("RemoveContainer called in worker pool")

	// Get the type of docker client to understand what's being used
	dockerClientType := fmt.Sprintf("%T", p.docker)
	p.logger.Info().
		Str("docker_client_type", dockerClientType).
		Msg("Docker client type")

	// For 64-character Docker container IDs, truncate to 32 characters
	// This is necessary for ECS compatibility (taskId length should be 32 or 36)
	if len(containerID) == 64 && isHexString(containerID) {
		truncatedID := containerID[:32]
		p.logger.Info().
			Str("original_id", containerID).
			Str("truncated_id", truncatedID).
			Msg("Truncating Docker container ID to 32 characters for compatibility")
		containerID = truncatedID
	}

	// Check if it's an ECS ARN
	isEcs := strings.HasPrefix(containerID, "arn:aws:ecs:")
	// Check if it's a Docker container ID (now 32 hex characters after potential truncation)
	isDockerContainerId := len(containerID) == 32 && isHexString(containerID)

	p.logger.Info().
		Bool("is_ecs_arn", isEcs).
		Bool("is_docker_id", isDockerContainerId).
		Msg("Container ID analysis")

	// Check for FORCE_LOCAL_EXECUTION
	if strings.ToLower(os.Getenv("FORCE_LOCAL_EXECUTION")) == "true" {
		p.logger.Info().
			Str("container_id", containerID).
			Msg("Force local execution enabled, using local Docker cleanup")
		return p.docker.RemoveContainer(ctx, containerID)
	}

	// Use a longer timeout for ECS tasks or Docker container IDs
	if isEcs || isDockerContainerId {
		if isDockerContainerId {
			p.logger.Info().
				Str("container_id", containerID).
				Msg("Docker container ID detected, using extended timeout")
		} else {
			p.logger.Info().
				Str("task_arn", containerID).
				Msg("ECS task ARN detected, using extended timeout")
		}

		// Create a longer context timeout for ECS cleanup (120 seconds)
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
		defer cancel()

		// Try to remove container with longer timeout
		err := p.docker.RemoveContainer(cleanupCtx, containerID)
		if err != nil {
			p.logger.Warn().
				Err(err).
				Str("container_id", containerID).
				Msg("Error stopping container, but continuing")

			// Don't return the error as it will be cleaned up eventually
			return nil
		}

		return nil
	}

	// For local Docker, use regular timeout
	return p.docker.RemoveContainer(ctx, containerID)
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

// Helper function to read logs as a plain string
func getRawLogsContent(logs io.Reader) string {
	buf := new(bytes.Buffer)
	buf.ReadFrom(logs)
	return buf.String()
}
