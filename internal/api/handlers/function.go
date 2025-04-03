package handlers

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	//"path/filepath"
	"strconv"
	//"os"
	"encoding/json"
	//"io"
	"strings"
	"time"

	"serverless-emulator/internal/models"
	"serverless-emulator/pkg/logger"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	//	"github.com/docker/docker/api/types/container"
	"serverless-emulator/internal/config"
	//	"serverless-emulator/internal/docker"
	"serverless-emulator/internal/queue"
	"serverless-emulator/internal/runtime"
	"serverless-emulator/internal/storage"
	"serverless-emulator/internal/worker"
)

// DB interface definition
type DB interface {
	CreateFunction(ctx context.Context, fn *models.Function) error
	GetFunction(ctx context.Context, id string) (*models.Function, error)
	ListFunctions(ctx context.Context, limit, offset int) ([]*models.Function, error)
	UpdateFunction(ctx context.Context, fn *models.Function) error
	DeleteFunction(ctx context.Context, id string) error
	CountFunctions(ctx context.Context) (int64, error)
	CreateFunctionLog(ctx context.Context, log *models.FunctionLog) error
	GetFunctionLogs(ctx context.Context, functionID string, limit, offset int) ([]*models.FunctionLog, error)
	GetFunctionLogByRequestID(ctx context.Context, requestID string) (*models.FunctionLog, error)
	UpdateFunctionLogStatus(ctx context.Context, requestID string, status models.ExecutionStatus) error
	UpdateFunctionLog(ctx context.Context, log *models.FunctionLog) error
}

// DockerClient interface definition
type DockerClient interface {
	BuildImage(ctx context.Context, opts *runtime.BuildImageOptions) error
	RemoveImage(ctx context.Context, imageName string) error
}

// Queue interface definition
type Queue interface {
	EnqueueFunction(ctx context.Context, req *models.InvokeFunctionRequest) error
	DequeueFunction(ctx context.Context, functionID string) (*queue.QueueMessage, error)
}

// WorkerPool interface definition
type WorkerPool interface {
	Submit(job *models.WorkerJob)
}

// FunctionHandlers contains the handlers for function management
type FunctionHandlers struct {
	db         DB
	docker     worker.RuntimeClient
	queue      Queue
	workerPool WorkerPool
	logger     *logger.Logger
	config     *config.Config
	s3Client   *storage.S3Client
}

// NewFunctionHandlers creates a new FunctionHandlers instance
func NewFunctionHandlers(db DB, docker worker.RuntimeClient, queue Queue, workerPool WorkerPool, logger *logger.Logger, config *config.Config, s3Client *storage.S3Client) *FunctionHandlers {
	return &FunctionHandlers{
		db:         db,
		docker:     docker,
		queue:      queue,
		workerPool: workerPool,
		logger:     logger,
		config:     config,
		s3Client:   s3Client,
	}
}

// CreateFunction handles the creation of a new function
func (h *FunctionHandlers) CreateFunction(c *gin.Context) {
	h.logger.Info().Msg("Starting function creation request")

	// Add request debugging
	h.logger.Debug().
		Str("content_type", c.GetHeader("Content-Type")).
		Str("content_length", c.GetHeader("Content-Length")).
		Msg("Request headers")

	// Get the multipart form with increased max memory and timeout
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 32<<20) // 32MB max
	if err := c.Request.ParseMultipartForm(32 << 20); err != nil {
		h.logger.Error().Err(err).Msg("Failed to parse multipart form")
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Failed to parse form: %v", err)})
		return
	}

	// Debug form data
	h.logger.Debug().
		Interface("form_values", c.Request.MultipartForm.Value).
		Interface("file_headers", c.Request.MultipartForm.File).
		Msg("Parsed multipart form")

	// Get the code file
	file, err := c.FormFile("code")
	if err != nil {
		h.logger.Error().Err(err).Msg("Failed to get code file")
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Code file is required: %v", err)})
		return
	}

	h.logger.Debug().
		Str("filename", file.Filename).
		Int64("size", file.Size).
		Str("content_type", file.Header.Get("Content-Type")).
		Msg("Received code file")

	// Get and parse the function data
	functionData := c.PostForm("data")
	if functionData == "" {
		h.logger.Error().Msg("No function data provided")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Function data is required"})
		return
	}

	h.logger.Debug().Str("function_data", functionData).Msg("Received function data")

	var req models.CreateFunctionRequest
	if err := json.Unmarshal([]byte(functionData), &req); err != nil {
		h.logger.Error().Err(err).
			Str("data", functionData).
			Msg("Failed to parse function data")
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Invalid function data format: %v", err)})
		return
	}

	// Validate request
	if err := validateCreateRequest(&req); err != nil {
		h.logger.Error().Err(err).Msg("Invalid function configuration")
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Set default values if not provided
	if req.Memory == nil {
		defaultMemory := int64(h.config.Docker.DefaultMemoryLimit)
		req.Memory = &defaultMemory
		h.logger.Debug().Int64("memory", *req.Memory).Msg("Using default memory")
	}

	if req.Timeout == nil {
		defaultTimeout := int(h.config.Docker.DefaultTimeout.Seconds())
		req.Timeout = &defaultTimeout
		h.logger.Debug().Int("timeout", *req.Timeout).Msg("Using default timeout")
	}

	// Generate unique ID for the function code path in S3
	codeID := uuid.New().String()
	s3Key := fmt.Sprintf("functions/%s/code", codeID)
	h.logger.Debug().Str("s3_key", s3Key).Msg("Generated S3 key")

	// Upload code to S3
	h.logger.Debug().Msg("Uploading code to S3")
	codePath, err := h.s3Client.UploadFileFromMultipart(c, file, s3Key)
	if err != nil {
		h.logger.Error().Err(err).Msg("Failed to upload code to S3")
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to upload code: %v", err)})
		return
	}
	h.logger.Debug().Str("code_path", codePath).Msg("Code uploaded to S3")

	// Create function object
	fn := &models.Function{
		Name:        req.Name,
		Runtime:     req.Runtime,
		Handler:     req.Handler,
		CodePath:    codePath,
		ImageName:   fmt.Sprintf("fn-%s", codeID),
		Status:      models.FunctionStatusActive,
		Memory:      *req.Memory,
		Timeout:     *req.Timeout,
		Environment: req.Environment,
	}

	// Build Docker image
	h.logger.Info().
		Str("runtime", string(req.Runtime)).
		Str("image", fn.ImageName).
		Msg("Building Docker image for function")

	// Download the code from S3 temporarily (needed for Docker build context)
	h.logger.Debug().Msg("Downloading code from S3 for build")
	_, err = h.s3Client.DownloadFile(c, s3Key)
	if err != nil {
		h.logger.Error().Err(err).Msg("Failed to download code from S3")
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to prepare build context: %v", err)})
		return
	}

	// Set up build options
	buildOpts := &runtime.BuildImageOptions{
		ImageName:   fn.ImageName,
		CodePath:    fn.CodePath,
		Runtime:     fn.Runtime,
		Handler:     fn.Handler,
		Environment: fn.Environment,
		Timeout:     time.Duration(fn.Timeout) * time.Second,
		Memory:      fn.Memory,
		CPU:         h.config.Docker.DefaultCPULimit,
		S3Client:    h.s3Client,
		S3Bucket:    h.config.S3.Bucket,
	}

	h.logger.Debug().
		Str("image_name", buildOpts.ImageName).
		Str("runtime", string(buildOpts.Runtime)).
		Str("handler", buildOpts.Handler).
		Int64("memory", buildOpts.Memory).
		Float64("cpu", buildOpts.CPU).
		Dur("timeout", buildOpts.Timeout).
		Msg("Build options prepared")

	// Build the Docker image
	ctx, cancel := context.WithTimeout(c, 5*time.Minute)
	defer cancel()

	h.logger.Debug().Msg("Calling docker.BuildImage")
	if err := h.docker.BuildImage(ctx, buildOpts); err != nil {
		h.logger.Error().Err(err).Msg("Failed to build Docker image")
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to build function image: %v", err)})
		return
	}

	h.logger.Debug().Msg("Docker image built successfully")

	// Save to database
	h.logger.Debug().Msg("Saving function to database")
	if err := h.db.CreateFunction(c, fn); err != nil {
		h.logger.Error().Err(err).Msg("Failed to save function to database")
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to create function: %v", err)})
		return
	}

	h.logger.Info().
		Str("id", fn.ID).
		Str("name", fn.Name).
		Str("runtime", string(fn.Runtime)).
		Msg("Function created successfully")

	c.JSON(http.StatusCreated, fn)
}

// GetFunction handles retrieving a function by ID
func (h *FunctionHandlers) GetFunction(c *gin.Context) {
	functionID := c.Param("id")
	if functionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Function ID is required"})
		return
	}

	fn, err := h.db.GetFunction(c, functionID)
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "Function not found"})
			return
		}
		h.logger.Error().Err(err).Msg("Failed to get function")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get function"})
		return
	}

	c.JSON(http.StatusOK, fn)
}

// ListFunctions handles retrieving a list of functions
func (h *FunctionHandlers) ListFunctions(c *gin.Context) {
	// Parse pagination parameters
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "10"))

	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 100 {
		limit = 10
	}

	offset := (page - 1) * limit

	// Get functions
	functions, err := h.db.ListFunctions(c, limit, offset)
	if err != nil {
		h.logger.Error().Err(err).Msg("Failed to list functions")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list functions"})
		return
	}

	// Get total count for pagination
	total, err := h.db.CountFunctions(c)
	if err != nil {
		h.logger.Error().Err(err).Msg("Failed to count functions")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to count functions"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"functions": functions,
		"pagination": gin.H{
			"current_page": page,
			"total_pages":  (total + int64(limit) - 1) / int64(limit),
			"total_items":  total,
			"limit":        limit,
		},
	})
}

// UpdateFunction handles updating an existing function
func (h *FunctionHandlers) UpdateFunction(c *gin.Context) {
	functionID := c.Param("id")
	if functionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Function ID is required"})
		return
	}

	var req models.UpdateFunctionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	// Get existing function
	fn, err := h.db.GetFunction(c, functionID)
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "Function not found"})
			return
		}
		h.logger.Error().Err(err).Msg("Failed to get function")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get function"})
		return
	}

	// Update fields if provided
	if req.Name != nil {
		fn.Name = *req.Name
	}
	if req.Handler != nil {
		fn.Handler = *req.Handler
	}
	if req.Memory != nil {
		fn.Memory = *req.Memory
	}
	if req.Timeout != nil {
		fn.Timeout = *req.Timeout
	}
	if req.Environment != nil {
		fn.Environment = req.Environment
	}

	// Handle code update if provided
	if file, err := c.FormFile("code"); err == nil {
		// Delete existing code from S3
		existingS3Key := strings.TrimPrefix(fn.CodePath, fmt.Sprintf("s3://%s/", h.config.S3.Bucket))
		if err := h.s3Client.DeleteFile(c, existingS3Key); err != nil {
			h.logger.Warn().Err(err).
				Str("function_id", fn.ID).
				Str("s3_key", existingS3Key).
				Msg("Failed to delete existing function code from S3")
			// Continue with upload even if deletion fails
		}

		// Upload new code to S3
		s3Key := fmt.Sprintf("functions/%s/code", fn.ID)
		s3Path, err := h.s3Client.UploadFileFromMultipart(c, file, s3Key)
		if err != nil {
			h.logger.Error().Err(err).Msg("Failed to upload updated function code to S3")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update function code"})
			return
		}

		fn.CodePath = s3Path

		// Rebuild Docker image
		if err := h.docker.BuildImage(c, &runtime.BuildImageOptions{
			CodePath:    s3Path,
			ImageName:   fn.ImageName,
			Runtime:     fn.Runtime,
			Handler:     fn.Handler,
			Memory:      fn.Memory,
			Timeout:     time.Duration(fn.Timeout) * time.Second,
			Environment: fn.Environment,
			CPU:         1.0,
			S3Client:    h.s3Client,
			S3Bucket:    h.config.S3.Bucket,
		}); err != nil {
			h.logger.Error().Err(err).Msg("Failed to rebuild function image")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to rebuild function image"})
			return
		}
	}

	// Update function in database
	if err := h.db.UpdateFunction(c, fn); err != nil {
		h.logger.Error().Err(err).Msg("Failed to update function")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update function"})
		return
	}

	c.JSON(http.StatusOK, fn)
}

// DeleteFunction handles deleting a function
func (h *FunctionHandlers) DeleteFunction(c *gin.Context) {
	functionID := c.Param("id")
	if functionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Function ID is required"})
		return
	}

	// Get function to get image name
	fn, err := h.db.GetFunction(c, functionID)
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "Function not found"})
			return
		}
		h.logger.Error().Err(err).Msg("Failed to get function")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete function"})
		return
	}

	// Delete Docker image
	if err := h.docker.RemoveImage(c, fn.ImageName); err != nil {
		h.logger.Error().Err(err).Msg("Failed to remove function image")
		// Continue with deletion even if image removal fails
	}

	// Delete code from S3
	s3Key := strings.TrimPrefix(fn.CodePath, fmt.Sprintf("s3://%s/", h.config.S3.Bucket))
	if err := h.s3Client.DeleteFile(c, s3Key); err != nil {
		h.logger.Error().Err(err).Msg("Failed to delete function code from S3")
		// Continue with deletion even if S3 deletion fails
	}

	// Delete function from database
	if err := h.db.DeleteFunction(c, functionID); err != nil {
		h.logger.Error().Err(err).Msg("Failed to delete function record")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete function"})
		return
	}

	c.Status(http.StatusNoContent)
}

// InvokeFunction handles function invocation requests
func (h *FunctionHandlers) InvokeFunction(c *gin.Context) {
	functionID := c.Param("id")
	if functionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Function ID is required"})
		return
	}

	// Get function metadata
	fn, err := h.db.GetFunction(c, functionID)
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "Function not found"})
			return
		}
		h.logger.Error().Err(err).Str("function_id", functionID).Msg("Failed to get function")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get function"})
		return
	}

	// Parse invocation request
	var req struct {
		Payload json.RawMessage `json:"payload"`
		Async   bool            `json:"async"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Error().Err(err).Msg("Failed to parse request body")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	// Create request ID
	requestID := uuid.New().String()

	// Create function log entry BEFORE execution
	functionLog := &models.FunctionLog{
		FunctionID: functionID,
		RequestID:  requestID,
		Status:     models.ExecutionStatusQueued,
		StartedAt:  time.Now().UTC(),
	}

	if err := h.db.CreateFunctionLog(c, functionLog); err != nil {
		h.logger.Error().Err(err).
			Str("function_id", functionID).
			Str("request_id", requestID).
			Msg("Failed to create function log")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create function log"})
		return
	}

	// Create invocation message
	invocation := &models.InvocationMessage{
		RequestID:   requestID,
		FunctionID:  functionID,
		Payload:     req.Payload,
		Headers:     getHeaders(c),
		QueryParams: getQueryParams(c),
		PathParams:  getPathParams(c),
		Method:      c.Request.Method,
		Timeout:     fn.Timeout,
		Memory:      fn.Memory,
		Handler:     fn.Handler,
		ImageName:   fn.ImageName,
	}

	// Create worker job
	resultChan := make(chan *models.FunctionResponse, 1)
	errorChan := make(chan error, 1)

	job := &models.WorkerJob{
		InvocationMessage: invocation,
		ResponseChan:      resultChan,
		ErrorChan:         errorChan,
		Async:             req.Async,
		Timeout:           fn.Timeout,
		Memory:            fn.Memory,
		Handler:           fn.Handler,
		ImageName:         fn.ImageName,
		RequestID:         requestID,
		FunctionID:        functionID,
	}

	// Update log status to running
	if err := h.db.UpdateFunctionLogStatus(c, requestID, models.ExecutionStatusRunning); err != nil {
		h.logger.Error().Err(err).
			Str("function_id", functionID).
			Str("request_id", requestID).
			Msg("Failed to update function log status")
	}

	h.workerPool.Submit(job)

	if req.Async {
		c.JSON(http.StatusAccepted, gin.H{
			"request_id": requestID,
			"status":     "queued",
		})
		return
	}

	// Wait for result with timeout
	select {
	case result := <-resultChan:
		// Update log status to completed
		if err := h.db.UpdateFunctionLog(c, &models.FunctionLog{
			RequestID:  requestID,
			Status:     models.ExecutionStatusCompleted,
			FinishedAt: result.FinishedAt,
			Duration:   result.Duration,
		}); err != nil {
			h.logger.Error().Err(err).
				Str("request_id", requestID).
				Msg("Failed to update function log")
		}
		c.JSON(http.StatusOK, result)

	case err := <-errorChan:
		now := time.Now().UTC()
		errMsg := err.Error()
		// Update log status to failed
		if dbErr := h.db.UpdateFunctionLog(c, &models.FunctionLog{
			RequestID:    requestID,
			Status:       models.ExecutionStatusFailed,
			FinishedAt:   &now,
			ErrorMessage: &errMsg,
		}); dbErr != nil {
			h.logger.Error().Err(dbErr).
				Str("request_id", requestID).
				Msg("Failed to update function log")
		}

		h.logger.Error().Err(err).
			Str("function_id", functionID).
			Str("request_id", requestID).
			Msg("Function execution failed")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":      "Function execution failed",
			"message":    err.Error(),
			"request_id": requestID,
		})

	case <-time.After(time.Duration(fn.Timeout) * time.Second):
		now := time.Now().UTC()
		// Update log status to timeout
		if err := h.db.UpdateFunctionLog(c, &models.FunctionLog{
			RequestID:  requestID,
			Status:     models.ExecutionStatusTimedOut,
			FinishedAt: &now,
		}); err != nil {
			h.logger.Error().Err(err).
				Str("request_id", requestID).
				Msg("Failed to update function log")
		}

		c.JSON(http.StatusGatewayTimeout, gin.H{
			"error":      "Function execution timed out",
			"request_id": requestID,
		})
	}
}

// Helper functions to get request details
func getHeaders(c *gin.Context) map[string]string {
	headers := make(map[string]string)
	for k, v := range c.Request.Header {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}
	return headers
}

func getQueryParams(c *gin.Context) map[string]string {
	params := make(map[string]string)
	for k, v := range c.Request.URL.Query() {
		if len(v) > 0 {
			params[k] = v[0]
		}
	}
	return params
}

func getPathParams(c *gin.Context) map[string]string {
	params := make(map[string]string)
	for _, param := range c.Params {
		params[param.Key] = param.Value
	}
	return params
}

// GetFunctionLogs handles retrieving logs for a function
func (h *FunctionHandlers) GetFunctionLogs(c *gin.Context) {
	functionID := c.Param("id")
	if functionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Function ID is required"})
		return
	}

	// Parse pagination parameters
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "10"))

	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 100 {
		limit = 10
	}

	offset := (page - 1) * limit

	// Get function logs
	logs, err := h.db.GetFunctionLogs(c, functionID, limit, offset)
	if err != nil {
		h.logger.Error().Err(err).
			Str("function_id", functionID).
			Msg("Failed to get function logs")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get function logs"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"logs": logs,
		"pagination": gin.H{
			"page":  page,
			"limit": limit,
		},
	})
}

// Helper functions

func validateCreateRequest(req *models.CreateFunctionRequest) error {
	if req.Name == "" {
		return errors.New("function name is required")
	}
	if req.Runtime == "" {
		return errors.New("runtime is required")
	}
	if !models.IsValidRuntime(req.Runtime) {
		return errors.New("invalid runtime specified")
	}
	if req.Handler == "" {
		return errors.New("handler is required")
	}

	// Set defaults if not provided
	if req.Memory == nil {
		defaultMem := int64(128) // 128MB default
		req.Memory = &defaultMem
	}
	if req.Timeout == nil {
		defaultTimeout := 300 // 300 seconds (5 minutes) default
		req.Timeout = &defaultTimeout
	}

	return nil
}

func (h *FunctionHandlers) handleAsyncInvocation(ctx context.Context, msg *models.InvocationMessage) error {
	return h.queue.EnqueueFunction(ctx, &models.InvokeFunctionRequest{
		FunctionID: msg.FunctionID,
		RequestID:  msg.RequestID,
		Payload:    msg.Payload,
		Async:      true,
	})
}

func (h *FunctionHandlers) handleSyncInvocation(ctx context.Context, msg *models.InvocationMessage) (*models.FunctionResponse, error) {
	resultChan := make(chan *models.FunctionResponse, 1)
	errorChan := make(chan error, 1)

	h.workerPool.Submit(&models.WorkerJob{
		InvocationMessage: msg,
		ResponseChan:      resultChan,
		ErrorChan:         errorChan,
	})

	select {
	case result := <-resultChan:
		return result, nil
	case err := <-errorChan:
		return nil, err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
