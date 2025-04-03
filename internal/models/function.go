package models

import (
	"errors"
	"fmt"
	"time"
	"encoding/json"
)

// Common errors
var (
	ErrNotFound      = errors.New("record not found")
	ErrAlreadyExists = errors.New("record already exists")
	ErrInvalidInput  = errors.New("invalid input")
)

// Runtime represents supported function runtimes
type Runtime string

const (
	RuntimeNodeJS14 Runtime = "nodejs14"
	RuntimeNodeJS16 Runtime = "nodejs16"
	RuntimeNodeJS18 Runtime = "nodejs18"
	RuntimePython38 Runtime = "python3.8"
	RuntimePython39 Runtime = "python3.9"
	RuntimePython310 Runtime = "python3.10"
	RuntimeGo116    Runtime = "go1.16"
	RuntimeGo117    Runtime = "go1.17"
	RuntimeGo118    Runtime = "go1.18"
)

// FunctionStatus represents the current status of a function
type FunctionStatus string

const (
	FunctionStatusPending   FunctionStatus = "pending"
	FunctionStatusActive    FunctionStatus = "active"
	FunctionStatusInactive  FunctionStatus = "inactive"
	FunctionStatusError     FunctionStatus = "error"
)

// ExecutionStatus represents the status of a function execution
type ExecutionStatus string

const (
	ExecutionStatusQueued     ExecutionStatus = "queued"
	ExecutionStatusStarting   ExecutionStatus = "starting"
	ExecutionStatusRunning    ExecutionStatus = "running"
	ExecutionStatusCompleted  ExecutionStatus = "completed"
	ExecutionStatusFailed     ExecutionStatus = "failed"
	ExecutionStatusTimedOut   ExecutionStatus = "timedout"
)

// EnvVar represents an environment variable
type EnvVar struct {
	Key   string `json:"key" db:"key"`
	Value string `json:"value" db:"value"`
}

// Function represents a serverless function
type Function struct {
	ID          string         `json:"id" db:"id"`
	Name        string         `json:"name" db:"name"`
	Runtime     Runtime        `json:"runtime" db:"runtime"`
	Handler     string         `json:"handler" db:"handler"`
	CodePath    string         `json:"code_path" db:"code_path"`
	ImageName   string         `json:"image_name" db:"image_name"`
	Status      FunctionStatus `json:"status" db:"status"`
	Memory      int64         `json:"memory" db:"memory"`         // in MB
	Timeout     int           `json:"timeout" db:"timeout"`       // in seconds
	Environment []EnvVar      `json:"environment" db:"environment"`
	CreatedAt   time.Time     `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time     `json:"updated_at" db:"updated_at"`
}

// FunctionLog represents a log entry for a function execution
type FunctionLog struct {
	ID           string          `json:"id" db:"id"`
	FunctionID   string          `json:"function_id" db:"function_id"`
	RequestID    string          `json:"request_id" db:"request_id"`
	Status       ExecutionStatus `json:"status" db:"status"`
	StartedAt    time.Time       `json:"started_at" db:"started_at"`
	FinishedAt   *time.Time      `json:"finished_at,omitempty" db:"finished_at"`
	Duration     *int            `json:"duration,omitempty" db:"duration"`       // in milliseconds
	MemoryUsed   *int64          `json:"memory_used,omitempty" db:"memory_used"` // in MB
	CPUUsed      *float64        `json:"cpu_used,omitempty" db:"cpu_used"`      // in CPU units
	ErrorMessage *string         `json:"error_message,omitempty" db:"error_message"`
	Stdout       *string         `json:"stdout,omitempty" db:"stdout"`
	Stderr       *string         `json:"stderr,omitempty" db:"stderr"`
}

// Request types for API endpoints

// CreateFunctionRequest represents the request body for creating a new function
type CreateFunctionRequest struct {
	Name        string    `json:"name" binding:"required"`
	Runtime     Runtime   `json:"runtime" binding:"required"`
	Handler     string    `json:"handler" binding:"required"`
	Memory      *int64    `json:"memory,omitempty"`      // optional, will use default if not provided
	Timeout     *int      `json:"timeout,omitempty"`     // optional, will use default if not provided
	Environment []EnvVar  `json:"environment,omitempty"` // optional environment variables
	Code        []byte    `json:"-"`                     // raw function code (from file upload)
	CodeType    string    `json:"code_type,omitempty"`   // zip, js, py, go, etc.
	
	
}

// UpdateFunctionRequest represents the request body for updating a function
type UpdateFunctionRequest struct {
	Name        *string   `json:"name,omitempty"`
	Handler     *string   `json:"handler,omitempty"`
	Memory      *int64    `json:"memory,omitempty"`
	Timeout     *int      `json:"timeout,omitempty"`
	Environment []EnvVar  `json:"environment,omitempty"`
	Code        []byte    `json:"-"`                   // raw function code (from file upload)
	CodeType    string    `json:"code_type,omitempty"` // zip, js, py, go, etc.
}

// InvokeFunctionRequest represents the request to invoke a function
type InvokeFunctionRequest struct {
	FunctionID string          `json:"function_id" binding:"required"`
	RequestID  string          `json:"request_id"`          // optional, will be generated if not provided
	Payload    json.RawMessage `json:"payload,omitempty"`   // function input data
	Async      bool            `json:"async"`               // whether to wait for execution result
}

// FunctionResponse represents the response from a function execution
type FunctionResponse struct {
	RequestID    string          `json:"request_id"`
	Status       ExecutionStatus `json:"status"`
	StartedAt    time.Time       `json:"started_at"`
	FinishedAt   *time.Time      `json:"finished_at,omitempty"`
	Duration     *int            `json:"duration,omitempty"`      // in milliseconds
	Result       interface{}     `json:"result,omitempty"`       // function output
	ErrorMessage *string         `json:"error_message,omitempty"`
}

// WorkerJob represents a job to be processed by the worker pool
type WorkerJob struct {
	InvocationMessage *InvocationMessage
	ResponseChan     chan *FunctionResponse
	ErrorChan        chan error
	Async            bool
	Timeout          int
	Memory           int64
	Handler          string
	ImageName        string
	Environment      []EnvVar
	CodePath         string
	RequestID        string
	FunctionID       string
	CPU              float64
	StopSignal       string
	StopTimeout      int
	

}

// InvocationMessage contains the details needed to invoke a function
type InvocationMessage struct {
	RequestID    string            `json:"request_id"`
	FunctionID   string            `json:"function_id"`
	Payload      json.RawMessage   `json:"payload,omitempty"`
	Headers      map[string]string `json:"headers,omitempty"`
	QueryParams  map[string]string `json:"query_params,omitempty"`
	PathParams   map[string]string `json:"path_params,omitempty"`
	Method       string            `json:"method"`
	Timeout      int               `json:"timeout"`
	Memory       int64             `json:"memory"`
	Handler      string            `json:"handler"`
	ImageName    string            `json:"image_name"`
}


// Validation functions

// Validate checks if a function configuration is valid
func (f *Function) Validate() error {
	if f.Name == "" {
		return errors.New("function name is required")
	}
	if !IsValidRuntime(f.Runtime) {
		return fmt.Errorf("invalid runtime: %s", f.Runtime)
	}
	if f.Handler == "" {
		return errors.New("function handler is required")
	}
	if f.Memory < 128 || f.Memory > 10240 {
		return errors.New("memory must be between 128MB and 10GB")
	}
	if f.Timeout < 1 || f.Timeout > 900 {
		return errors.New("timeout must be between 1 and 900 seconds")
	}
	return validateEnvironmentVariables(f.Environment)
}

// IsValidRuntime checks if the provided runtime is supported
func IsValidRuntime(r Runtime) bool {
	switch r {
	case RuntimeNodeJS14, RuntimeNodeJS16, RuntimeNodeJS18,
		RuntimePython38, RuntimePython39, RuntimePython310,
		RuntimeGo116, RuntimeGo117, RuntimeGo118:
		return true
	default:
		return false
	}
}

// GetDefaultsForRuntime returns default configurations for a given runtime
func GetDefaultsForRuntime(r Runtime) (string, int64, int) {
	switch r {
	case RuntimeNodeJS14, RuntimeNodeJS16, RuntimeNodeJS18:
		return "index.handler", 128, 300 // handler, memory (MB), timeout (seconds)
	case RuntimePython38, RuntimePython39, RuntimePython310:
		return "main.handler", 128, 300
	case RuntimeGo116, RuntimeGo117, RuntimeGo118:
		return "main.Handle", 128, 300
	default:
		return "", 128, 300
	}
}

// validateEnvironmentVariables checks if environment variables are valid
func validateEnvironmentVariables(envVars []EnvVar) error {
	seen := make(map[string]struct{})
	for _, env := range envVars {
		if env.Key == "" {
			return errors.New("environment variable key cannot be empty")
		}
		if _, exists := seen[env.Key]; exists {
			return fmt.Errorf("duplicate environment variable key: %s", env.Key)
		}
		seen[env.Key] = struct{}{}
	}
	return nil
}