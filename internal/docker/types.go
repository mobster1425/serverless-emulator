package docker

import (
	"encoding/json"
	"fmt"
	"io"
	"serverless-emulator/internal/models"
	"serverless-emulator/internal/runtime"
	"serverless-emulator/internal/storage"
	"time"
)

// RuntimeDefinition contains the configuration for a specific runtime
type RuntimeDefinition struct {
	BaseImage   string
	PreInstall  []string
	BuildScript string
}

// runtimeDefinitions maps runtime identifiers to their configurations
var runtimeDefinitions = map[models.Runtime]RuntimeDefinition{
	models.RuntimeNodeJS14: {
		BaseImage: "node:14-alpine",
		PreInstall: []string{
			"npm install",
		},
	},
	models.RuntimeNodeJS16: {
		BaseImage: "node:16-alpine",
		PreInstall: []string{
			"npm install",
		},
	},
	models.RuntimeNodeJS18: {
		BaseImage: "node:18-alpine",
		PreInstall: []string{
			"npm install",
		},
	},
	models.RuntimePython38: {
		BaseImage: "python:3.8-alpine",
		PreInstall: []string{
			"pip install -r requirements.txt",
		},
	},
	models.RuntimePython39: {
		BaseImage: "python:3.9-alpine",
		PreInstall: []string{
			"pip install -r requirements.txt",
		},
	},
	models.RuntimePython310: {
		BaseImage: "python:3.10-alpine",
		PreInstall: []string{
			"pip install -r requirements.txt",
		},
	},
	models.RuntimeGo116: {
		BaseImage: "golang:1.16-alpine",
		PreInstall: []string{
			"go mod download",
		},
		BuildScript: "go build -o function",
	},
	models.RuntimeGo117: {
		BaseImage: "golang:1.17-alpine",
		PreInstall: []string{
			"go mod download",
		},
		BuildScript: "go build -o function",
	},
	models.RuntimeGo118: {
		BaseImage: "golang:1.18-alpine",
		PreInstall: []string{
			"go mod download",
		},
		BuildScript: "go build -o function",
	},
}

// BuildImageOptions contains options for building a function image
type BuildImageOptions struct {
	ImageName   string
	CodePath    string
	Runtime     models.Runtime
	Handler     string
	Environment []models.EnvVar
	Timeout     time.Duration
	Memory      int64
	CPU         float64
	S3Client    *storage.S3Client
	S3Bucket    string
}

// CreateContainerOptions contains options for creating a container
type CreateContainerOptions struct {
	ImageName   string
	FunctionID  string
	RequestID   string
	Handler     string
	Timeout     int
	Memory      int64
	CPU         float64
	Environment map[string]string
	Payload     json.RawMessage
	Headers     map[string]string
	QueryParams map[string]string
	PathParams  map[string]string
	Method      string
}

// ContainerLogs represents the stdout and stderr output from a container
type ContainerLogs struct {
	Stdout string
	Stderr string
}

// ContainerWaitResponse represents the response from container wait operations
type ContainerWaitResponse struct {
	StatusCode int64 `json:"StatusCode"`
	Error      *struct {
		Message string `json:"Message"`
	} `json:"Error,omitempty"`
}

// Helper functions for docker client
func createBuildArgs(opts interface{}) map[string]*string {
	args := make(map[string]*string)

	switch o := opts.(type) {
	case *BuildImageOptions:
		// Handle internal BuildImageOptions
		handlerStr := o.Handler
		args["FUNCTION_HANDLER"] = &handlerStr

		memoryStr := fmt.Sprintf("%d", o.Memory)
		args["FUNCTION_MEMORY"] = &memoryStr

		cpuStr := fmt.Sprintf("%.2f", o.CPU)
		args["FUNCTION_CPU"] = &cpuStr

		timeoutStr := fmt.Sprintf("%d", int(o.Timeout.Seconds()))
		args["FUNCTION_TIMEOUT"] = &timeoutStr

		for _, env := range o.Environment {
			value := env.Value
			args[fmt.Sprintf("ENV_%s", env.Key)] = &value
		}

	case *runtime.BuildImageOptions:
		// Handle runtime.BuildImageOptions
		handlerStr := o.Handler
		args["FUNCTION_HANDLER"] = &handlerStr

		memoryStr := fmt.Sprintf("%d", o.Memory)
		args["FUNCTION_MEMORY"] = &memoryStr

		cpuStr := fmt.Sprintf("%.2f", o.CPU)
		args["FUNCTION_CPU"] = &cpuStr

		timeoutStr := fmt.Sprintf("%d", int(o.Timeout.Seconds()))
		args["FUNCTION_TIMEOUT"] = &timeoutStr

		for _, env := range o.Environment {
			value := env.Value
			args[fmt.Sprintf("ENV_%s", env.Key)] = &value
		}
	}

	return args
}

func readBuildOutput(body io.Reader) error {
	decoder := json.NewDecoder(body)
	for {
		var message struct {
			Stream string `json:"stream"`
			Error  string `json:"error"`
		}

		if err := decoder.Decode(&message); err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}

		if message.Error != "" {
			return fmt.Errorf("build error: %s", message.Error)
		}
	}
}
