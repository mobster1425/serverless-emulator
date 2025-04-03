package worker

import (
	"context"
	//"io"
	"serverless-emulator/internal/models"
	"serverless-emulator/internal/runtime"
)

// DB represents the database interface required by the worker pool
type DB interface {
	UpdateFunctionLogStatus(ctx context.Context, requestID string, status models.ExecutionStatus) error
	UpdateFunctionLog(ctx context.Context, log *models.FunctionLog) error
	GetFunction(ctx context.Context, functionID string) (*models.Function, error)
}

// Use RuntimeClient from runtime package
type RuntimeClient = runtime.RuntimeClient

// Queue represents the queue operations required by the worker pool
type Queue interface {
	EnqueueFunction(ctx context.Context, req *models.InvokeFunctionRequest) error
	DequeueFunction(ctx context.Context) (*models.InvokeFunctionRequest, error)
}

// ContainerLogs represents the container log output
type ContainerLogs struct {
	Stdout string
	Stderr string
}
