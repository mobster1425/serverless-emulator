package runtime

import (
//	"context"
//	"io"
	"serverless-emulator/internal/models"
	"serverless-emulator/internal/storage"
	"time"

//	"github.com/docker/docker/api/types/container"
)


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
