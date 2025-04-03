package runtime

import (
	"context"
	"io"
	"serverless-emulator/internal/types"

	"github.com/docker/docker/api/types/container"
)

type RuntimeClient interface {
	BuildImage(ctx context.Context, opts *BuildImageOptions) error
	RemoveImage(ctx context.Context, imageName string) error
	CreateContainer(ctx context.Context, config *container.Config, hostConfig *container.HostConfig, name string) (container.CreateResponse, error)
	StartContainer(ctx context.Context, containerID string) error
	StopContainer(ctx context.Context, containerID string) error
	RemoveContainer(ctx context.Context, containerID string) error
	ContainerLogs(ctx context.Context, containerID string) (io.ReadCloser, error)
	ContainerWait(ctx context.Context, containerID string, condition container.WaitCondition) (<-chan types.ContainerWaitResponse, <-chan error)
	Ping(ctx context.Context) error
	IsDockerHubEnabled() bool
	GetDockerHubUsername() string
	CleanupResources(ctx context.Context) error
}
