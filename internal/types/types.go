package types

// ContainerWaitResponse represents the response from container wait operations
type ContainerWaitResponse struct {
    StatusCode int64  `json:"StatusCode"`
    Error      *struct {
        Message string `json:"Message"`
    } `json:"Error,omitempty"`
} 