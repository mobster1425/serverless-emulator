package queue

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
	"serverless-emulator/internal/config"
	"serverless-emulator/internal/models"
)

const (
	// Queue names
	functionQueuePrefix = "fn:queue:"
	deadLetterQueue    = "fn:dlq"
	
	// Key prefixes
	functionStatePrefix = "fn:state:"
	functionLockPrefix  = "fn:lock:"
	
	// Default values
	defaultQueueTimeout = 30 * time.Second
	maxRetryCount      = 3
)

// QueueMessage represents a message in the queue
type QueueMessage struct {
	RequestID    string          `json:"request_id"`
	FunctionID   string          `json:"function_id"`
	Payload      json.RawMessage `json:"payload,omitempty"`
	RetryCount   int             `json:"retry_count"`
	FirstEnqueued time.Time      `json:"first_enqueued"`
	LastEnqueued  time.Time      `json:"last_enqueued"`
}

// Redis represents a Redis queue client
type Redis struct {
	client *redis.Client
	config config.RedisConfig
}

// NewRedis creates a new Redis queue client
func NewRedis(ctx context.Context, cfg config.RedisConfig) (*Redis, error) {
	client := redis.NewClient(&redis.Options{
		Addr:         cfg.Addr,
		Password:     cfg.Password,
		DB:           cfg.DB,
		DialTimeout:  5 * time.Second,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		PoolSize:     10,
		MinIdleConns: 5,
	})

	// Verify connection
	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	return &Redis{
		client: client,
		config: cfg,
	}, nil
}

// Close closes the Redis connection
func (r *Redis) Close() error {
	return r.client.Close()
}

// EnqueueFunction adds a function invocation request to the queue
func (r *Redis) EnqueueFunction(ctx context.Context, req *models.InvokeFunctionRequest) error {
	queueName := functionQueuePrefix + req.FunctionID

	msg := QueueMessage{
		RequestID:     req.RequestID,
		FunctionID:    req.FunctionID,
		Payload:       req.Payload,
		RetryCount:    0,
		FirstEnqueued: time.Now().UTC(),
		LastEnqueued:  time.Now().UTC(),
	}

	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal queue message: %w", err)
	}

	// Add to function-specific queue
	if err := r.client.LPush(ctx, queueName, data).Err(); err != nil {
		return fmt.Errorf("failed to enqueue function request: %w", err)
	}

	return nil
}

// DequeueFunction retrieves and removes a function invocation request from the queue
func (r *Redis) DequeueFunction(ctx context.Context, functionID string) (*QueueMessage, error) {
	queueName := functionQueuePrefix + functionID

	// Try to get message with timeout
	result, err := r.client.BRPop(ctx, defaultQueueTimeout, queueName).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, nil // No messages available
		}
		return nil, fmt.Errorf("failed to dequeue message: %w", err)
	}

	// result[0] is the queue name, result[1] is the message
	var msg QueueMessage
	if err := json.Unmarshal([]byte(result[1]), &msg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal queue message: %w", err)
	}

	return &msg, nil
}

// RequeueFunction puts a failed function invocation back in the queue for retry
func (r *Redis) RequeueFunction(ctx context.Context, msg *QueueMessage) error {
	if msg.RetryCount >= maxRetryCount {
		// Move to dead letter queue if max retries exceeded
		return r.moveToDeadLetterQueue(ctx, msg)
	}

	msg.RetryCount++
	msg.LastEnqueued = time.Now().UTC()

	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal queue message: %w", err)
	}

	queueName := functionQueuePrefix + msg.FunctionID

	// Add back to the queue with exponential backoff
	backoff := time.Duration(1<<uint(msg.RetryCount)) * time.Second
	if err := r.client.Set(ctx, 
		functionLockPrefix+msg.RequestID, 
		"locked", 
		backoff).Err(); err != nil {
		return fmt.Errorf("failed to set retry backoff: %w", err)
	}

	if err := r.client.LPush(ctx, queueName, data).Err(); err != nil {
		return fmt.Errorf("failed to requeue function request: %w", err)
	}

	return nil
}

// moveToDeadLetterQueue moves a failed message to the dead letter queue
func (r *Redis) moveToDeadLetterQueue(ctx context.Context, msg *QueueMessage) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal queue message: %w", err)
	}

	if err := r.client.LPush(ctx, deadLetterQueue, data).Err(); err != nil {
		return fmt.Errorf("failed to move message to DLQ: %w", err)
	}

	return nil
}

// GetDeadLetterMessages retrieves messages from the dead letter queue
func (r *Redis) GetDeadLetterMessages(ctx context.Context, limit int64) ([]*QueueMessage, error) {
	// Get messages without removing them
	results, err := r.client.LRange(ctx, deadLetterQueue, 0, limit-1).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get DLQ messages: %w", err)
	}

	messages := make([]*QueueMessage, 0, len(results))
	for _, result := range results {
		var msg QueueMessage
		if err := json.Unmarshal([]byte(result), &msg); err != nil {
			return nil, fmt.Errorf("failed to unmarshal DLQ message: %w", err)
		}
		messages = append(messages, &msg)
	}

	return messages, nil
}

// RetryDeadLetterMessage moves a message from DLQ back to the main queue
func (r *Redis) RetryDeadLetterMessage(ctx context.Context, requestID string) error {
	// Find and remove message from DLQ
	messages, err := r.GetDeadLetterMessages(ctx, -1) // Get all messages
	if err != nil {
		return err
	}

	var targetMsg *QueueMessage
	for _, msg := range messages {
		if msg.RequestID == requestID {
			targetMsg = msg
			break
		}
	}

	if targetMsg == nil {
		return fmt.Errorf("message with request ID %s not found in DLQ", requestID)
	}

	// Reset retry count and requeue
	targetMsg.RetryCount = 0
	targetMsg.LastEnqueued = time.Now().UTC()

	// Remove from DLQ and add to main queue
	pipe := r.client.Pipeline()
	
	// Remove the specific message from DLQ
	data, err := json.Marshal(targetMsg)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}
	pipe.LRem(ctx, deadLetterQueue, 1, string(data))
	
	// Add to main queue
	pipe.LPush(ctx, functionQueuePrefix+targetMsg.FunctionID, data)

	_, err = pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to retry DLQ message: %w", err)
	}

	return nil
}

// PurgeQueue removes all messages from a function's queue
func (r *Redis) PurgeQueue(ctx context.Context, functionID string) error {
	queueName := functionQueuePrefix + functionID
	if err := r.client.Del(ctx, queueName).Err(); err != nil {
		return fmt.Errorf("failed to purge queue: %w", err)
	}
	return nil
}

// GetQueueLength returns the number of messages in a function's queue
func (r *Redis) GetQueueLength(ctx context.Context, functionID string) (int64, error) {
	queueName := functionQueuePrefix + functionID
	length, err := r.client.LLen(ctx, queueName).Result()
	if err != nil {
		return 0, fmt.Errorf("failed to get queue length: %w", err)
	}
	return length, nil
}

// GetQueueMetrics returns various metrics about a function's queue
func (r *Redis) GetQueueMetrics(ctx context.Context, functionID string) (map[string]interface{}, error) {
	queueName := functionQueuePrefix + functionID
	
	pipe := r.client.Pipeline()
	
	// Queue length
	lenCmd := pipe.LLen(ctx, queueName)
	
	// Get first and last message timestamps
	firstCmd := pipe.LIndex(ctx, queueName, 0)
	lastCmd := pipe.LIndex(ctx, queueName, -1)
	
	_, err := pipe.Exec(ctx)
	if err != nil && err != redis.Nil {
		return nil, fmt.Errorf("failed to get queue metrics: %w", err)
	}

	metrics := map[string]interface{}{
		"queue_length": lenCmd.Val(),
	}

	// Parse first message if exists
	if firstMsg := firstCmd.Val(); firstMsg != "" {
		var msg QueueMessage
		if err := json.Unmarshal([]byte(firstMsg), &msg); err == nil {
			metrics["oldest_message"] = msg.LastEnqueued
		}
	}

	// Parse last message if exists
	if lastMsg := lastCmd.Val(); lastMsg != "" {
		var msg QueueMessage
		if err := json.Unmarshal([]byte(lastMsg), &msg); err == nil {
			metrics["newest_message"] = msg.LastEnqueued
		}
	}

	return metrics, nil
}

// Ping checks the connection to Redis
func (r *Redis) Ping(ctx context.Context) error {
	return r.client.Ping(ctx).Err()
}