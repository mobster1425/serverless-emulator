package config

import (
	//	"fmt"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds all configuration for the application
type Config struct {
	API      APIConfig
	Database DatabaseConfig
	Redis    RedisConfig
	Docker   DockerConfig
	Worker   WorkerConfig
	S3       S3Config
	Runtime  RuntimeConfig
}

type APIConfig struct {
	Port            string
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	ShutdownTimeout time.Duration
	IdleTimeout     time.Duration
	Environment     string
}

type DatabaseConfig struct {
	DSN             string
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
}

type RedisConfig struct {
	Addr     string
	Password string
	DB       int
}

type DockerConfig struct {
	Host               string
	DefaultMemoryLimit int64   // in MB
	DefaultCPULimit    float64 // in CPU units (1.0 = 1 core)
	DefaultTimeout     time.Duration
	NetworkName        string
	ContainerPrefix    string
	Runtime            RuntimeConfig
}

type WorkerConfig struct {
	NumWorkers        int
	QueueName         string
	MaxRetries        int
	ProcessingTimeout time.Duration
	QueueSize         int
	WorkerTimeout     time.Duration
	ShutdownTimeout   time.Duration
	QueueTimeout      time.Duration
}

type S3Config struct {
	AccessKey string
	SecretKey string
	Region    string
	Bucket    string
}

type RuntimeConfig struct {
	Mode string // "local" or "ecs"
	ECS  ECSConfig
}

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
	UseCodeBuild            bool
	CodeBuild               CodeBuildConfig
}

// Add the CodeBuild configuration struct
type CodeBuildConfig struct {
	ProjectName string
	Region      string
	Enabled     bool
}

// Update the DockerRuntimeConfig struct to include the CodeBuild flag
type DockerRuntimeConfig struct {
	Mode string // "local" or "ecs"
	ECS  ECSConfig
}

// Load creates a Config instance from environment variables
func Load() (*Config, error) {
	cfg := &Config{
		API:      loadAPIConfig(),
		Database: loadDatabaseConfig(),
		Redis:    loadRedisConfig(),
		Docker:   loadDockerConfig(),
		Worker:   loadWorkerConfig(),
		S3:       loadS3Config(),
	}

	cfg.Runtime = loadRuntimeConfig()

	return cfg, nil
}

func loadAPIConfig() APIConfig {
	return APIConfig{
		Port:            getEnvOrDefault("API_PORT", "8080"),
		ReadTimeout:     getEnvDurationOrDefault("API_READ_TIMEOUT", 5*time.Second),
		WriteTimeout:    getEnvDurationOrDefault("API_WRITE_TIMEOUT", 10*time.Second),
		ShutdownTimeout: getEnvDurationOrDefault("API_SHUTDOWN_TIMEOUT", 15*time.Second),
		IdleTimeout:     getEnvDurationOrDefault("API_IDLE_TIMEOUT", 60*time.Second),
		Environment:     getEnvOrDefault("API_ENVIRONMENT", "development"),
	}
}

func loadDatabaseConfig() DatabaseConfig {
	dsn := getEnvOrDefault("POSTGRES_DSN", "postgres://postgres:postgres@localhost:5432/serverless-emulator?sslmode=disable")
	fmt.Printf("Loading Database Config - DSN: %s\n", dsn)

	return DatabaseConfig{
		DSN:             dsn,
		MaxOpenConns:    getEnvIntOrDefault("DB_MAX_OPEN_CONNS", 25),
		MaxIdleConns:    getEnvIntOrDefault("DB_MAX_IDLE_CONNS", 25),
		ConnMaxLifetime: getEnvDurationOrDefault("DB_CONN_MAX_LIFETIME", time.Hour),
	}
}

func loadRedisConfig() RedisConfig {
	return RedisConfig{
		Addr:     getEnvOrDefault("REDIS_ADDR", "localhost:6379"),
		Password: getEnvOrDefault("REDIS_PASSWORD", ""),
		DB:       getEnvIntOrDefault("REDIS_DB", 0),
	}
}

func loadDockerConfig() DockerConfig {
	return DockerConfig{
		Host:               getEnvOrDefault("DOCKER_HOST", "unix:///var/run/docker.sock"),
		DefaultMemoryLimit: int64(getEnvIntOrDefault("DOCKER_DEFAULT_MEMORY_LIMIT", 128)), // 128MB
		DefaultCPULimit:    getEnvFloatOrDefault("DOCKER_DEFAULT_CPU_LIMIT", 1.0),
		DefaultTimeout:     getEnvDurationOrDefault("DOCKER_DEFAULT_TIMEOUT", 300*time.Second),
		NetworkName:        getEnvOrDefault("DOCKER_NETWORK", "serverless-network"),
		ContainerPrefix:    getEnvOrDefault("DOCKER_CONTAINER_PREFIX", "fn-"),
	}
}

func loadWorkerConfig() WorkerConfig {
	return WorkerConfig{
		NumWorkers:        getEnvIntOrDefault("WORKER_COUNT", 5),
		QueueName:         getEnvOrDefault("WORKER_QUEUE_NAME", "function_queue"),
		MaxRetries:        getEnvIntOrDefault("WORKER_MAX_RETRIES", 3),
		ProcessingTimeout: getEnvDurationOrDefault("WORKER_PROCESSING_TIMEOUT", 5*time.Minute),
	}
}

func loadS3Config() S3Config {
	// Use the same AWS credentials for S3 as we do for ECS
	return S3Config{
		AccessKey: getEnvOrDefault("AWS_ACCESS_KEY_ID", getEnvOrDefault("AWS_S3_BUCKET_ACCESS_KEY", "")),
		SecretKey: getEnvOrDefault("AWS_SECRET_ACCESS_KEY", getEnvOrDefault("AWS_S3_BUCKET_SECRET_KEY", "")),
		Region:    getEnvOrDefault("AWS_DEFAULT_REGION", "us-east-1"),
		Bucket:    getEnvOrDefault("AWS_S3_BUCKET", "your-bucket-name"),
	}
}

func loadRuntimeConfig() RuntimeConfig {
	// Get EFS configuration
	efsFileSystemId := getEnvOrDefault("AWS_EFS_FILESYSTEM_ID", "")
	efsAccessPointId := getEnvOrDefault("AWS_EFS_ACCESS_POINT_ID", "")

	// Debug output for EFS configuration
	fmt.Printf("EFS Configuration - FileSystemId: %s, AccessPointId: %s\n",
		efsFileSystemId, efsAccessPointId)

	return RuntimeConfig{
		Mode: getEnvOrDefault("RUNTIME_MODE", "ecs"),
		ECS: ECSConfig{
			Cluster:                 getEnvOrDefault("AWS_ECS_CLUSTER", ""),
			Subnets:                 strings.Split(getEnvOrDefault("AWS_ECS_SUBNETS", ""), ","),
			SecurityGroups:          strings.Split(getEnvOrDefault("AWS_ECS_SECURITY_GROUPS", ""), ","),
			Region:                  getEnvOrDefault("AWS_REGION", "us-east-1"),
			TaskExecutionRoleArn:    getEnvOrDefault("AWS_ECS_TASK_EXECUTION_ROLE_ARN", ""),
			TaskRoleArn:             getEnvOrDefault("AWS_ECS_TASK_ROLE_ARN", ""),
			DockerHubCredentialsArn: getEnvOrDefault("AWS_ECS_DOCKERHUB_CREDENTIALS_ARN", ""),
			EFSFileSystemId:         efsFileSystemId,
			EFSAccessPointId:        efsAccessPointId,
		},
	}
}

// Helper functions for environment variables
func getEnvOrDefault(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

func getEnvIntOrDefault(key string, defaultValue int) int {
	strValue := getEnvOrDefault(key, "")
	if strValue == "" {
		return defaultValue
	}

	value, err := strconv.Atoi(strValue)
	if err != nil {
		return defaultValue
	}
	return value
}

func getEnvFloatOrDefault(key string, defaultValue float64) float64 {
	strValue := getEnvOrDefault(key, "")
	if strValue == "" {
		return defaultValue
	}

	value, err := strconv.ParseFloat(strValue, 64)
	if err != nil {
		return defaultValue
	}
	return value
}

func getEnvDurationOrDefault(key string, defaultValue time.Duration) time.Duration {
	strValue := getEnvOrDefault(key, "")
	if strValue == "" {
		return defaultValue
	}

	value, err := time.ParseDuration(strValue)
	if err != nil {
		return defaultValue
	}
	return value
}
