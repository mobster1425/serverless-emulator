package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"serverless-emulator/internal/api"
	"serverless-emulator/internal/config"
	"serverless-emulator/internal/db"
	"serverless-emulator/internal/docker"
	"serverless-emulator/internal/queue"
	"serverless-emulator/internal/storage"
	"serverless-emulator/internal/worker"
	"serverless-emulator/pkg/logger"

	"github.com/joho/godotenv"
)

func main() {
	// Load .env file explicitly
	if err := godotenv.Load(); err != nil {
		log.Printf("Error loading .env file: %v", err)
	}

	// Debug: Print environment variables
	fmt.Printf("POSTGRES_DSN=%s\n", os.Getenv("POSTGRES_DSN"))

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Debug: Print loaded database configuration
	fmt.Printf("Loaded Database DSN: %s\n", cfg.Database.DSN)

	// Initialize logger
	logger := logger.NewLogger(&logger.Config{
		Level:      "info",
		Format:     "console",
		Output:     "stdout",
		TimeFormat: "2006-01-02T15:04:05.000Z07:00",
		AddCaller:  true,
	})

	// Initialize database
	db, err := db.NewPostgres(context.Background(), cfg.Database)
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to connect to database")
	}
	defer db.Close()

	// Run database migrations
	if err := db.Migrate(); err != nil {
		logger.Fatal().Err(err).Msg("Failed to run database migrations")
	}

	// Initialize Redis queue
	queue, err := queue.NewRedis(context.Background(), cfg.Redis)
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to connect to Redis")
	}
	defer queue.Close()

	// Docker client needs runtime config
	dockerConfig := cfg.Docker
	dockerConfig.Runtime = cfg.Runtime

	// Initialize Docker client with runtime config
	docker, err := docker.NewClient(&dockerConfig, logger)
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to create Docker client")
	}

	// Initialize S3 client
	s3Client, err := storage.NewS3Client(
		cfg.S3.Bucket,
		cfg.S3.Region,
		cfg.S3.AccessKey,
		cfg.S3.SecretKey,
		logger,
	)
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to create S3 client")
	}

	// Initialize worker pool
	workerPool := worker.NewWorkerPool(&cfg.Worker, db, docker, logger)

	// Create and start server
	server := api.NewServer(cfg, db, queue, docker, workerPool, logger, s3Client)

	// Start worker pool
	go workerPool.Start()

	// Start the cleanup scheduler for ECS resources if running in ECS mode
	if cfg.Runtime.Mode == "ecs" {
		// Schedule cleanup of ECS resources every 30 minutes
		go func() {
			logger.Info().Msg("Starting ECS resource cleanup scheduler")

			// Wait 5 minutes before first cleanup
			time.Sleep(5 * time.Minute)

			// Run cleanup every 30 minutes
			ticker := time.NewTicker(30 * time.Minute)
			defer ticker.Stop()

			for {
				select {
				case <-ticker.C:
					logger.Info().Msg("Running scheduled ECS resource cleanup")
					cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)

					// Call the cleanup method
					err := docker.CleanupResources(cleanupCtx)
					if err != nil {
						logger.Error().Err(err).Msg("Failed to cleanup ECS resources")
					}

					cancel()
				}
			}
		}()
	}

	// Handle graceful shutdown
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan

		logger.Info().Msg("Received shutdown signal")

		// Create shutdown context with timeout
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Stop worker pool
		workerPool.Stop()

		// Shutdown server
		if err := server.Shutdown(ctx); err != nil {
			logger.Error().Err(err).Msg("Server shutdown error")
		}
	}()

	// Start server
	if err := server.Start(); err != nil {
		logger.Fatal().Err(err).Msg("Server startup failed")
	}
}
