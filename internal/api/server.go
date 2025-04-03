package api

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"serverless-emulator/internal/config"
	"serverless-emulator/internal/db"
	//"serverless-emulator/internal/docker"
	"serverless-emulator/internal/queue"
	"serverless-emulator/internal/worker"
	"serverless-emulator/pkg/logger"
	"serverless-emulator/internal/api/handlers"
	"serverless-emulator/internal/storage"
)

// Server represents the API server
type Server struct {
	config     *config.Config
	router     *gin.Engine
	db         *db.Postgres
	queue      *queue.Redis
	docker     worker.RuntimeClient
	workerPool *worker.WorkerPool
	logger     *logger.Logger
	httpServer *http.Server
	functionHandlers *handlers.FunctionHandlers
	s3Client       *storage.S3Client
}

// NewServer creates a new API server instance
func NewServer(cfg *config.Config, db *db.Postgres, queue *queue.Redis, 
	docker worker.RuntimeClient, workerPool *worker.WorkerPool, logger *logger.Logger, s3Client *storage.S3Client) *Server {
	
	// Set Gin to release mode in production
	if cfg.API.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	server := &Server{
		config:     cfg,
		db:         db,
		queue:      queue,
		docker:     docker,
		workerPool: workerPool,
		logger:     logger,
		s3Client:   s3Client,
	
	}

	// Initialize function handlers
	server.functionHandlers = handlers.NewFunctionHandlers(db, docker, queue, workerPool, logger, cfg, s3Client)

	// Initialize router
	server.setupRouter()

	return server
}

// Start starts the API server
func (s *Server) Start() error {
	s.httpServer = &http.Server{
		Addr:         fmt.Sprintf(":%s", s.config.API.Port),
		Handler:      s.router,
		ReadTimeout:  s.config.API.ReadTimeout,
		WriteTimeout: s.config.API.WriteTimeout,
		IdleTimeout:  s.config.API.IdleTimeout,
	}

	s.logger.Info().Msgf("Starting API server on port %s", s.config.API.Port)
	if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("failed to start server: %w", err)
	}

	return nil
}

// Shutdown gracefully shuts down the server
func (s *Server) Shutdown(ctx context.Context) error {
	s.logger.Info().Msg("Shutting down API server...")
	return s.httpServer.Shutdown(ctx)
}

// setupRouter initializes the Gin router and routes
func (s *Server) setupRouter() {
	router := gin.New()

	// Global middleware
	router.Use(gin.Recovery())
	router.Use(s.loggerMiddleware())
	router.Use(s.corsMiddleware())
	
	// Health check
	router.GET("/health", s.handleHealthCheck)

	// API v1 routes
	v1 := router.Group("/api/v1")
	{
		// Function management
		functions := v1.Group("/functions")
		{
			functions.POST("", s.functionHandlers.CreateFunction)
			functions.GET("", s.functionHandlers.ListFunctions)
			functions.GET("/:id", s.functionHandlers.GetFunction)
			functions.PUT("/:id", s.functionHandlers.UpdateFunction)
			functions.DELETE("/:id", s.functionHandlers.DeleteFunction)
			
			// Function invocation
			functions.POST("/:id/invoke", s.functionHandlers.InvokeFunction)
			
			// Function logs
			functions.GET("/:id/logs", s.functionHandlers.GetFunctionLogs)
		}


		/*
		// System metrics and monitoring
		monitoring := v1.Group("/monitoring")
		{
			monitoring.GET("/metrics", s.handleGetMetrics)
			monitoring.GET("/workers", s.handleGetWorkerStatus)
			monitoring.GET("/queue", s.handleGetQueueMetrics)
		}
		*/
	}

	s.router = router
}

// Middleware functions

func (s *Server) loggerMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		raw := c.Request.URL.RawQuery

		// Process request
		c.Next()

		// Log request details
		if raw != "" {
			path = path + "?" + raw
		}

		s.logger.Info().
			Str("method", c.Request.Method).
			Str("path", path).
			Int("status", c.Writer.Status()).
			Dur("latency", time.Since(start)).
			Str("ip", c.ClientIP()).
			Str("user-agent", c.Request.UserAgent()).
			Int("body-size", c.Writer.Size()).
			Send()
	}
}

func (s *Server) corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	//	c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}

// Basic health check handler
func (s *Server) handleHealthCheck(c *gin.Context) {
	status := map[string]interface{}{
		"status":    "ok",
		"timestamp": time.Now().UTC(),
	}

	// Check database connection
	if err := s.db.Ping(c); err != nil {
		status["status"] = "degraded"
		status["database_error"] = err.Error()
	}

	// Check Redis connection
	if err := s.queue.Ping(c); err != nil {
		status["status"] = "degraded"
		status["queue_error"] = err.Error()
	}

	// Check Docker connection
	if err := s.docker.Ping(c); err != nil {
		status["status"] = "degraded"
		status["docker_error"] = err.Error()
	}

	// Check S3 connection
	if err := s.s3Client.Ping(c); err != nil {
		status["status"] = "degraded"
		status["s3_error"] = err.Error()
	}

	c.JSON(http.StatusOK, status)
}