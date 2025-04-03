package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"
	//_ "github.com/lib/pq" // PostgreSQL driver
	"serverless-emulator/internal/config"
	"serverless-emulator/internal/models"

	"github.com/jmoiron/sqlx"
)

// Common database errors
var (
	ErrNotFound      = errors.New("record not found")
	ErrAlreadyExists = errors.New("record already exists")
	ErrInvalidInput  = errors.New("invalid input")
)

// Postgres represents the PostgreSQL database connection and operations
type Postgres struct {
	db *sqlx.DB
}

// NewPostgres creates a new PostgreSQL database connection
func NewPostgres(ctx context.Context, cfg config.DatabaseConfig) (*Postgres, error) {
	db, err := sqlx.ConnectContext(ctx, "postgres", cfg.DSN)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Configure connection pool
	db.SetMaxOpenConns(cfg.MaxOpenConns)
	db.SetMaxIdleConns(cfg.MaxIdleConns)
	db.SetConnMaxLifetime(cfg.ConnMaxLifetime)

	// Verify connection
	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return &Postgres{db: db}, nil
}

// Close closes the database connection
func (p *Postgres) Close() error {
	return p.db.Close()
}

// Migrate runs database migrations
func (p *Postgres) Migrate() error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS functions (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			name VARCHAR(255) NOT NULL,
			runtime VARCHAR(50) NOT NULL,
			handler VARCHAR(255) NOT NULL,
			code_path TEXT NOT NULL,
			image_name VARCHAR(255) NOT NULL,
			status VARCHAR(50) NOT NULL DEFAULT 'pending',
			memory INTEGER NOT NULL DEFAULT 128,
			timeout INTEGER NOT NULL DEFAULT 300,
			environment JSONB,
			created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
		)`,
		`CREATE INDEX IF NOT EXISTS idx_functions_name ON functions(name)`,

		`CREATE TABLE IF NOT EXISTS function_logs (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			function_id UUID NOT NULL,
			request_id VARCHAR(255) NOT NULL,
			status VARCHAR(50) NOT NULL,
			started_at TIMESTAMP WITH TIME ZONE NOT NULL,
			finished_at TIMESTAMP WITH TIME ZONE,
			duration INTEGER,
			memory_used INTEGER,
			cpu_used FLOAT,
			error_message TEXT,
			stdout TEXT,
			stderr TEXT,
			CONSTRAINT fk_function
				FOREIGN KEY(function_id)
				REFERENCES functions(id)
				ON DELETE CASCADE
		)`,
		`CREATE INDEX IF NOT EXISTS idx_function_logs_function_id ON function_logs(function_id)`,
		`CREATE INDEX IF NOT EXISTS idx_function_logs_request_id ON function_logs(request_id)`,
	}

	for _, query := range queries {
		if _, err := p.db.Exec(query); err != nil {
			return fmt.Errorf("migration failed: %w", err)
		}
	}

	return nil
}

// CreateFunction creates a new function in the database
func (p *Postgres) CreateFunction(ctx context.Context, fn *models.Function) error {
	query := `
		INSERT INTO functions (
			name, runtime, handler, code_path, image_name,
			status, memory, timeout, environment, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $10
		) RETURNING id`

	envJSON, err := json.Marshal(fn.Environment)
	if err != nil {
		return fmt.Errorf("failed to marshal environment: %w", err)
	}

	now := time.Now().UTC()
	fn.Status = models.FunctionStatusActive // Set status to active

	err = p.db.QueryRowContext(ctx, query,
		fn.Name, fn.Runtime, fn.Handler, fn.CodePath, fn.ImageName,
		fn.Status, fn.Memory, fn.Timeout, envJSON, now,
	).Scan(&fn.ID)

	if err != nil {
		if pqErr, ok := err.(*pq.Error); ok {
			if pqErr.Code == "23505" { // unique_violation
				return ErrAlreadyExists
			}
		}
		return fmt.Errorf("failed to create function: %w", err)
	}

	fn.CreatedAt = now
	fn.UpdatedAt = now
	return nil
}

// GetFunction retrieves a function by ID
func (p *Postgres) GetFunction(ctx context.Context, id string) (*models.Function, error) {
	var fn models.Function
	var envJSON []byte

	query := `
		SELECT id, name, runtime, handler, code_path, image_name,
			   status, memory, timeout, environment, created_at, updated_at
		FROM functions
		WHERE id = $1`

	err := p.db.QueryRowContext(ctx, query, id).Scan(
		&fn.ID, &fn.Name, &fn.Runtime, &fn.Handler, &fn.CodePath, &fn.ImageName,
		&fn.Status, &fn.Memory, &fn.Timeout, &envJSON, &fn.CreatedAt, &fn.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get function: %w", err)
	}

	if envJSON != nil {
		if err := json.Unmarshal(envJSON, &fn.Environment); err != nil {
			return nil, fmt.Errorf("failed to unmarshal environment: %w", err)
		}
	}

	// Set default status if empty
	if fn.Status == "" {
		fn.Status = models.FunctionStatusActive
	}

	return &fn, nil
}

// UpdateFunction updates an existing function
func (p *Postgres) UpdateFunction(ctx context.Context, fn *models.Function) error {
	query := `
		UPDATE functions
		SET name = $1, handler = $2, memory = $3, timeout = $4,
			environment = $5, updated_at = $6
		WHERE id = $7`

	envJSON, err := json.Marshal(fn.Environment)
	if err != nil {
		return fmt.Errorf("failed to marshal environment: %w", err)
	}

	now := time.Now().UTC()
	result, err := p.db.ExecContext(ctx, query,
		fn.Name, fn.Handler, fn.Memory, fn.Timeout,
		envJSON, now, fn.ID,
	)

	if err != nil {
		return fmt.Errorf("failed to update function: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return ErrNotFound
	}

	fn.UpdatedAt = now
	return nil
}

// DeleteFunction deletes a function by ID
func (p *Postgres) DeleteFunction(ctx context.Context, id string) error {
	query := `DELETE FROM functions WHERE id = $1`

	result, err := p.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete function: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return ErrNotFound
	}

	return nil
}

// ListFunctions retrieves all functions with optional pagination
func (p *Postgres) ListFunctions(ctx context.Context, limit, offset int) ([]*models.Function, error) {
	query := `
		SELECT id, name, runtime, handler, code_path, image_name,
			   memory, timeout, environment, created_at, updated_at
		FROM functions
		ORDER BY created_at DESC
		LIMIT $1 OFFSET $2`

	rows, err := p.db.QueryContext(ctx, query, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to list functions: %w", err)
	}
	defer rows.Close()

	var functions []*models.Function
	for rows.Next() {
		var fn models.Function
		var envJSON []byte

		err := rows.Scan(
			&fn.ID, &fn.Name, &fn.Runtime, &fn.Handler, &fn.CodePath, &fn.ImageName,
			&fn.Memory, &fn.Timeout, &envJSON, &fn.CreatedAt, &fn.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan function: %w", err)
		}

		if envJSON != nil {
			if err := json.Unmarshal(envJSON, &fn.Environment); err != nil {
				return nil, fmt.Errorf("failed to unmarshal environment: %w", err)
			}
		}

		functions = append(functions, &fn)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating functions: %w", err)
	}

	return functions, nil
}

// CreateFunctionLog creates a new function execution log
func (p *Postgres) CreateFunctionLog(ctx context.Context, log *models.FunctionLog) error {
	query := `
		INSERT INTO function_logs (
			function_id, request_id, status, started_at,
			finished_at, duration, memory_used, cpu_used,
			error_message, stdout, stderr
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11
		) RETURNING id`

	err := p.db.QueryRowContext(ctx, query,
		log.FunctionID, log.RequestID, log.Status, log.StartedAt,
		log.FinishedAt, log.Duration, log.MemoryUsed, log.CPUUsed,
		log.ErrorMessage, log.Stdout, log.Stderr,
	).Scan(&log.ID)

	if err != nil {
		return fmt.Errorf("failed to create function log: %w", err)
	}

	return nil
}

// GetFunctionLogs retrieves logs for a specific function
func (p *Postgres) GetFunctionLogs(ctx context.Context, functionID string, limit, offset int) ([]*models.FunctionLog, error) {
	query := `
		SELECT id, function_id, request_id, status, started_at,
			   finished_at, duration, memory_used, cpu_used,
			   error_message, stdout, stderr
		FROM function_logs
		WHERE function_id = $1
		ORDER BY started_at DESC
		LIMIT $2 OFFSET $3`

	rows, err := p.db.QueryContext(ctx, query, functionID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to get function logs: %w", err)
	}
	defer rows.Close()

	var logs []*models.FunctionLog
	for rows.Next() {
		var log models.FunctionLog
		err := rows.Scan(
			&log.ID, &log.FunctionID, &log.RequestID, &log.Status, &log.StartedAt,
			&log.FinishedAt, &log.Duration, &log.MemoryUsed, &log.CPUUsed,
			&log.ErrorMessage, &log.Stdout, &log.Stderr,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan function log: %w", err)
		}
		logs = append(logs, &log)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating function logs: %w", err)
	}

	return logs, nil
}

// GetFunctionLogByRequestID retrieves a specific function log by request ID
func (p *Postgres) GetFunctionLogByRequestID(ctx context.Context, requestID string) (*models.FunctionLog, error) {
	var log models.FunctionLog

	query := `
		SELECT id, function_id, request_id, status, started_at,
			   finished_at, duration, memory_used, cpu_used,
			   error_message, stdout, stderr
		FROM function_logs
		WHERE request_id = $1`

	err := p.db.QueryRowContext(ctx, query, requestID).Scan(
		&log.ID, &log.FunctionID, &log.RequestID, &log.Status, &log.StartedAt,
		&log.FinishedAt, &log.Duration, &log.MemoryUsed, &log.CPUUsed,
		&log.ErrorMessage, &log.Stdout, &log.Stderr,
	)

	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get function log: %w", err)
	}

	return &log, nil
}

// Add this method to the Postgres struct
func (p *Postgres) Ping(ctx context.Context) error {
	return p.db.PingContext(ctx)
}

// Add this method to the Postgres struct
func (p *Postgres) CountFunctions(ctx context.Context) (int64, error) {
	var count int64
	query := `SELECT COUNT(*) FROM functions`

	err := p.db.QueryRowContext(ctx, query).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count functions: %w", err)
	}

	return count, nil
}

// UpdateFunctionLogStatus updates the status of a function log
func (p *Postgres) UpdateFunctionLogStatus(ctx context.Context, requestID string, status models.ExecutionStatus) error {
	query := `
		UPDATE function_logs
		SET status = $1
		WHERE request_id = $2`

	result, err := p.db.ExecContext(ctx, query, status, requestID)
	if err != nil {
		return fmt.Errorf("failed to update function log status: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return ErrNotFound
	}

	return nil
}

// UpdateFunctionLog updates an existing function log
func (p *Postgres) UpdateFunctionLog(ctx context.Context, log *models.FunctionLog) error {
	query := `
		UPDATE function_logs
		SET status = $1,
			finished_at = $2,
			duration = $3,
			memory_used = $4,
			cpu_used = $5,
			error_message = $6,
			stdout = $7,
			stderr = $8
		WHERE request_id = $9`

	result, err := p.db.ExecContext(ctx, query,
		log.Status,
		log.FinishedAt,
		log.Duration,
		log.MemoryUsed,
		log.CPUUsed,
		log.ErrorMessage,
		log.Stdout,
		log.Stderr,
		log.RequestID,
	)

	if err != nil {
		return fmt.Errorf("failed to update function log: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return ErrNotFound
	}

	return nil
}
