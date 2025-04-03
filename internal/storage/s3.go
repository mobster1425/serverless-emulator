package storage

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime/multipart"

	"serverless-emulator/pkg/logger"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// S3Client uses AWS S3 for storage
type S3Client struct {
	client *s3.Client
	bucket string
	logger *logger.Logger
}

// NewS3Client creates a new S3 client
func NewS3Client(bucket, region, accessKey, secretKey string, logger *logger.Logger) (*S3Client, error) {
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}

	logger.Debug().
		Str("bucket", bucket).
		Str("region", region).
		Msg("Creating S3 client")

	// Check required params
	if bucket == "" {
		return nil, fmt.Errorf("bucket is required")
	}
	if region == "" {
		return nil, fmt.Errorf("region is required")
	}

	// Create AWS credentials
	var creds aws.CredentialsProvider
	if accessKey != "" && secretKey != "" {
		creds = credentials.NewStaticCredentialsProvider(accessKey, secretKey, "")
	} else {
		// Just don't set the credentials provider and use the default chain
		// This will use environment variables, shared credentials file, etc.
	}

	// Create custom endpoint resolver option for S3
	customResolver := aws.EndpointResolverWithOptionsFunc(func(service, region string, options ...interface{}) (aws.Endpoint, error) {
		if service == "s3" {
			return aws.Endpoint{
				URL:               fmt.Sprintf("https://s3.%s.amazonaws.com", region),
				HostnameImmutable: true,
				SigningRegion:     region,
			}, nil
		}
		// Fallback to default endpoint resolution
		return aws.Endpoint{}, &aws.EndpointNotFoundError{}
	})

	// Load AWS configuration with appropriate options
	var cfg aws.Config
	var err error
	if accessKey != "" && secretKey != "" {
		// Use custom credentials if provided
		cfg, err = config.LoadDefaultConfig(context.Background(),
			config.WithRegion(region),
			config.WithCredentialsProvider(creds),
			config.WithEndpointResolverWithOptions(customResolver),
		)
	} else {
		// Use default credentials
		cfg, err = config.LoadDefaultConfig(context.Background(),
			config.WithRegion(region),
			config.WithEndpointResolverWithOptions(customResolver),
		)
	}
	if err != nil {
		logger.Error().
			Err(err).
			Str("region", region).
			Msg("Failed to load AWS config")
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	client := s3.NewFromConfig(cfg)

	logger.Info().
		Str("bucket", bucket).
		Str("region", region).
		Msg("S3 client created")

	return &S3Client{
		client: client,
		bucket: bucket,
		logger: logger,
	}, nil
}

// UploadFile uploads a file to S3
func (s *S3Client) UploadFile(ctx context.Context, key string, file io.Reader) error {
	s.logger.Debug().
		Str("bucket", s.bucket).
		Str("key", key).
		Msg("Uploading file to S3")

	// Read the entire file to create a seek-able buffer
	data, err := io.ReadAll(file)
	if err != nil {
		s.logger.Error().
			Err(err).
			Str("key", key).
			Msg("Failed to read file")
		return fmt.Errorf("failed to read file: %w", err)
	}

	// Log file size and preview content (first 100 bytes)
	previewSize := 100
	if len(data) < previewSize {
		previewSize = len(data)
	}
	contentPreview := data[:previewSize]

	s.logger.Debug().
		Int("file_size", len(data)).
		Str("content_preview", string(contentPreview)).
		Msg("File content preview")

	// Create buffer for upload
	buffer := bytes.NewReader(data)

	// Upload to S3
	_, err = s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
		Body:   buffer,
	})
	if err != nil {
		s.logger.Error().
			Err(err).
			Str("bucket", s.bucket).
			Str("key", key).
			Msg("Failed to upload file to S3")
		return fmt.Errorf("failed to upload file to S3: %w", err)
	}

	s.logger.Info().
		Str("bucket", s.bucket).
		Str("key", key).
		Int("size", len(data)).
		Msg("File uploaded to S3")

	return nil
}

// UploadFileFromMultipart uploads a multipart file to S3
func (s *S3Client) UploadFileFromMultipart(ctx context.Context, file *multipart.FileHeader, key string) (string, error) {
	src, err := file.Open()
	if err != nil {
		s.logger.Error().
			Err(err).
			Str("key", key).
			Str("filename", file.Filename).
			Msg("Failed to open multipart file")
		return "", fmt.Errorf("failed to open file: %w", err)
	}
	defer src.Close()

	s.logger.Debug().
		Str("filename", file.Filename).
		Str("key", key).
		Int64("size", file.Size).
		Str("content_type", file.Header.Get("Content-Type")).
		Msg("Uploading multipart file to S3")

	// Read file content
	data, err := io.ReadAll(src)
	if err != nil {
		s.logger.Error().
			Err(err).
			Str("key", key).
			Msg("Failed to read file content")
		return "", fmt.Errorf("failed to read file content: %w", err)
	}

	// Upload to S3 with content type
	_, err = s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(s.bucket),
		Key:         aws.String(key),
		Body:        bytes.NewReader(data),
		ContentType: aws.String(file.Header.Get("Content-Type")),
	})
	if err != nil {
		s.logger.Error().
			Err(err).
			Str("bucket", s.bucket).
			Str("key", key).
			Msg("Failed to upload file to S3")
		return "", fmt.Errorf("failed to upload file to S3: %w", err)
	}

	s.logger.Info().
		Str("bucket", s.bucket).
		Str("key", key).
		Int64("size", file.Size).
		Msg("File uploaded to S3")

	// Return the S3 URL
	return fmt.Sprintf("s3://%s/%s", s.bucket, key), nil
}

func (s *S3Client) DeleteFile(ctx context.Context, key string) error {
	_, err := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return fmt.Errorf("failed to delete file from S3: %w", err)
	}
	return nil
}

func (s *S3Client) DownloadFile(ctx context.Context, key string) ([]byte, error) {
	s.logger.Debug().
		Str("bucket", s.bucket).
		Str("key", key).
		Msg("Downloading file from S3")

	// Get object
	result, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		s.logger.Error().
			Err(err).
			Str("bucket", s.bucket).
			Str("key", key).
			Msg("Failed to download file from S3")
		return nil, fmt.Errorf("failed to download file from S3: %w", err)
	}
	defer result.Body.Close()

	// Read all data
	data, err := io.ReadAll(result.Body)
	if err != nil {
		s.logger.Error().
			Err(err).
			Str("bucket", s.bucket).
			Str("key", key).
			Msg("Failed to read file data")
		return nil, fmt.Errorf("failed to read file data: %w", err)
	}

	// Log file size and preview content (first 100 bytes)
	previewSize := 100
	if len(data) < previewSize {
		previewSize = len(data)
	}
	contentPreview := data[:previewSize]

	s.logger.Debug().
		Int("file_size", len(data)).
		Str("content_preview", string(contentPreview)).
		Msg("Downloaded file content preview")

	// Print content type if available
	if result.ContentType != nil {
		s.logger.Debug().
			Str("content_type", *result.ContentType).
			Msg("Content type")
	}

	s.logger.Info().
		Str("bucket", s.bucket).
		Str("key", key).
		Int("size", len(data)).
		Msg("File downloaded from S3")

	return data, nil
}

func (s *S3Client) Ping(ctx context.Context) error {
	// Try to list objects with max 1 result to check connectivity
	_, err := s.client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
		Bucket:  aws.String(s.bucket),
		MaxKeys: aws.Int32(1),
	})
	if err != nil {
		return fmt.Errorf("failed to ping S3: %w", err)
	}
	return nil
}
