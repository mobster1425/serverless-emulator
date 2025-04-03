#!/bin/bash
set -e

# Enable debug mode
DEBUG=true

debug() {
    if [ "$DEBUG" = true ]; then
        echo "DEBUG: $1"
    fi
}

error() {
    echo "ERROR: $1"
    exit 1
}

# Base URL for the API
BASE_URL="http://localhost:8080/api/v1"

# Create test function files
rm -rf test-function
mkdir -p test-function
cd test-function

# Create main.go with corrected input handling
cat > main.go << 'EOF'
package main

import (
    "encoding/json"
    "fmt"
    "math"
    "os"
    "time"
)

type Image struct {
    Name   string `json:"name"`
    Width  int    `json:"width"`
    Height int    `json:"height"`
    Size   int    `json:"size"`
    Format string `json:"format"`
}

type Analysis struct {
    AspectRatio     float64  `json:"aspectRatio"`
    Megapixels      float64  `json:"megapixels"`
    PixelDensity    float64  `json:"pixelDensity"`
    QualityScore    float64  `json:"qualityScore"`
    Recommendations []string `json:"recommendations"`
}

type Result struct {
    OriginalImage Image    `json:"originalImage"`
    Analysis      Analysis `json:"analysis"`
}

type Response struct {
    StatusCode int         `json:"statusCode"`
    Body       ResponseBody `json:"body"`
}

type ResponseBody struct {
    Timestamp string    `json:"timestamp"`
    Summary   Summary   `json:"summary"`
    Results   []Result  `json:"results"`
}

type Summary struct {
    ProcessedImages     int     `json:"processedImages"`
    AverageQualityScore float64 `json:"averageQualityScore"`
    TotalSizeMB        float64 `json:"totalSizeMB"`
}

func Handler(event json.RawMessage) (interface{}, error) {
    // Debug print the raw input
    fmt.Fprintf(os.Stderr, "Raw input: %s\n", string(event))

    // Try to parse the input in both formats
    var images []Image

    // First try parsing as wrapped payload
    var wrappedInput struct {
        Payload struct {
            Images []Image `json:"images"`
        } `json:"payload"`
    }
    if err := json.Unmarshal(event, &wrappedInput); err == nil && len(wrappedInput.Payload.Images) > 0 {
        images = wrappedInput.Payload.Images
    } else {
        // Try parsing as direct payload
        var directInput struct {
            Images []Image `json:"images"`
        }
        if err := json.Unmarshal(event, &directInput); err == nil && len(directInput.Images) > 0 {
            images = directInput.Images
        } else {
            // Try parsing as raw array
            var rawImages []Image
            if err := json.Unmarshal(event, &rawImages); err != nil {
                fmt.Fprintf(os.Stderr, "Error parsing input: %v\n", err)
                return nil, fmt.Errorf("failed to parse input: %v", err)
            }
            images = rawImages
        }
    }

    // Debug print the parsed images
    fmt.Fprintf(os.Stderr, "Parsed images: %+v\n", images)

    if len(images) == 0 {
        return nil, fmt.Errorf("no images provided in payload")
    }

    var results []Result
    var totalQualityScore float64
    var totalSize float64

    for _, image := range images {
        aspectRatio := float64(image.Width) / float64(image.Height)
        megapixels := float64(image.Width * image.Height) / 1000000
        pixelDensity := megapixels / (float64(image.Size) / 1024 / 1024)
        qualityScore := calculateQualityScore(image, pixelDensity)
        recommendations := generateRecommendations(image, qualityScore)

        result := Result{
            OriginalImage: image,
            Analysis: Analysis{
                AspectRatio:     math.Round(aspectRatio*100) / 100,
                Megapixels:      math.Round(megapixels*100) / 100,
                PixelDensity:    math.Round(pixelDensity*100) / 100,
                QualityScore:    math.Round(qualityScore*100) / 100,
                Recommendations: recommendations,
            },
        }

        results = append(results, result)
        totalQualityScore += qualityScore
        totalSize += float64(image.Size)
    }

    avgQualityScore := totalQualityScore / float64(len(results))
    totalSizeMB := totalSize / 1024 / 1024

    return Response{
        StatusCode: 200,
        Body: ResponseBody{
            Timestamp: time.Now().UTC().Format(time.RFC3339),
            Summary: Summary{
                ProcessedImages:     len(results),
                AverageQualityScore: math.Round(avgQualityScore*100) / 100,
                TotalSizeMB:        math.Round(totalSizeMB*100) / 100,
            },
            Results: results,
        },
    }, nil
}

func calculateQualityScore(image Image, pixelDensity float64) float64 {
    sizeScore := math.Min(100, (float64(image.Size)/1024/1024)*10)
    resolutionScore := math.Min(100, math.Sqrt(float64(image.Width*image.Height))/50)
    densityScore := math.Min(100, pixelDensity*20)
    return (sizeScore * 0.3) + (resolutionScore * 0.4) + (densityScore * 0.3)
}

func generateRecommendations(image Image, qualityScore float64) []string {
    var recommendations []string
    if image.Size > 5*1024*1024 {
        recommendations = append(recommendations, "Consider compressing the image to reduce file size")
    }
    if image.Width > 4000 || image.Height > 4000 {
        recommendations = append(recommendations, "Image resolution may be unnecessarily high for web use")
    }
    if qualityScore < 50 {
        recommendations = append(recommendations, "Image quality could be improved")
    } else if qualityScore > 90 {
        recommendations = append(recommendations, "Image quality is excellent")
    }
    return recommendations
}

func main() {
    input := os.Getenv("FUNCTION_INPUT")
    if input == "" {
        fmt.Fprintf(os.Stderr, "No input provided\n")
        os.Exit(1)
    }

    // Debug print the environment input
    fmt.Fprintf(os.Stderr, "Function input from env: %s\n", input)

    result, err := Handler(json.RawMessage(input))
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error: %v\n", err)
        json.NewEncoder(os.Stdout).Encode(map[string]interface{}{
            "statusCode": 500,
            "body": map[string]interface{}{
                "error": err.Error(),
            },
        })
        os.Exit(1)
    }

    if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
        fmt.Fprintf(os.Stderr, "Error encoding response: %v\n", err)
        os.Exit(1)
    }
}
EOF

# Create go.mod with explicit line endings
echo -e "module function\n\ngo 1.18" > go.mod

# Create zip file with specific options
zip -r ../function.zip ./*

cd ..

# Function metadata
FUNCTION_DATA='{
    "name": "go-image-analyzer",
    "runtime": "go1.18",
    "handler": "main.Handler",
    "memory": 256,
    "timeout": 60,
    "environment": []
}'

# Create function with improved error handling and response capture
echo "Creating function..."
echo "Function data: $FUNCTION_DATA"

debug "Sending POST request to ${BASE_URL}/functions"

# Use curl with better error handling and store response in a file
TEMP_RESPONSE=$(mktemp)
TEMP_HEADERS=$(mktemp)
HTTP_CODE=$(curl -s -w "%{http_code}" -X POST "${BASE_URL}/functions" \
    -H "Content-Type: multipart/form-data" \
    -H "Accept: application/json" \
    -F "code=@function.zip" \
    -F "data=${FUNCTION_DATA}" \
    --max-time 300 \
    -D "${TEMP_HEADERS}" \
    -o "${TEMP_RESPONSE}")

echo "HTTP Status Code: ${HTTP_CODE}"
RESPONSE_BODY=$(cat "${TEMP_RESPONSE}")
echo "Response Body: ${RESPONSE_BODY}"

# Cleanup temp files
rm -f "${TEMP_RESPONSE}" "${TEMP_HEADERS}"

# Check HTTP status code
if [ "${HTTP_CODE}" != "201" ]; then
    error "Failed to create function. HTTP Status: ${HTTP_CODE}, Response: ${RESPONSE_BODY}"
fi

# Validate JSON response
if ! echo "${RESPONSE_BODY}" | jq . >/dev/null 2>&1; then
    error "Invalid JSON response: ${RESPONSE_BODY}"
fi

# Extract function ID with error handling
FUNCTION_ID=$(echo "${RESPONSE_BODY}" | jq -r '.id')
if [ "${FUNCTION_ID}" = "null" ] || [ -z "${FUNCTION_ID}" ]; then
    error "Failed to get function ID from response: ${RESPONSE_BODY}"
fi

echo "Function ID: ${FUNCTION_ID}"

# Wait for function to be ready with improved status checking and debugging
echo "Waiting for function to be ready..."
for i in {1..30}; do
    echo "Checking status (attempt $i)..."
    
    # Use temp file for status check response
    TEMP_STATUS=$(mktemp)
    echo "Fetching from ${BASE_URL}/functions/${FUNCTION_ID}"
    STATUS_CODE=$(curl -s -w "%{http_code}" "${BASE_URL}/functions/${FUNCTION_ID}" -o "${TEMP_STATUS}")
    echo "Status check code: ${STATUS_CODE}"
    STATUS_BODY=$(cat "${TEMP_STATUS}")
    echo "Status check response: ${STATUS_BODY}"
    rm -f "${TEMP_STATUS}"
    
    if [ "${STATUS_CODE}" != "200" ]; then
        echo "Error checking status (HTTP ${STATUS_CODE}), retrying..."
        sleep 5
        continue
    fi
    
    if [ -z "${STATUS_BODY}" ]; then
        echo "Empty status response, retrying..."
        sleep 5
        continue
    fi
    
    STATUS=$(echo "${STATUS_BODY}" | jq -r '.status' || echo "failed to parse JSON")
    echo "Current status: ${STATUS}"
    
    if [ "${STATUS}" = "active" ] || [ "${STATUS}" = "ACTIVE" ]; then
        echo "Function is ready"
        break
    elif [ $i -eq 30 ]; then
        error "Function failed to become ready in 2.5 minutes"
    fi
    
    sleep 5
done

# Test invocation with proper payload and error handling
echo "Invoking function..."
INVOKE_DATA='{
    "payload": {
        "images": [
            {
                "name": "hero-image.jpg",
                "width": 3840,
                "height": 2160,
                "size": 4194304,
                "format": "jpeg"
            }
        ]
    }
}'

echo "Invoke request data:"
echo "${INVOKE_DATA}" | jq .

# Use temp file for invoke response
TEMP_INVOKE=$(mktemp)
echo "Sending request to ${BASE_URL}/functions/${FUNCTION_ID}/invoke"
INVOKE_CODE=$(curl -s -X POST "${BASE_URL}/functions/${FUNCTION_ID}/invoke" \
    -H "Content-Type: application/json" \
    -H "Accept: application/json" \
    -d "${INVOKE_DATA}" \
    --max-time 60 \
    -w "%{http_code}" \
    -o "${TEMP_INVOKE}")

echo "Invoke HTTP status: ${INVOKE_CODE}"
INVOKE_RESPONSE=$(cat "${TEMP_INVOKE}")
echo "Raw invoke response: ${INVOKE_RESPONSE}"
rm -f "${TEMP_INVOKE}"

if [ -z "${INVOKE_RESPONSE}" ]; then
    error "Empty response from function invocation"
fi

echo "Invoke response:"
echo "${INVOKE_RESPONSE}" | jq . || echo "Failed to parse response as JSON: ${INVOKE_RESPONSE}"

# Get function logs with error handling
echo "Function logs:"
TEMP_LOGS=$(mktemp)
LOGS_RESPONSE=$(curl -s "${BASE_URL}/functions/${FUNCTION_ID}/logs" -o "${TEMP_LOGS}" && cat "${TEMP_LOGS}")
rm -f "${TEMP_LOGS}"

if [ -z "${LOGS_RESPONSE}" ]; then
    error "Empty response when fetching logs"
fi

echo "Logs response:"
echo "${LOGS_RESPONSE}" | jq . || echo "Raw logs: ${LOGS_RESPONSE}"

# Cleanup
rm -rf test-function function.zip