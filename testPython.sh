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

# Create main.py with image processing logic
cat > main.py << 'EOL'
import json
import math
from datetime import datetime

def handler(event, context):
    try:
        print(f"Event received: {json.dumps(event, indent=2)}")
        
        # Validate input - Check if images array exists directly
        if not event.get('images'):
            raise ValueError('Input must contain an images array')

        images = event['images']
        results = []

        # Process each image
        for image in images:
            if not all(k in image for k in ['width', 'height', 'size']):
                raise ValueError('Each image must have width, height, and size properties')

            # Calculate metrics
            aspect_ratio = image['width'] / image['height']
            megapixels = (image['width'] * image['height']) / 1000000
            pixel_density = megapixels / (image['size'] / 1024 / 1024)  # pixels per MB
            
            # Calculate quality score and recommendations
            quality_score = calculate_quality_score(image, pixel_density)
            recommendations = generate_recommendations(image, quality_score)

            results.append({
                'originalImage': image,
                'analysis': {
                    'aspectRatio': round(aspect_ratio, 2),
                    'megapixels': round(megapixels, 2),
                    'pixelDensity': round(pixel_density, 2),
                    'qualityScore': round(quality_score, 2),
                    'recommendations': recommendations
                }
            })

        # Aggregate statistics
        avg_quality_score = sum(r['analysis']['qualityScore'] for r in results) / len(results)
        total_size = sum(r['originalImage']['size'] for r in results) / 1024 / 1024  # MB

        response = {
            'statusCode': 200,
            'body': {
                'timestamp': datetime.utcnow().isoformat(),
                'summary': {
                    'processedImages': len(results),
                    'averageQualityScore': round(avg_quality_score, 2),
                    'totalSizeMB': round(total_size, 2)
                },
                'results': results
            }
        }
        
        print(f"Response: {json.dumps(response, indent=2)}")
        return response

    except Exception as e:
        print(f"Error: {str(e)}")
        return {
            'statusCode': 500,
            'body': {
                'error': str(e),
                'timestamp': datetime.utcnow().isoformat()
            }
        }

def calculate_quality_score(image, pixel_density):
    # Quality scoring algorithm
    size_score = min(100, (image['size'] / 1024 / 1024) * 10)  # Size factor
    resolution_score = min(100, math.sqrt(image['width'] * image['height']) / 50)  # Resolution factor
    density_score = min(100, pixel_density * 20)  # Density factor
    
    # Weighted average
    return (size_score * 0.3) + (resolution_score * 0.4) + (density_score * 0.3)

def generate_recommendations(image, quality_score):
    recommendations = []
    
    # Size-based recommendations
    if image['size'] > 5 * 1024 * 1024:  # > 5MB
        recommendations.append('Consider compressing the image to reduce file size')
    
    # Resolution-based recommendations
    if image['width'] > 4000 or image['height'] > 4000:
        recommendations.append('Image resolution may be unnecessarily high for web use')
    
    # Quality score recommendations
    if quality_score < 50:
        recommendations.append('Image quality could be improved')
    elif quality_score > 90:
        recommendations.append('Image quality is excellent')
    
    return recommendations
EOL

# Create requirements.txt
cat > requirements.txt << 'EOL'
# No external dependencies required for this example
EOL

# Create zip file
zip -r ../function.zip ./*
cd ..

# Function metadata
FUNCTION_DATA='{
    "name": "python-image-analyzer",
    "runtime": "python3.10",
    "handler": "main.handler",
    "memory": 256,
    "timeout": 60,
    "environment": [
        {"key": "PYTHONPATH", "value": "/app"}
    ]
}'

# Create function with improved error handling and response capture
echo "Creating function..."
echo "Function data: $FUNCTION_DATA"

debug "Sending POST request to ${BASE_URL}/functions"

# Use curl with better error handling and store response in a file
TEMP_RESPONSE=$(mktemp)
TEMP_VERBOSE=$(mktemp)
HTTP_CODE=$(curl -s -w "%{http_code}" "${BASE_URL}/functions" \
    -H "Content-Type: multipart/form-data" \
    -H "Accept: application/json" \
    -F "code=@function.zip" \
    -F "data=${FUNCTION_DATA}" \
    --max-time 300 \
    -o "${TEMP_RESPONSE}")

echo "HTTP Status Code: ${HTTP_CODE}"
RESPONSE_BODY=$(cat "${TEMP_RESPONSE}")
echo "Response Body: ${RESPONSE_BODY}"

# Clean up temp files
rm -f "${TEMP_RESPONSE}" "${TEMP_VERBOSE}"

# Check HTTP status code
if [ "${HTTP_CODE}" != "201" ]; then
    error "Failed to create function. Status code: ${HTTP_CODE}, Response: ${RESPONSE_BODY}"
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

# Wait for function to be ready with improved debugging and error handling
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