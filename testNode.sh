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

# Create index.js with more complex image processing logic
cat > index.js << 'EOL'
// Simulate image processing library
class ImageProcessor {
    constructor() {
        this.supportedFormats = ['jpeg', 'png', 'gif', 'webp'];
    }
    
    analyzeImage(imageData) {
        if (!imageData || !imageData.format) {
            throw new Error('Invalid image data provided');
        }
        
        if (!this.supportedFormats.includes(imageData.format.toLowerCase())) {
            throw new Error(`Unsupported format: ${imageData.format}`);
        }
        
        // Calculate aspect ratio
        const aspectRatio = imageData.width / imageData.height;
        
        // Calculate compression ratio (original / compressed)
        const compressionRatio = Math.round((imageData.size / (imageData.width * imageData.height * 3)) * 100) / 100;
        
        // Determine image category based on dimensions
        let category = 'unknown';
        if (aspectRatio > 1.5) {
            category = 'panorama';
        } else if (aspectRatio < 0.75) {
            category = 'portrait';
        } else if (imageData.width >= 1920 && imageData.height >= 1080) {
            category = 'high-resolution';
        } else if (imageData.width <= 800 && imageData.height <= 600) {
            category = 'thumbnail';
        } else {
            category = 'standard';
        }
        
        // Simulate processing time based on size
        const processingTime = Math.log(imageData.size) * 2;
        
        return {
            name: imageData.name,
            dimensions: {
                width: imageData.width,
                height: imageData.height,
                aspectRatio: parseFloat(aspectRatio.toFixed(2))
            },
            format: imageData.format,
            category: category,
            size: {
                bytes: imageData.size,
                kilobytes: Math.round(imageData.size / 1024),
                megabytes: parseFloat((imageData.size / (1024 * 1024)).toFixed(2))
            },
            analysis: {
                compressionRatio: compressionRatio,
                estimatedQuality: this.estimateQuality(imageData),
                processingTimeMs: processingTime
            },
            transformations: this.getRecommendedTransformations(imageData, category)
        };
    }
    
    estimateQuality(imageData) {
        // Simple quality estimation based on size per pixel
        const pixelCount = imageData.width * imageData.height;
        const bytesPerPixel = imageData.size / pixelCount;
        
        if (bytesPerPixel < 0.5) return 'low';
        if (bytesPerPixel < 2) return 'medium';
        return 'high';
    }
    
    getRecommendedTransformations(imageData, category) {
        const transformations = [];
        
        // Recommend resizing for very large images
        if (imageData.width > 2000 || imageData.height > 2000) {
            transformations.push({
                type: 'resize',
                params: {
                    width: Math.min(2000, imageData.width),
                    height: Math.min(2000, imageData.height),
                    preserveAspectRatio: true
                }
            });
        }
        
        // Format conversion recommendations
        if (imageData.format.toLowerCase() === 'jpeg' || imageData.format.toLowerCase() === 'png') {
            transformations.push({
                type: 'convert',
                params: {
                    format: 'webp',
                    reason: 'Better compression and quality'
                }
            });
        }
        
        // Compression recommendation for large files
        if (imageData.size > 1000000) {
            transformations.push({
                type: 'compress',
                params: {
                    quality: 85,
                    estimatedSavings: `${Math.round((imageData.size * 0.3) / 1024)}KB`
                }
            });
        }
        
        return transformations;
    }
}

exports.handler = async (event, context) => {
    console.log('Starting advanced image analysis');
    console.log('Event:', JSON.stringify(event));
    
    try {
        // Add input validation
        if (!event || !event.payload || !event.payload.images || !Array.isArray(event.payload.images)) {
            throw new Error('Invalid input: expected event.payload.images array');
        }

        // Process each image
        const processor = new ImageProcessor();
        const startTime = Date.now();
        
        const processedImages = event.payload.images.map(img => processor.analyzeImage(img));
        
        // Calculate batch statistics
        const totalSize = processedImages.reduce((sum, img) => sum + img.size.bytes, 0);
        const averageWidth = processedImages.reduce((sum, img) => sum + img.dimensions.width, 0) / processedImages.length;
        const averageHeight = processedImages.reduce((sum, img) => sum + img.dimensions.height, 0) / processedImages.length;
        
        // Group by category
        const categoryCounts = {};
        processedImages.forEach(img => {
            categoryCounts[img.category] = (categoryCounts[img.category] || 0) + 1;
        });
        
        const result = {
            message: "Image analysis completed successfully",
            executionTime: Date.now() - startTime,
            summary: {
                imagesProcessed: processedImages.length,
                totalSizeBytes: totalSize,
                totalSizeMB: parseFloat((totalSize / (1024 * 1024)).toFixed(2)),
                averageDimensions: {
                    width: Math.round(averageWidth),
                    height: Math.round(averageHeight)
                },
                categoryDistribution: categoryCounts
            },
            processedImages: processedImages,
            input: event,
            timestamp: new Date().toISOString()
        };
        
        // Log the result with explicit markers for easier parsing
        console.log('--- Function Output ---');
        console.log(JSON.stringify(result, null, 2));
        console.log('----------------------');
        
        // Also log with standard pattern that our parser looks for
        console.log('Execution successful:', JSON.stringify(result));
        
        return result;
    } catch (error) {
        console.error('Execution failed:', error);
        throw error;
    }
};
EOL

# Create package.json
cat > package.json << 'EOL'
{
  "name": "image-analyzer",
  "version": "1.0.0",
  "main": "index.js"
}
EOL

# Create zip file
zip -r ../function.zip ./*
cd ..

# Function metadata
FUNCTION_DATA='{
    "name": "image-analyzer",
    "runtime": "nodejs18",
    "handler": "index.handler",
    "memory": 256,
    "timeout": 60,
    "environment": [
        {"key": "NODE_ENV", "value": "production"}
    ]
}'

# Create function with improved error handling and response capture
echo "Creating function..."
echo "Sending request to ${BASE_URL}/functions"

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
                "name": "test-image.jpg",
                "width": 1920,
                "height": 1080,
                "size": 2097152,
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


