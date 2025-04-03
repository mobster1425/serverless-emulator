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

# Create a simple async test function
cat > index.js << 'EOL'
exports.handler = async (event, context) => {
    // Simulate long running task
    await new Promise(resolve => setTimeout(resolve, 5000));
    
    return {
        statusCode: 200,
        body: {
            message: "Async execution completed",
            input: event,
            timestamp: new Date().toISOString()
        }
    };
};
EOL

# Create package.json
cat > package.json << 'EOL'
{
  "name": "async-test",
  "version": "1.0.0",
  "main": "index.js"
}
EOL

# Create zip file
zip -r ../function.zip ./*
cd ..

# Function metadata
FUNCTION_DATA='{
    "name": "async-test-function",
    "runtime": "nodejs18",
    "handler": "index.handler",
    "memory": 128,
    "timeout": 30,
    "environment": []
}'

# Create function with improved error handling and response capture
echo "Creating function..."
echo "Function data: $FUNCTION_DATA"

debug "Sending POST request to ${BASE_URL}/functions"

# Use curl with better error handling and store response in a file
TEMP_RESPONSE=$(mktemp)
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
rm -f "${TEMP_RESPONSE}"

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

# Test async invocation with proper payload and error handling
echo "Testing async invocation..."
INVOKE_DATA='{
    "payload": {"test": "async invocation"},
    "async": true
}'

echo "Invoke request data:"
echo "${INVOKE_DATA}" | jq .

# Use temp file for invoke response
TEMP_INVOKE=$(mktemp)
echo "Sending async request to ${BASE_URL}/functions/${FUNCTION_ID}/invoke"
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

echo "Async invoke response:"
echo "${INVOKE_RESPONSE}" | jq . || echo "Failed to parse response as JSON: ${INVOKE_RESPONSE}"

# Extract request ID from async response with better error handling
REQUEST_ID=$(echo "${INVOKE_RESPONSE}" | jq -r '.request_id')
if [ -z "${REQUEST_ID}" ] || [ "${REQUEST_ID}" = "null" ]; then
    error "Failed to get request ID from async response"
fi

echo "Request ID: ${REQUEST_ID}"

# Poll for function logs to check execution status with improved error handling
echo "Polling for execution status..."
for i in {1..20}; do
    echo "Checking execution status (attempt $i)..."
    
    # Use temp file for logs response
    TEMP_LOGS=$(mktemp)
    LOGS_CODE=$(curl -s -w "%{http_code}" "${BASE_URL}/functions/${FUNCTION_ID}/logs" -o "${TEMP_LOGS}")
    LOGS_RESPONSE=$(cat "${TEMP_LOGS}")
    rm -f "${TEMP_LOGS}"
    
    if [ "${LOGS_CODE}" != "200" ]; then
        echo "Error fetching logs (HTTP ${LOGS_CODE}), retrying..."
        sleep 5
        continue
    fi
    
    if [ -z "${LOGS_RESPONSE}" ]; then
        echo "Empty logs response, retrying..."
        sleep 5
        continue
    fi
    
    LOG_STATUS=$(echo "${LOGS_RESPONSE}" | jq -r ".logs[] | select(.request_id==\"${REQUEST_ID}\") | .status" || echo "failed to parse logs")
    
    if [ "${LOG_STATUS}" = "completed" ]; then
        echo "Async execution completed successfully"
        echo "Final log entry:"
        echo "${LOGS_RESPONSE}" | jq ".logs[] | select(.request_id==\"${REQUEST_ID}\")"
        break
    elif [ "${LOG_STATUS}" = "failed" ]; then
        error "Async execution failed"
    elif [ $i -eq 20 ]; then
        error "Timed out waiting for async execution"
    fi
    
    echo "Status: ${LOG_STATUS}, waiting..."
    sleep 5
done

# Cleanup
rm -rf test-function function.zip 