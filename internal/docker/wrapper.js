#!/usr/bin/env node

const fs = require("fs");
const path = require("path");
const { performance } = require("perf_hooks");

// Determine function handler path
const handlerPath = process.env.AWS_LAMBDA_FUNCTION_HANDLER || "index.handler";
const [fileName, handlerName] = handlerPath.split(".");

// Load the handler function
console.log("Loading handler from " + fileName + ".js (" + handlerName + ")");
let handlerModule;
try {
  handlerModule = require("./" + fileName);
  if (!handlerModule[handlerName]) {
    throw new Error("Handler function \"" + handlerName + "\" not found in module \"" + fileName + "\"");
  }
} catch (err) {
  console.error("Failed to load handler: " + err.message);
  process.exit(1);
}

// Get the handler function
const handler = handlerModule[handlerName];

// Execute async function
async function run() {
  // Read the event data from stdin
  let event = {};
  let context = { 
    functionName: process.env.AWS_LAMBDA_FUNCTION_NAME,
    functionVersion: process.env.AWS_LAMBDA_FUNCTION_VERSION || '1',
    memoryLimitInMB: process.env.AWS_LAMBDA_FUNCTION_MEMORY_SIZE || '128',
    logGroupName: process.env.AWS_LAMBDA_LOG_GROUP_NAME,
    logStreamName: process.env.AWS_LAMBDA_LOG_STREAM_NAME
  };

  try {
    const stdinBuffer = fs.readFileSync(0, "utf-8").trim();
    if (stdinBuffer) {
      try {
        // Try to parse the JSON input
        const parsedData = JSON.parse(stdinBuffer);
        
        // Handle different input formats
        if (parsedData.event) {
          // Format: { event: {...}, context: {...} }
          event = parsedData.event;
          if (parsedData.context) {
            context = { ...context, ...parsedData.context };
          }
        } else if (parsedData.payload) {
          // Format: { payload: {...} }
          event = { payload: parsedData.payload };
        } else {
          // Assume direct event object
          event = parsedData;
        }
      } catch (parseErr) {
        console.error("Error parsing event data: " + parseErr.message);
        event = { rawInput: stdinBuffer };
      }
    }
  } catch (readErr) {
    console.error("Warning: Could not read from stdin: " + readErr.message);
  }

  // Log event data for debugging
  console.log("Starting handler execution");
  console.log("Event:", JSON.stringify(event, null, 2));
  console.log("Context:", JSON.stringify(context, null, 2));

  // Execute handler function
  try {
    const startTime = performance.now();
    let response;

    if (handler.length >= 3) {
      // Handler uses callback pattern
      response = await new Promise((resolve, reject) => {
        handler(event, context, (err, result) => {
          if (err) {
            reject(err);
          } else {
            resolve(result);
          }
        });
      });
    } else {
      // Handler uses async pattern
      response = await handler(event, context);
    }

    const endTime = performance.now();
    const executionTime = endTime - startTime;

    // Output with markers for easier parsing
    console.log("--- FUNCTION OUTPUT START ---");
    if (typeof response === "object") {
      try {
        console.log(JSON.stringify(response));
      } catch (e) {
        console.log(response);
      }
    } else {
      console.log(response);
    }
    console.log("--- FUNCTION OUTPUT END ---");

    console.log("Execution successful - Duration: " + executionTime.toFixed(2) + "ms");
    process.exit(0);
  } catch (error) {
    console.error("Function execution failed:");
    console.error(error);

    console.log("--- FUNCTION OUTPUT START ---");
    console.log(JSON.stringify({
      errorMessage: error.message || "Unknown error",
      errorType: error.name || "Error",
      stackTrace: error.stack ? error.stack.split("\n") : ["No stack trace available"]
    }));
    console.log("--- FUNCTION OUTPUT END ---");

    process.exit(1);
  }
}

run(); 