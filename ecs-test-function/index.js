exports.handler = async (event, context) => {
    // Print detailed information about the runtime environment
    console.log('=== RUNTIME INFORMATION ===');
    console.log('Node.js version:', process.version);
    console.log('Architecture:', process.arch);
    console.log('Platform:', process.platform);
    console.log('Process ID:', process.pid);
    
    // Print all environment variables
    console.log('=== ENVIRONMENT VARIABLES ===');
    Object.keys(process.env).sort().forEach(key => {
        console.log(`${key}=${process.env[key]}`);
    });
    
    // Print CPU information if available (on Linux)
    try {
        const fs = require('fs');
        if (fs.existsSync('/proc/cpuinfo')) {
            console.log('=== CPU INFO ===');
            const cpuInfo = fs.readFileSync('/proc/cpuinfo', 'utf8');
            const modelName = cpuInfo.split('\n')
                .find(line => line.includes('model name'))
                ?.split(':')[1]?.trim();
            console.log('CPU Model:', modelName || 'Unknown');
        }
    } catch (error) {
        console.log('Error reading CPU info:', error.message);
    }
    
    // Return detailed system information
    return {
        message: "Architecture test completed successfully",
        system: {
            nodejs: process.version,
            arch: process.arch,
            platform: process.platform,
            env: process.env.NODE_ENV,
        },
        timestamp: new Date().toISOString()
    };
};
