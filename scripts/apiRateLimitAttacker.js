/**
 * API Rate Limit Attacker
 *
 * This script simulates an attack on the API by sending requests at a high rate
 * to trigger rate limit detection. It can be used for testing and demonstration purposes.
 *
 * Usage:
 * node apiRateLimitAttacker.js --target=http://localhost:3000/api --requests=100 --interval=50 --client=attacker
 */

const fs = require('fs');
const path = require('path');
const axios = require('axios');
const { v4: uuidv4 } = require('uuid');

// Default configuration
const defaultConfig = {
	targetUrl: 'http://localhost:3000/api/ca/sign_request', // Default target URL
	requestCount: 50, // Number of requests to send
	requestInterval: 100, // Interval between requests in ms
	clientId: 'attack-test', // Client ID to use
	clientCategory: 'standard', // Client category (premium, standard, restricted)
	outputFile: path.join(process.cwd(), 'attack_logs.csv'), // Output file for logs
	requestTimeout: 5000, // Request timeout in ms
	logToConsole: true, // Whether to log to console
};

// Parse command line arguments
function parseArgs() {
	const args = process.argv.slice(2);
	const config = { ...defaultConfig };

	args.forEach((arg) => {
		if (arg.startsWith('--target=')) {
			config.targetUrl = arg.split('=')[1];
		} else if (arg.startsWith('--requests=')) {
			config.requestCount = parseInt(arg.split('=')[1], 10);
		} else if (arg.startsWith('--interval=')) {
			config.requestInterval = parseInt(arg.split('=')[1], 10);
		} else if (arg.startsWith('--client=')) {
			config.clientId = arg.split('=')[1];
		} else if (arg.startsWith('--category=')) {
			const category = arg.split('=')[1].toLowerCase();
			if (['premium', 'standard', 'restricted'].includes(category)) {
				config.clientCategory = category;
			} else {
				console.warn(`Invalid client category: ${category}. Using 'standard' instead.`);
			}
		} else if (arg.startsWith('--output=')) {
			config.outputFile = arg.split('=')[1];
		} else if (arg === '--silent') {
			config.logToConsole = false;
		} else if (arg === '--help' || arg === '-h') {
			showHelp();
			process.exit(0);
		}
	});

	// Apply client category prefix if not already included
	if (
		!config.clientId.startsWith('premium-') &&
		!config.clientId.startsWith('restricted-') &&
		!config.clientId.includes('-prem-') &&
		!config.clientId.includes('-rest-')
	) {
		config.clientId = `${config.clientCategory}-${config.clientId}`;
	}

	return config;
}

function showHelp() {
	console.log(`
API Rate Limit Attacker
-----------------------
This tool simulates API attacks by sending requests at a high rate to trigger rate limiting.

Usage:
  node apiRateLimitAttacker.js [options]

Options:
  --target=URL        Target API URL (default: ${defaultConfig.targetUrl})
  --requests=N        Number of requests to send (default: ${defaultConfig.requestCount})
  --interval=MS       Interval between requests in ms (default: ${defaultConfig.requestInterval})
  --client=ID         Client ID to use (default: ${defaultConfig.clientId})
  --category=TYPE     Client category: premium, standard, restricted (default: ${defaultConfig.clientCategory})
  --output=FILE       Output file for logs (default: ${defaultConfig.outputFile})
  --silent            Suppress console output
  --help, -h          Show this help message

Examples:
  # Send 100 requests with 50ms intervals
  node apiRateLimitAttacker.js --requests=100 --interval=50

  # Attack a specific endpoint as a premium client
  node apiRateLimitAttacker.js --target=http://example.com/api/v1/users --client=my-client --category=premium
    `);
}

// Initialize CSV output
function initCsv(filePath) {
	const dir = path.dirname(filePath);
	if (!fs.existsSync(dir)) {
		fs.mkdirSync(dir, { recursive: true });
	}

	const headers = 'timestamp,url,method,status,duration,client_id,request_id\n';
	fs.writeFileSync(filePath, headers);
}

// Log a request to CSV
function logRequest(filePath, requestData) {
	const { timestamp, url, method, status, duration, clientId, requestId } = requestData;
	const logLine = `${timestamp},${url},${method},${status},${duration},${clientId},${requestId}\n`;
	fs.appendFileSync(filePath, logLine);
}

// Create a payload for the request
function createPayload(clientId, endpoint) {
	// Default payload for certificate request
	if (endpoint.includes('sign_request')) {
		return {
			certificate: {
				commonName: `${clientId}-test.example.com`,
				organization: 'Test Organization',
				organizationalUnit: 'Security Testing',
				country: 'US',
				state: 'Test State',
				locality: 'Test City',
			},
			csr: '-----BEGIN CERTIFICATE REQUEST-----\nMIICnTCCAYUCAQAwXDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRQwEgYDVQQH\nDAtMb3MgQW5nZWxlczENMAsGA1UECgwEVGVzdDEbMBkGA1UEAwwSdGVzdC5leGFt\ncGxlLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK6VD9vygInA\newp1XUReA5HnmVB6A4nFi0crSN9z9WAKtpxl9ghFQsxZyZCZwQK1mxX9Vtag6wwX\nQQZtF18P/LGi45NFkY/Lx+vU9wYYO27GVhCwQ+YBwaC8T+u/TD+F9WM1VCDY1Xqu\nK5UJVf5XzfVa8DIPTP4i3qZYZrbGV3Z4RrFHUQA0PyANRFIHVdB7Dc0sRdUJjoZS\nwRjERCVf1nhQYexoBYhHIMEYY4nGzBxKiOY4FxX6DQN40+jreFdgOCEXUYKbsgZc\ns9w2jQNzBq3eQCKZK0ztEKpQ6p1egv9R5azuNYYnWyEZ1QlnUvxPT61CbVVZNgFl\nBJ/XegsqyUsCAwEAAaAAMA0GCSqGSIb3DQEBCwUAA4IBAQAuq9Gv6RLfCcLhv2G8\ndMh2YnQxT8wdz3PXkKpMsXjJf6kxLjZDFJXKSqzVBWEXCGf2GUQkz7R9oJWhU1Z2\nXf0iy+NnZ3EnIQHI3tBfMO31+EXXxvLcWYjVzGK7eSgcz6nOk1SfFPGPr5HeK8xv\nzZIHdCm2CY+SjOhOBHe0xW1Q057M5b5eKkYfJoYKIlOJvgkxvz8zLWvK2Pv2eLXq\nYUjziW1qihC6/wBnlqzQ2iLF7MsWyZzxsNK0UDi7SZnfVs7HO7K+5avn4zOFnG+P\nKnmD/UQMEJYwgBS3m0xwIMHsyDhvoHJfZ7zzr0XVeUmgSuXvyrXRITNl0uQXnt64\noXcF\n-----END CERTIFICATE REQUEST-----\n',
		};
	}

	// Default payload for authentication
	if (endpoint.includes('token') || endpoint.includes('oauth')) {
		return {
			client_id: clientId,
			client_secret: 'attack-test-secret',
			grant_type: 'client_credentials',
		};
	}

	// Generic payload for other endpoints
	return {
		client_id: clientId,
		timestamp: new Date().toISOString(),
		requestId: uuidv4(),
		data: {
			test: 'Attack test payload',
			timestamp: Date.now(),
		},
	};
}

// Send a single request
async function sendRequest(config, requestNumber) {
	const requestId = uuidv4();
	const startTime = Date.now();
	const timestamp = new Date().toISOString();

	try {
		const response = await axios({
			method: 'POST',
			url: config.targetUrl,
			data: createPayload(config.clientId, config.targetUrl),
			headers: {
				'Content-Type': 'application/json',
				'X-API-Key': config.clientId,
				'X-API-Tran-ID': `${config.clientId}-${requestId}`,
				'User-Agent': 'API-Attack-Test/1.0',
			},
			timeout: config.requestTimeout,
		});

		const duration = Date.now() - startTime;

		if (config.logToConsole) {
			console.log(`[${requestNumber}/${config.requestCount}] ${timestamp} - ${response.status} (${duration}ms)`);
		}

		logRequest(config.outputFile, {
			timestamp,
			url: config.targetUrl,
			method: 'POST',
			status: response.status,
			duration,
			clientId: config.clientId,
			requestId,
		});

		return { success: true, status: response.status };
	} catch (error) {
		const duration = Date.now() - startTime;
		const status = error.response ? error.response.status : 'ERROR';

		if (config.logToConsole) {
			console.error(`[${requestNumber}/${config.requestCount}] ${timestamp} - ERROR: ${status} (${duration}ms)`);
		}

		logRequest(config.outputFile, {
			timestamp,
			url: config.targetUrl,
			method: 'POST',
			status,
			duration,
			clientId: config.clientId,
			requestId,
		});

		return { success: false, status };
	}
}

// Main function
async function main() {
	const config = parseArgs();

	console.log(`
API Rate Limit Attacker
-----------------------
Target URL:       ${config.targetUrl}
Request Count:    ${config.requestCount}
Request Interval: ${config.requestInterval}ms
Client ID:        ${config.clientId}
Output File:      ${config.outputFile}
`);

	// Initialize output file
	initCsv(config.outputFile);

	// Confirm before starting attack
	if (process.stdin.isTTY) {
		process.stdout.write('Press Enter to start the attack or Ctrl+C to abort...');
		await new Promise((resolve) => process.stdin.once('data', resolve));
	}

	console.log('\nStarting attack...');

	const startTime = Date.now();
	let successCount = 0;
	let failCount = 0;

	// Send requests with specified interval
	for (let i = 1; i <= config.requestCount; i++) {
		const result = await sendRequest(config, i);
		if (result.success) {
			successCount++;
		} else {
			failCount++;
		}

		// Wait for the interval unless it's the last request
		if (i < config.requestCount) {
			await new Promise((resolve) => setTimeout(resolve, config.requestInterval));
		}
	}

	const totalTime = (Date.now() - startTime) / 1000;
	const requestsPerSecond = config.requestCount / totalTime;

	console.log(`
Attack completed
---------------
Requests sent:     ${config.requestCount}
Successful:        ${successCount}
Failed:            ${failCount}
Total time:        ${totalTime.toFixed(2)}s
Requests/second:   ${requestsPerSecond.toFixed(2)}
Log file:          ${config.outputFile}
`);

	// Convert attack logs to CA format for detection
	console.log('Converting attack logs to detection format...');
	convertLogsToDetectionFormat(config.outputFile);
}

// Convert attack logs to CA detection format
function convertLogsToDetectionFormat(attackLogFile) {
	try {
		const outputFile = path.join(process.cwd(), 'public', 'attack_formatted_logs.csv');

		// Create headers for CA format
		const caHeaders =
			'timestamp,source.ip,request.method,request.url,request.headers,response.status,attack.type,attack.description\n';
		fs.writeFileSync(outputFile, caHeaders);

		// Read attack logs
		const attackLogs = fs.readFileSync(attackLogFile, 'utf8');
		const lines = attackLogs.split('\n');

		// Skip header
		for (let i = 1; i < lines.length; i++) {
			const line = lines[i].trim();
			if (!line) continue;

			const [timestamp, url, method, status, duration, clientId, requestId] = line.split(',');

			// Extract endpoint from URL
			let endpoint = url;
			try {
				// Try to parse as URL and get pathname
				const urlObj = new URL(url);
				endpoint = urlObj.pathname;
			} catch {
				// If parsing fails, just use the URL as is or extract path portion
				endpoint = url.split('?')[0];
			}

			// Create request object with improved information
			const request = {
				url,
				method,
				path: endpoint, // Add explicit path/endpoint information
				headers: {
					'X-API-Key': clientId,
					'X-API-Tran-ID': requestId,
				},
			};

			// Create CA format line
			// Classify as rate limit attack
			const caLine = `${timestamp},192.168.1.1,${method},${url},${JSON.stringify(
				request
			)},${status},rate_limit_attack,API flooding attack to trigger rate limiting\n`;
			fs.appendFileSync(outputFile, caLine);
		}

		console.log(`Converted logs saved to: ${outputFile}`);
		console.log(`You can now copy these logs to ca_formatted_logs.csv to test rate limit detection.`);
	} catch (error) {
		console.error('Error converting logs:', error);
	}
}

// Run the main function
main().catch((error) => {
	console.error('Unhandled error:', error);
	process.exit(1);
});
