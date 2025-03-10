import * as fs from 'fs';
import * as path from 'path';
import { LogEntry } from './types';

/**
 * Focused Rate Limiting Implementation Using Sliding Window Strategy
 *
 * This implementation specifically focuses on the sliding window rate limiting strategy
 * for analyzing logs from requests_responses.txt and detecting rate limit violations.
 */

// File paths
const LOG_FILE_PATH = path.join(process.cwd(), 'public', 'requests_responses.txt');
const DETECTION_LOG_PATH = path.join(process.cwd(), 'logs', 'rate_limit_detection.csv');

// Types for rate limiting
export interface RateLimitResult {
	exceeded: boolean;
	reason: string;
	remaining: number;
	resetAt: number;
}

export interface RateLimitConfig {
	// General settings
	enabled: boolean;

	// Limits by client ID
	clientRateLimits: {
		[clientId: string]: {
			requestsPerMinute: number;
		};
	};

	// Limits by endpoint
	endpointRateLimits: {
		[endpoint: string]: {
			requestsPerMinute: number;
		};
	};

	// Default limits
	defaultRequestsPerMinute: number;
}

// Default configuration
const defaultConfig: RateLimitConfig = {
	enabled: true,

	clientRateLimits: {
		// Example client-specific limits
		anya123456: {
			requestsPerMinute: 30, // Stricter limit for specific client
		},
	},

	endpointRateLimits: {
		// Example endpoint-specific limits
		'/api/v2/mgmts/oauth/2.0/token': {
			requestsPerMinute: 5, // Stricter limit for authentication endpoint
		},
		'/api/oauth/2.0/token': {
			requestsPerMinute: 5, // Stricter limit for authentication endpoint
		},
		'/api/ca/sign_request': {
			requestsPerMinute: 10,
		},
	},

	defaultRequestsPerMinute: 20,
};

/**
 * Sliding Window Rate Limiter
 * This class implements the sliding window algorithm for rate limiting
 */
export class SlidingWindowRateLimiter {
	private readonly config: RateLimitConfig;
	private readonly requestStore: Map<string, number[]>;

	constructor(config: Partial<RateLimitConfig> = {}) {
		this.config = { ...defaultConfig, ...config };
		this.requestStore = new Map<string, number[]>();
	}

	/**
	 * Checks if a request exceeds rate limits
	 * @param entry The log entry containing request data
	 * @returns A result object indicating if limits were exceeded and why
	 */
	public checkRateLimit(entry: LogEntry): RateLimitResult {
		if (!this.config.enabled) {
			return { exceeded: false, reason: '', remaining: Infinity, resetAt: 0 };
		}

		// Extract relevant information from the log entry
		const clientId = this.extractClientId(entry);
		const endpoint = this.extractEndpoint(entry);
		const timestamp = this.extractTimestamp(entry);

		// Check client-specific rate limit
		const clientCheck = this.checkSlidingWindowLimit(`client:${clientId}`, this.getClientLimit(clientId), timestamp);

		if (clientCheck.exceeded) {
			return clientCheck;
		}

		// Check endpoint-specific rate limit
		const endpointCheck = this.checkSlidingWindowLimit(
			`endpoint:${endpoint}:${clientId}`,
			this.getEndpointLimit(endpoint),
			timestamp
		);

		if (endpointCheck.exceeded) {
			return endpointCheck;
		}

		// If all checks pass, return the remaining count from the more restrictive limit
		return {
			exceeded: false,
			reason: '',
			remaining: Math.min(clientCheck.remaining, endpointCheck.remaining),
			resetAt: Math.min(clientCheck.resetAt, endpointCheck.resetAt),
		};
	}

	/**
	 * Core sliding window rate limit implementation
	 * @param key Unique key for the rate limit (client, endpoint, etc.)
	 * @param limit Maximum requests allowed in the time window
	 * @param timestamp Current request timestamp
	 * @returns Rate limit check result
	 */
	private checkSlidingWindowLimit(key: string, limit: number, timestamp: number): RateLimitResult {
		// Window size: 1 minute (60,000 ms)
		const windowSize = 60000;
		const windowStart = timestamp - windowSize;

		// Initialize or get timestamps for this key
		if (!this.requestStore.has(key)) {
			this.requestStore.set(key, []);
		}

		// Get timestamps and filter out those outside the current window
		const timestamps = this.requestStore.get(key)!;
		const validTimestamps = timestamps.filter((time) => time > windowStart);

		// Update the store with only valid timestamps
		this.requestStore.set(key, validTimestamps);

		// Check if limit is exceeded
		if (validTimestamps.length >= limit) {
			return {
				exceeded: true,
				reason: `Rate limit of ${limit} requests per minute exceeded for ${key}`,
				remaining: 0,
				resetAt: validTimestamps.length > 0 ? validTimestamps[0] + windowSize : timestamp + windowSize,
			};
		}

		// Add current timestamp to the window
		validTimestamps.push(timestamp);
		this.requestStore.set(key, validTimestamps);

		// Return successful result with remaining count
		return {
			exceeded: false,
			reason: '',
			remaining: limit - validTimestamps.length,
			resetAt: timestamp + windowSize,
		};
	}

	/**
	 * Extract the client ID from the log entry
	 */
	private extractClientId(entry: LogEntry): string {
		// Use the first 10 characters of x-api-tran-id as client ID
		const transactionId = entry.request['x-api-tran-id'] || '';
		return transactionId.substring(0, 10);
	}

	/**
	 * Extract the endpoint from the log entry URL
	 */
	private extractEndpoint(entry: LogEntry): string {
		try {
			const url = new URL(entry.request.url);
			return url.pathname;
		} catch (e) {
			// If URL parsing fails, extract path part from the URL string
			const urlPath = entry.request.url.split('?')[0];
			return urlPath;
		}
	}

	/**
	 * Extract the timestamp from the log entry
	 */
	public extractTimestamp(entry: LogEntry): number {
		// In a real implementation, we would use the timestamp from the log
		// For this example, use current time if not available in the log
		return Date.now();
	}

	/**
	 * Get the rate limit for a specific client
	 */
	private getClientLimit(clientId: string): number {
		const clientConfig = this.config.clientRateLimits[clientId];
		return clientConfig ? clientConfig.requestsPerMinute : this.config.defaultRequestsPerMinute;
	}

	/**
	 * Get the rate limit for a specific endpoint
	 */
	private getEndpointLimit(endpoint: string): number {
		const endpointConfig = this.config.endpointRateLimits[endpoint];
		return endpointConfig ? endpointConfig.requestsPerMinute : this.config.defaultRequestsPerMinute;
	}
}

/**
 * Parse a log line into a LogEntry object
 */
export function parseLogLine(line: string): LogEntry | null {
	try {
		// Format from requests_responses.txt is:
		// ||[timestamp] [request {...}] [response {...}]
		const parts = line.split('[');

		if (parts.length < 4) return null;

		const requestPart = '[' + parts[2];
		const responsePart = '[' + parts[3];

		// Extract and parse the request and response JSON
		const requestMatch = requestPart.match(/\[request (.*?)\]/);
		const responseMatch = responsePart.match(/\[response (.*?)\]/);

		if (!requestMatch || !responseMatch) return null;

		const request = JSON.parse(requestMatch[1]);
		const response = JSON.parse(responseMatch[1]);

		return { request, response };
	} catch (e) {
		console.error('Error parsing log line:', e);
		return null;
	}
}

/**
 * Parse the timestamp from the log line
 */
export function parseTimestamp(line: string): Date | null {
	try {
		const timestampMatch = line.match(/\|\|\[(.*?)\]/);
		if (!timestampMatch) return null;

		return new Date(timestampMatch[1]);
	} catch (e) {
		console.error('Error parsing timestamp:', e);
		return null;
	}
}

/**
 * Read log file and apply rate limiting
 */
export async function analyzeLogsWithRateLimit(logFilePath: string = LOG_FILE_PATH): Promise<void> {
	// Ensure log directory exists
	const logDir = path.dirname(DETECTION_LOG_PATH);
	if (!fs.existsSync(logDir)) {
		fs.mkdirSync(logDir, { recursive: true });
	}

	// Initialize CSV with headers if it doesn't exist
	if (!fs.existsSync(DETECTION_LOG_PATH)) {
		const headers = 'timestamp,detectionType,detected,reason,request,response\n';
		fs.writeFileSync(DETECTION_LOG_PATH, headers);
	}

	try {
		// Read the entire log file
		const logContent = fs.readFileSync(logFilePath, 'utf8');
		const logLines = logContent.split('\n').filter((line) => line.trim() !== '');

		// Create rate limiter instance
		const rateLimiter = new SlidingWindowRateLimiter();

		// Process each log line
		for (const line of logLines) {
			const entry = parseLogLine(line);
			if (!entry) continue;

			// Extract timestamp for more accurate rate limiting
			const timestamp = parseTimestamp(line);
			if (timestamp) {
				// Override the timestamp extraction method for accurate historical analysis
				const originalExtractMethod = rateLimiter.extractTimestamp;
				// Use a function that returns the timestamp from the log
				rateLimiter.extractTimestamp = () => timestamp.getTime();
			}

			// Check rate limit
			const result = rateLimiter.checkRateLimit(entry);

			// Log rate limit violations
			if (result.exceeded) {
				await logRateLimitViolation(entry, result, timestamp);
				console.log(`[RATE LIMIT VIOLATION] ${result.reason}`);
			}
		}

		console.log('Rate limit analysis completed. Results written to:', DETECTION_LOG_PATH);
	} catch (error) {
		console.error('Error analyzing logs:', error);
	}
}

/**
 * Log rate limit violations to CSV
 */
async function logRateLimitViolation(entry: LogEntry, result: RateLimitResult, timestamp: Date | null): Promise<void> {
	const logTimestamp = timestamp ? timestamp.toISOString() : new Date().toISOString();

	const record = {
		timestamp: logTimestamp,
		detectionType: 'RateLimit',
		detected: result.exceeded,
		reason: result.reason,
		request: JSON.stringify(entry.request),
		response: JSON.stringify(entry.response),
	};

	const csvLine = `${record.timestamp},${record.detectionType},${record.detected},${record.reason.replace(
		/,/g,
		';'
	)},${record.request.replace(/,/g, ';')},${record.response.replace(/,/g, ';')}\n`;

	fs.appendFileSync(DETECTION_LOG_PATH, csvLine);
}

// Run the analysis if this file is executed directly
if (require.main === module) {
	analyzeLogsWithRateLimit()
		.then(() => console.log('Analysis complete'))
		.catch((err) => console.error('Error:', err));
}
