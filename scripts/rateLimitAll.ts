import * as fs from 'fs';
import * as path from 'path';
import { Redis } from 'ioredis';
import { createObjectCsvWriter } from 'csv-writer';

/**
 * COMBINED RATE LIMITING AND DETECTION IMPLEMENTATION
 *
 * This file combines both the rate limiting implementation and the detection functionality
 * to avoid module resolution errors with imports.
 */

// ============= TYPE DEFINITIONS =============

// LogEntry type definition
export interface RequestData {
	url: string;
	method: string;
	authorization: string;
	'user-agent': string;
	'x-api-tran-id': string;
	'x-api-type'?: string;
	'x-csrf-token'?: string;
	cookie?: string;
	'set-cookie'?: string;
	'content-length'?: string;
	'x-forwarded-for'?: string;
	body?: string | any;
	[key: string]: string | any | undefined;
}

export interface ResponseData {
	body: string | any;
	[key: string]: string | any | undefined;
}

export interface LogEntry {
	request: RequestData;
	response: ResponseData;
	requestBody?: any;
	responseBody?: any;
}

// Rate limit result type
export interface RateLimitResult {
	exceeded: boolean;
	reason: string;
	remaining: number;
	resetAt: number; // Timestamp when the rate limit will reset
}

// Rate limit configuration interface
export interface RateLimitConfig {
	// General settings
	enabled: boolean;
	strategy: 'fixed-window' | 'sliding-window' | 'token-bucket';

	// Limits
	globalRateLimit: {
		requestsPerMinute: number;
		burstAllowance: number; // Additional requests allowed in burst scenarios
	};

	// Client-specific limits
	clientRateLimits: {
		[clientId: string]: {
			requestsPerMinute: number;
			maxPayloadSize: number; // in bytes
		};
	};

	// Endpoint-specific limits
	endpointRateLimits: {
		[endpoint: string]: {
			requestsPerMinute: number;
			maxPayloadSize: number; // in bytes
		};
	};

	// Method-specific limits
	methodRateLimits: {
		[method: string]: {
			requestsPerMinute: number;
		};
	};

	// Payload limits
	payloadLimits: {
		defaultMaxSize: number; // in bytes
		headerMaxSize: number; // in bytes
		bodyMaxSize: number; // in bytes
		fieldSpecificLimits: {
			[fieldName: string]: number; // in bytes
		};
	};

	// Action to take when limit is exceeded
	limitExceededAction: 'block' | 'delay' | 'log-only';

	// Redis configuration for distributed rate limiting
	redisConfig: {
		enabled: boolean;
		host: string;
		port: number;
		password: string;
		keyPrefix: string;
	};
}

// ============= RATE LIMITER IMPLEMENTATION =============

// Default configuration
const defaultConfig: RateLimitConfig = {
	enabled: true,
	strategy: 'sliding-window',

	globalRateLimit: {
		requestsPerMinute: 500,
		burstAllowance: 50,
	},

	clientRateLimits: {
		// Client-specific limits based on OrgCode
		anya123456: {
			requestsPerMinute: 150,
			maxPayloadSize: 2500,
		},
		bond123456: {
			requestsPerMinute: 120,
			maxPayloadSize: 2000,
		},
	},

	endpointRateLimits: {
		// Authentication endpoints - stricter limits to prevent abuse
		'/api/v2/mgmts/oauth/2.0/token': {
			requestsPerMinute: 10,
			maxPayloadSize: 1000,
		},
		'/api/oauth/2.0/token': {
			requestsPerMinute: 10,
			maxPayloadSize: 1000,
		},
		// Certificate management endpoints
		'/api/ca/sign_request': {
			requestsPerMinute: 20,
			maxPayloadSize: 5000,
		},
		'/api/ca/sign_result': {
			requestsPerMinute: 20,
			maxPayloadSize: 3000,
		},
		'/api/ca/sign_verification': {
			requestsPerMinute: 30,
			maxPayloadSize: 3000,
		},
		// Organization management endpoints
		'/api/v2/mgmts/orgs': {
			requestsPerMinute: 30,
			maxPayloadSize: 2000,
		},
	},

	methodRateLimits: {
		// Method-specific limits
		POST: {
			requestsPerMinute: 60,
		},
		GET: {
			requestsPerMinute: 120,
		},
		PUT: {
			requestsPerMinute: 40,
		},
		DELETE: {
			requestsPerMinute: 20,
		},
	},

	payloadLimits: {
		defaultMaxSize: 1000,
		headerMaxSize: 8192,
		bodyMaxSize: 1048576, // 1MB
		fieldSpecificLimits: {
			authorization: 2048,
			cookie: 4096,
			'x-api-tran-id': 50, // Based on OpenAPI spec: maxLength 25 characters
			client_id: 100, // Based on OpenAPI spec: maxLength 50 characters
			client_secret: 100, // Based on OpenAPI spec: maxLength 50 characters
			scope: 12, // Based on OpenAPI spec: maxLength 6 characters
		},
	},

	limitExceededAction: 'block',

	redisConfig: {
		enabled: false,
		host: 'localhost',
		port: 6379,
		password: '',
		keyPrefix: 'ratelimit:',
	},
};

export class RateLimiter {
	private readonly config: RateLimitConfig;
	private readonly inMemoryStore: Map<string, number[]>;
	private readonly redisClient?: Redis;

	/**
	 * Creates a new RateLimiter instance
	 * @param config - Configuration for the rate limiter
	 */
	constructor(config: Partial<RateLimitConfig> = {}) {
		this.config = { ...defaultConfig, ...config };
		this.inMemoryStore = new Map<string, number[]>();

		// Initialize Redis if enabled
		if (this.config.redisConfig.enabled) {
			this.redisClient = new Redis({
				host: this.config.redisConfig.host,
				port: this.config.redisConfig.port,
				password: this.config.redisConfig.password || undefined,
			});
		}
	}

	/**
	 * Checks if a request exceeds rate limits
	 * @param entry - The log entry containing request/response data
	 * @returns A result object indicating if limits were exceeded and why
	 */
	public async checkRateLimits(entry: LogEntry): Promise<RateLimitResult> {
		if (!this.config.enabled) {
			return { exceeded: false, reason: '', remaining: Infinity, resetAt: 0 };
		}

		const clientId = entry.request['x-api-tran-id'] || 'anonymous';
		const ip = entry.request['x-forwarded-for'] || 'unknown-ip';
		const url = entry.request.url;
		const method = entry.request.method;

		// Parse URL to get endpoint path
		let endpoint = '';
		try {
			endpoint = new URL(url).pathname;
		} catch (e) {
			endpoint = url.split('?')[0]; // Fallback if URL is invalid
		}

		// Check different types of rate limits
		const clientCheck = await this.checkClientRateLimit(clientId);
		if (clientCheck.exceeded) return clientCheck;

		const endpointCheck = await this.checkEndpointRateLimit(endpoint, clientId);
		if (endpointCheck.exceeded) return endpointCheck;

		const methodCheck = await this.checkMethodRateLimit(method, clientId);
		if (methodCheck.exceeded) return methodCheck;

		const payloadCheck = this.checkPayloadSize(entry);
		if (payloadCheck.exceeded) return payloadCheck;

		// If everything passes
		return {
			exceeded: false,
			reason: '',
			remaining: Math.min(clientCheck.remaining, endpointCheck.remaining, methodCheck.remaining),
			resetAt: Math.min(clientCheck.resetAt, endpointCheck.resetAt, methodCheck.resetAt),
		};
	}

	/**
	 * Checks client-specific rate limits
	 */
	private async checkClientRateLimit(clientId: string): Promise<RateLimitResult> {
		const clientConfig = this.config.clientRateLimits[clientId] || {
			requestsPerMinute: this.config.globalRateLimit.requestsPerMinute,
		};

		return this.checkRateLimit(`client:${clientId}`, clientConfig.requestsPerMinute);
	}

	/**
	 * Checks endpoint-specific rate limits
	 */
	private async checkEndpointRateLimit(endpoint: string, clientId: string): Promise<RateLimitResult> {
		const endpointConfig = this.config.endpointRateLimits[endpoint] || {
			requestsPerMinute: this.config.globalRateLimit.requestsPerMinute,
		};

		return this.checkRateLimit(`endpoint:${endpoint}:${clientId}`, endpointConfig.requestsPerMinute);
	}

	/**
	 * Checks method-specific rate limits
	 */
	private async checkMethodRateLimit(method: string, clientId: string): Promise<RateLimitResult> {
		const methodConfig = this.config.methodRateLimits[method] || {
			requestsPerMinute: this.config.globalRateLimit.requestsPerMinute,
		};

		return this.checkRateLimit(`method:${method}:${clientId}`, methodConfig.requestsPerMinute);
	}

	/**
	 * Core rate limit checking logic based on the configured strategy
	 */
	private async checkRateLimit(key: string, limit: number): Promise<RateLimitResult> {
		const now = Date.now();
		const windowSize = 60000; // 1 minute in milliseconds
		const windowEnd = now + windowSize;

		if (this.config.redisConfig.enabled && this.redisClient) {
			return this.checkRateLimitRedis(key, limit, now, windowSize);
		} else {
			return this.checkRateLimitInMemory(key, limit, now, windowSize);
		}
	}

	/**
	 * In-memory implementation of rate limiting
	 */
	private checkRateLimitInMemory(key: string, limit: number, now: number, windowSize: number): RateLimitResult {
		// Get current requests in the window
		let requests = this.inMemoryStore.get(key) || [];

		// Filter out expired timestamps based on strategy
		if (this.config.strategy === 'fixed-window') {
			// Fixed window: all requests in the current minute window
			const windowStart = Math.floor(now / windowSize) * windowSize;
			requests = requests.filter((timestamp) => timestamp >= windowStart);
		} else {
			// Sliding window: all requests in the last minute
			requests = requests.filter((timestamp) => now - timestamp < windowSize);
		}

		// Calculate when the rate limit will reset
		const resetAt =
			this.config.strategy === 'fixed-window'
				? Math.floor(now / windowSize) * windowSize + windowSize // Next minute boundary
				: now + windowSize; // 1 minute from now

		// Check if limit is exceeded
		if (requests.length >= limit) {
			return {
				exceeded: true,
				reason: `Rate limit of ${limit} requests per minute exceeded for ${key}`,
				remaining: 0,
				resetAt,
			};
		}

		// Add current request to history
		requests.push(now);
		this.inMemoryStore.set(key, requests);

		return {
			exceeded: false,
			reason: '',
			remaining: limit - requests.length,
			resetAt,
		};
	}

	/**
	 * Redis-based implementation for distributed rate limiting
	 */
	private async checkRateLimitRedis(
		key: string,
		limit: number,
		now: number,
		windowSize: number
	): Promise<RateLimitResult> {
		if (!this.redisClient) {
			return this.checkRateLimitInMemory(key, limit, now, windowSize);
		}

		const redisKey = `${this.config.redisConfig.keyPrefix}${key}`;
		const windowStart =
			this.config.strategy === 'fixed-window' ? Math.floor(now / windowSize) * windowSize : now - windowSize;

		// Redis pipeline for atomic operations
		const pipeline = this.redisClient.pipeline();

		// Add current timestamp to the sorted set
		pipeline.zadd(redisKey, now, now.toString());

		// Remove timestamps outside the current window
		pipeline.zremrangebyscore(redisKey, 0, windowStart);

		// Count requests in the current window
		pipeline.zcard(redisKey);

		// Set expiry on the key to auto-cleanup
		pipeline.expire(redisKey, Math.ceil(windowSize / 1000) * 2);

		// Execute pipeline
		const results = await pipeline.exec();

		// Check the count from the third command
		const count = (results?.[2]?.[1] as number) || 0;

		// Calculate reset time based on strategy
		const resetAt =
			this.config.strategy === 'fixed-window'
				? Math.floor(now / windowSize) * windowSize + windowSize
				: now + windowSize;

		if (count > limit) {
			return {
				exceeded: true,
				reason: `Rate limit of ${limit} requests per minute exceeded for ${key}`,
				remaining: 0,
				resetAt,
			};
		}

		return {
			exceeded: false,
			reason: '',
			remaining: limit - count,
			resetAt,
		};
	}

	/**
	 * Checks if payload size exceeds configured limits
	 */
	private checkPayloadSize(entry: LogEntry): RateLimitResult {
		if (!entry.request) {
			return { exceeded: false, reason: '', remaining: Infinity, resetAt: 0 };
		}

		const overloadedFields: string[] = [];

		// Check headers
		for (const [key, value] of Object.entries(entry.request)) {
			if (typeof value !== 'string') continue;

			const fieldLimit = this.config.payloadLimits.fieldSpecificLimits[key] || this.config.payloadLimits.defaultMaxSize;

			const size = Buffer.from(value).length;
			if (size > fieldLimit) {
				overloadedFields.push(`${key} (${size} bytes, limit: ${fieldLimit} bytes)`);
			}
		}

		// Check body size if present
		if (entry.requestBody) {
			const bodySize = Buffer.from(JSON.stringify(entry.requestBody)).length;
			if (bodySize > this.config.payloadLimits.bodyMaxSize) {
				overloadedFields.push(`body (${bodySize} bytes, limit: ${this.config.payloadLimits.bodyMaxSize} bytes)`);
			}
		}

		if (overloadedFields.length > 0) {
			return {
				exceeded: true,
				reason: `Payload size exceeded in fields: ${overloadedFields.join(', ')}`,
				remaining: 0,
				resetAt: 0, // Not applicable for payload size limits
			};
		}

		return { exceeded: false, reason: '', remaining: Infinity, resetAt: 0 };
	}

	/**
	 * Generates rate limit headers for HTTP responses
	 */
	public getRateLimitHeaders(result: RateLimitResult): Record<string, string> {
		return {
			'RateLimit-Limit': String(result.remaining + (result.exceeded ? 0 : 1)),
			'RateLimit-Remaining': String(result.exceeded ? 0 : result.remaining),
			'RateLimit-Reset': String(Math.ceil(result.resetAt / 1000)), // Unix timestamp in seconds
			...(result.exceeded ? { 'Retry-After': String(Math.ceil((result.resetAt - Date.now()) / 1000)) } : {}),
		};
	}
}

// ============= RATE LIMIT DETECTION IMPLEMENTATION =============

const LOG_FILE_PATH = path.join(process.cwd(), 'public', 'requests_responses.txt');
const RATE_LIMIT_LOG_PATH = path.join(process.cwd(), 'logs', 'rate_limit_detection.csv');

/**
 * Parse a log line into a LogEntry object
 */
function parseLogLine(line: string): LogEntry | null {
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
function parseTimestamp(line: string): Date | null {
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
 * Run rate limit detection on a log file
 * @param logFilePath The path to the log file to analyze
 */
export async function runRateLimitDetection(logFilePath = LOG_FILE_PATH): Promise<void> {
	console.log(`Starting rate limit detection on: ${logFilePath}`);

	// Create logs directory if it doesn't exist
	const logDir = path.dirname(RATE_LIMIT_LOG_PATH);
	if (!fs.existsSync(logDir)) {
		fs.mkdirSync(logDir, { recursive: true });
	}

	// Initialize CSV writer for detection results
	const csvWriter = createObjectCsvWriter({
		path: RATE_LIMIT_LOG_PATH,
		header: [
			{ id: 'timestamp', title: 'Timestamp' },
			{ id: 'detectionType', title: 'Detection Type' },
			{ id: 'detected', title: 'Attack Detected' },
			{ id: 'reason', title: 'Detection Reason' },
			{ id: 'request', title: 'Request' },
			{ id: 'response', title: 'Response' },
		],
	});

	try {
		// Read log file
		const logContent = fs.readFileSync(logFilePath, 'utf8');
		const logLines = logContent.split('\n').filter((line) => line.trim() !== '');

		console.log(`Found ${logLines.length} log entries to analyze`);

		// Create rate limiter instance
		const rateLimiter = new RateLimiter();

		// Detection records to write to CSV
		const detectionRecords: any[] = [];

		// Process log entries
		for (const line of logLines) {
			const entry = parseLogLine(line);
			if (!entry) continue;

			// Get the timestamp for accurate rate limiting
			const timestamp = parseTimestamp(line);
			if (!timestamp) continue;

			// Check rate limit
			const result = await rateLimiter.checkRateLimits(entry);

			// Log violations
			if (result.exceeded) {
				const detectionRecord = {
					timestamp: timestamp.toISOString(),
					detectionType: 'RateLimit',
					detected: true,
					reason: result.reason,
					request: JSON.stringify(entry.request),
					response: JSON.stringify(entry.response),
				};

				detectionRecords.push(detectionRecord);
				console.log(`[RATE LIMIT VIOLATION] ${result.reason}`);
			}
		}

		// Write detection records to CSV
		if (detectionRecords.length > 0) {
			await csvWriter.writeRecords(detectionRecords);
			console.log(`Wrote ${detectionRecords.length} rate limit violations to ${RATE_LIMIT_LOG_PATH}`);
		} else {
			console.log('No rate limit violations detected');
		}
	} catch (error) {
		console.error('Error during rate limit detection:', error);
	}
}

/**
 * Apply rate limiting to a log entry (for middleware usage)
 */
export async function applyRateLimiting(entry: LogEntry): Promise<RateLimitResult> {
	const limiter = new RateLimiter();
	const result = await limiter.checkRateLimits(entry);

	if (result.exceeded) {
		console.log(`[RATE LIMIT] ${result.reason}`);

		// Log the rate limit violation
		const logRecord = {
			timestamp: new Date().toISOString(),
			clientId: entry.request['x-api-tran-id'] || 'anonymous',
			ip: entry.request['x-forwarded-for'] || 'unknown-ip',
			endpoint: new URL(entry.request.url).pathname,
			method: entry.request.method,
			reason: result.reason,
			resetAt: new Date(result.resetAt).toISOString(),
		};

		// Log to file
		console.log('[RATE LIMIT VIOLATION]', JSON.stringify(logRecord));
		fs.appendFileSync('rate_limit_violations.log', JSON.stringify(logRecord) + '\n');
	}

	return result;
}

/**
 * Main entry point when run directly
 */
// ES Module way to detect if file is being run directly
const isMainModule = import.meta.url === `file://${process.argv[1]}`;

if (isMainModule) {
	// Get log file path from command line arguments if provided
	const logFile = process.argv[2] || LOG_FILE_PATH;

	runRateLimitDetection(logFile)
		.then(() => console.log('Rate limit detection completed'))
		.catch((error) => console.error('Error:', error));
}
