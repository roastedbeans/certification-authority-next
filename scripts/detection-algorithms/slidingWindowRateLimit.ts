import * as fs from 'fs';
import * as path from 'path';
import {
	LogEntry,
	DetectionResult,
	filePath,
	initializeCSV,
	readNewCSVLogEntries,
	FilePosition,
	logDetectionResult,
} from '../utils';

/**
 * Enhanced Rate Limiting Implementation Using Sliding Window Strategy
 *
 * This implementation integrates with the detection framework to analyze logs
 * and detect rate limit violations using the sliding window approach.
 */

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

	// Using a more flexible approach for client limits
	clientRateLimits: {
		// This will be used as a fallback for known clients
		'default-premium-client': {
			requestsPerMinute: 30, // Example limit for premium clients
		},
	},

	endpointRateLimits: {
		// Authentication endpoints - stricter limits to prevent abuse
		'/api/v2/mgmts/oauth/2.0/token': {
			requestsPerMinute: 10,
		},
		'/api/oauth/2.0/token': {
			requestsPerMinute: 10,
		},
		// Certificate management endpoints
		'/api/ca/sign_request': {
			requestsPerMinute: 20,
		},
		'/api/ca/sign_result': {
			requestsPerMinute: 20,
		},
		'/api/ca/sign_verification': {
			requestsPerMinute: 30,
		},
		// Organization management endpoints
		'/api/v2/mgmts/orgs': {
			requestsPerMinute: 30,
		},
	},

	defaultRequestsPerMinute: 20,
};

// Client categories with their rate limits
const clientCategories = {
	premium: 30, // Premium clients get higher limits
	standard: 20, // Standard clients get default limits
	restricted: 10, // Restricted clients get lower limits
};

// Function to determine client rate limit
function getClientRateLimit(clientId: string): number {
	// 1. Check if client has a specific limit in the config
	if (defaultConfig.clientRateLimits[clientId]) {
		return defaultConfig.clientRateLimits[clientId].requestsPerMinute;
	}

	// 2. Check client category based on prefix or pattern
	if (clientId.startsWith('premium-') || clientId.includes('-prem-')) {
		return clientCategories.premium;
	}

	if (clientId.startsWith('restricted-') || clientId.includes('-rest-')) {
		return clientCategories.restricted;
	}

	// 3. Default to standard rate
	return clientCategories.standard;
}

/**
 * Sliding Window Rate Limiter
 * This class implements the sliding window algorithm for rate limiting
 */
export class SlidingWindowRateLimiter {
	public readonly config: RateLimitConfig;
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
			return {
				exceeded: true,
				reason: `Client ${clientId} exceeded rate limit of ${this.getClientLimit(clientId)} requests per minute`,
				remaining: clientCheck.remaining,
				resetAt: clientCheck.resetAt,
			};
		}

		// Check endpoint-specific rate limit
		const endpointCheck = this.checkSlidingWindowLimit(
			`endpoint:${endpoint}:${clientId}`,
			this.getEndpointLimit(endpoint),
			timestamp
		);

		if (endpointCheck.exceeded) {
			return {
				exceeded: true,
				reason: `Client ${clientId} exceeded rate limit of ${this.getEndpointLimit(
					endpoint
				)} requests per minute for endpoint ${endpoint}`,
				remaining: endpointCheck.remaining,
				resetAt: endpointCheck.resetAt,
			};
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
	public extractClientId(entry: LogEntry): string {
		// Try to extract from x-api-tran-id first
		if (entry.request && entry.request['x-api-tran-id']) {
			const transactionId = entry.request['x-api-tran-id'] || '';
			return transactionId.substring(0, 10);
		}

		// Try to extract from various other common fields
		if (entry.request) {
			if (entry.request['x-api-key']) return String(entry.request['x-api-key']);
			if (entry.request['clientId']) return String(entry.request['clientId']);
			if (entry.request['client_id']) return String(entry.request['client_id']);
		}

		// Fallback to IP address or generate random ID
		if (entry.request && entry.request['ip']) {
			return String(entry.request['ip']);
		}

		// Generate a random ID as last resort
		return `unknown-${Math.random().toString(36).substring(2, 10)}`;
	}

	/**
	 * Extract the endpoint from the log entry URL
	 */
	public extractEndpoint(entry: LogEntry): string {
		if (!entry.request || !entry.request.url) {
			return 'unknown-endpoint';
		}

		try {
			const url = new URL(entry.request.url);
			return url.pathname;
		} catch (e) {
			// If URL parsing fails, extract path part from the URL string
			const urlPath = entry.request.url.split('?')[0];
			return urlPath || 'unknown-endpoint';
		}
	}

	/**
	 * Extract the timestamp from the log entry
	 */
	public extractTimestamp(entry: LogEntry): number {
		// If timestamp is provided in the entry, use it
		if (entry.timestamp) {
			return new Date(entry.timestamp).getTime();
		}

		// Otherwise fall back to current time
		return Date.now();
	}

	/**
	 * Get the rate limit for a specific client
	 */
	private getClientLimit(clientId: string): number {
		// Use the dynamic client rate limit function
		return getClientRateLimit(clientId);
	}

	/**
	 * Get the rate limit for a specific endpoint
	 */
	private getEndpointLimit(endpoint: string): number {
		const endpointConfig = this.config.endpointRateLimits[endpoint];
		return endpointConfig ? endpointConfig.requestsPerMinute : this.config.defaultRequestsPerMinute;
	}
}

// Add new interfaces for timeframe analysis
export interface TimeframeAnalysis {
	startTime: Date;
	endTime: Date;
	isAnomaly: boolean;
	reason: string;
	requestCount: number;
	clientId: string;
	endpoint?: string;
}

/**
 * Analyzes a timeframe for rate limit anomalies
 * @param timeframe The timeframe to analyze
 * @param requestStore Map containing sliding window data for rate limit analysis
 * @returns DetectionResult indicating if an anomaly was detected
 */
function analyzeTimeframeAnomaly(timeframe: TimeframeAnalysis, requestStore: Map<string, number[]>): DetectionResult {
	// Calculate requests per minute for this timeframe
	const timeframeDurationMinutes = 5; // 5-minute timeframe
	const requestsPerMinute = timeframe.requestCount / timeframeDurationMinutes;

	// Get rate limits for this client and endpoint
	const clientLimit = getClientRateLimit(timeframe.clientId);
	let endpointLimit = defaultConfig.defaultRequestsPerMinute;

	if (timeframe.endpoint && defaultConfig.endpointRateLimits[timeframe.endpoint]) {
		endpointLimit = defaultConfig.endpointRateLimits[timeframe.endpoint].requestsPerMinute;
	}

	// Determine the applicable limit (most restrictive applies)
	const applicableLimit = Math.min(clientLimit, endpointLimit);

	// Check for anomalies
	if (requestsPerMinute > applicableLimit * 0.8) {
		return {
			detected: true,
			reason: `High sustained traffic: ${requestsPerMinute.toFixed(1)} req/min (limit: ${applicableLimit} req/min)`,
		};
	}

	// Look for minute-by-minute spikes using the sliding window data
	const clientKey = `client:${timeframe.clientId}`;
	const endpointKey = `endpoint:${timeframe.endpoint}:${timeframe.clientId}`;

	// Check if we have sliding window data for this client/endpoint
	if (requestStore.has(clientKey)) {
		const minuteCount = requestStore.get(clientKey)!.length;
		if (minuteCount > clientLimit) {
			return {
				detected: true,
				reason: `Client rate limit exceeded: ${minuteCount} requests in last minute (limit: ${clientLimit})`,
			};
		}
	}

	if (requestStore.has(endpointKey)) {
		const minuteCount = requestStore.get(endpointKey)!.length;
		if (minuteCount > endpointLimit) {
			return {
				detected: true,
				reason: `Endpoint rate limit exceeded: ${minuteCount} requests in last minute to ${timeframe.endpoint} (limit: ${endpointLimit})`,
			};
		}
	}

	// No anomalies detected
	return {
		detected: false,
		reason: 'Normal traffic pattern',
	};
}

/**
 * Integration with detection system - can be called from security-actions.ts
 * This is the main entry point for rate limit detection
 * Returns "done" on success or an error message on failure
 */
export async function startRateLimitDetection(
	logFilePath = filePath('/public/ca_formatted_logs.csv')
): Promise<string> {
	const DETECTION_LOG_PATH = filePath('/public/rate_limit_intrusions.csv');

	try {
		// Initialize detection log CSV if it doesn't exist
		await initializeCSV(DETECTION_LOG_PATH, 'ratelimit');

		const filePosition = new FilePosition();

		// First, read the entire file initially to catch up
		console.log('Initial reading of the log file...');
		const initialEntries = await readNewCSVLogEntries(logFilePath, filePosition);

		if (initialEntries.length > 0) {
			console.log(`Processing ${initialEntries.length} existing entries from CSV...`);

			// Create rate limiter instance with default configuration
			const rateLimiter = new SlidingWindowRateLimiter();

			// Track client request counts by minute for sliding window analysis
			const requestStore = new Map<string, number[]>();

			// Track timeframes for analysis
			const timeframes = new Map<string, TimeframeAnalysis>();
			const timeframeWindow = 300000; // 5 minutes in milliseconds

			// Process a batch of entries at a time
			const batchSize = 50;
			for (let i = 0; i < initialEntries.length; i += batchSize) {
				const batch = initialEntries.slice(i, i + batchSize);
				console.log(
					`Processing batch ${Math.floor(i / batchSize) + 1}/${Math.ceil(initialEntries.length / batchSize)}`
				);

				for (const entry of batch) {
					// Extract client and endpoint info
					const clientId = rateLimiter.extractClientId(entry);
					const endpoint = rateLimiter.extractEndpoint(entry);
					const timestamp = rateLimiter.extractTimestamp(entry);

					// Create sanitized IDs for timeframe key
					const sanitizedClientId = clientId.startsWith('unknown-') ? 'unknown-client' : clientId;
					const timeframeEndpoint = endpoint === 'unknown-endpoint' ? 'unknown-endpoint' : endpoint;
					const timeframeTime = Math.floor(timestamp / timeframeWindow) * timeframeWindow;
					const timeframeKey = `${sanitizedClientId}:${timeframeEndpoint}:${timeframeTime}`;

					// Track client requests for this timeframe
					if (!timeframes.has(timeframeKey)) {
						// Initialize a new timeframe
						timeframes.set(timeframeKey, {
							startTime: new Date(timeframeTime),
							endTime: new Date(timeframeTime + timeframeWindow),
							isAnomaly: false,
							reason: 'Normal traffic pattern',
							requestCount: 1,
							clientId: sanitizedClientId,
							endpoint: timeframeEndpoint,
						});
					} else {
						// Update existing timeframe
						const timeframe = timeframes.get(timeframeKey)!;
						timeframe.requestCount++;

						// Update the map
						timeframes.set(timeframeKey, timeframe);
					}

					// Update sliding window data structure for rate limit analysis
					// Maintain separate tracking for minute-by-minute analysis (sliding window)
					// We'll use this to determine the actual rate limits
					const clientKey = `client:${clientId}`;
					const endpointKey = `endpoint:${endpoint}:${clientId}`;
					const minuteWindow = 60000; // 1 minute window

					// Initialize client tracking if needed
					if (!requestStore.has(clientKey)) {
						requestStore.set(clientKey, []);
					}

					// Initialize endpoint tracking if needed
					if (!requestStore.has(endpointKey)) {
						requestStore.set(endpointKey, []);
					}

					// Get existing timestamps
					const clientTimestamps = requestStore.get(clientKey)!;
					const endpointTimestamps = requestStore.get(endpointKey)!;

					// Add current timestamp
					clientTimestamps.push(timestamp);
					endpointTimestamps.push(timestamp);

					// Filter out old timestamps (older than 1 minute)
					const validClientTimestamps = clientTimestamps.filter((ts) => timestamp - ts <= minuteWindow);
					const validEndpointTimestamps = endpointTimestamps.filter((ts) => timestamp - ts <= minuteWindow);

					// Update the request store
					requestStore.set(clientKey, validClientTimestamps);
					requestStore.set(endpointKey, validEndpointTimestamps);
				}
			}

			// Analyze timeframes for anomalies and log intrusions
			console.log(`Analyzing ${timeframes.size} timeframes for rate limit anomalies...`);
			let anomalyCount = 0;

			// Process each timeframe
			for (const [key, timeframe] of timeframes.entries()) {
				// Calculate requests per minute for this timeframe
				const timeframeDurationMinutes = timeframeWindow / 60000; // Convert ms to minutes
				const requestsPerMinute = timeframe.requestCount / timeframeDurationMinutes;

				// Get rate limits for this client and endpoint
				const clientLimit = getClientRateLimit(timeframe.clientId);
				let endpointLimit = rateLimiter.config.defaultRequestsPerMinute;

				if (timeframe.endpoint && rateLimiter.config.endpointRateLimits[timeframe.endpoint]) {
					endpointLimit = rateLimiter.config.endpointRateLimits[timeframe.endpoint].requestsPerMinute;
				}

				// Determine the applicable limit (most restrictive applies)
				const applicableLimit = Math.min(clientLimit, endpointLimit);

				// Determine if this is an anomaly
				let isAnomaly = false;
				let reason = 'Normal traffic pattern';

				// First check: Sustained traffic exceeding 80% of the limit is suspicious
				if (requestsPerMinute > applicableLimit * 0.8) {
					isAnomaly = true;
					reason = `High sustained traffic: ${requestsPerMinute.toFixed(
						1
					)} req/min (limit: ${applicableLimit} req/min)`;
				}

				// Second check: Look for minute-by-minute spikes using the sliding window data
				const clientKey = `client:${timeframe.clientId}`;
				const endpointKey = `endpoint:${timeframe.endpoint}:${timeframe.clientId}`;

				// Check if we have sliding window data for this client/endpoint
				if (requestStore.has(clientKey)) {
					const minuteCount = requestStore.get(clientKey)!.length;
					if (minuteCount > clientLimit) {
						isAnomaly = true;
						reason = `Client rate limit exceeded: ${minuteCount} requests in last minute (limit: ${clientLimit})`;
					}
				}

				if (requestStore.has(endpointKey)) {
					const minuteCount = requestStore.get(endpointKey)!.length;
					if (minuteCount > endpointLimit) {
						isAnomaly = true;
						reason = `Endpoint rate limit exceeded: ${minuteCount} requests in last minute to ${timeframe.endpoint} (limit: ${endpointLimit})`;
					}
				}

				// Update the timeframe status
				timeframe.isAnomaly = isAnomaly;
				timeframe.reason = reason;

				// Log intrusions to the detection log
				if (isAnomaly) {
					anomalyCount++;

					const entry: LogEntry = {
						timestamp: timeframe.startTime.toISOString(),
						request: {
							url: timeframe.endpoint || 'unknown-endpoint',
							method: 'GET',
							authorization: '',
							'user-agent': 'rate-limit-detector',
							'x-api-tran-id': `${timeframe.clientId}-${Date.now()}`,
							'x-api-type': 'system',
							'x-csrf-token': '',
							cookie: '',
							'set-cookie': '',
							'content-length': '0',
							body: '',
						},
						response: {
							status: '429',
							'x-api-tran-id': `${timeframe.clientId}-${Date.now()}`,
							'content-type': 'application/json',
							body: JSON.stringify({
								error: 'Too Many Requests',
							}),
						},
					};
					// Create a synthetic log entry for the timeframe
					const detectionResult: DetectionResult = {
						detected: true,
						reason: reason,
					};

					await logDetectionResult(entry, 'ratelimit', detectionResult);

					// Also append to our main detection log in a more readable format
					const logLine = `${timeframe.startTime.toISOString()},ratelimit,true,${reason.replace(/,/g, ';')},${
						timeframe.clientId
					},${timeframe.endpoint || ''},${
						timeframe.requestCount
					},${timeframe.startTime.toISOString()},${timeframe.endTime.toISOString()}\n`;

					fs.appendFileSync(DETECTION_LOG_PATH, logLine);

					console.log(`⚠️ RATE LIMIT ANOMALY DETECTED ⚠️`);
					console.log(`Timeframe: ${timeframe.startTime.toISOString()} to ${timeframe.endTime.toISOString()}`);
					console.log(`Client: ${timeframe.clientId}, Endpoint: ${timeframe.endpoint}`);
					console.log(`Reason: ${reason}`);
					console.log(`Request count: ${timeframe.requestCount} (${requestsPerMinute.toFixed(1)} req/min)`);
					console.log(`Applicable limit: ${applicableLimit} req/min`);
					console.log('-----------------------------------------------------');
				}
			}

			console.log(
				`Rate limit analysis completed. Found ${anomalyCount} anomalies out of ${timeframes.size} timeframes.`
			);
			console.log(`Results written to: ${DETECTION_LOG_PATH}`);
		} else {
			console.log('No existing entries found in the log file.');
		}

		return 'done';
	} catch (error) {
		console.error('Error in rate limit detection:', error);
		return String(error);
	}
}
