import { createObjectCsvWriter as createCsvWriter } from 'csv-writer';
import { z } from 'zod';
import {
	filePath,
	LogEntry,
	DetectionResult,
	LogRecord,
	FilePosition,
	readNewLogEntries,
	ensureLogFile,
	detectionCSVLoggerHeader,
} from './utils';

// Specification-based Detection Implementation
class SpecificationBasedDetection {
	private static readonly defaultRequestHeadersSchema = z
		.object({
			url: z.string().url(),
			method: z.enum(['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD']),
			authorization: z.string().optional(),
			'user-agent': z.string(),
			'x-api-tran-id': z.string().regex(/^[A-Z][0-9]{11,12}$/),
			'x-api-type': z.enum(['CA', 'IP', 'MDO']),
			'x-csrf-token': z.string().optional(),
			cookie: z.string().optional(),
			'set-cookie': z.string().optional(),
			'content-length': z
				.string()
				.transform((val) => parseInt(val, 10))
				.pipe(z.number().int().positive()),
			body: z.string(),
		})
		.strict()
		.passthrough();

	private static readonly withTokenRequestHeadersSchema = {
		authorization: z.string().regex(/^Bearer [A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+$/),
	};

	private static readonly defaultResponseHeadersSchema = z
		.object({
			body: z.string(),
		})
		.strict()
		.passthrough();

	private static readonly rateLimiting = {
		maxRequestsPerMinute: 60,
		maxRequestsPerHour: 1000,
		maxPayloadSize: 10 * 1024, // 10KB
	};

	private static readonly apiSchemas: {
		[key: string]: { [method: string]: { request: z.ZodTypeAny; response: z.ZodTypeAny } };
	} = {
		// OAuth 2.0 Token Endpoint
		'/api/oauth/2.0/token': {
			POST: {
				request: z.object({
					headers: SpecificationBasedDetection.defaultRequestHeadersSchema,
					body: z.string().refine(
						(body) => {
							try {
								const params = new URLSearchParams(body);
								return (
									(params.get('grant_type') === 'client_credentials' &&
										params.has('client_id') &&
										params.has('client_secret') &&
										params.has('scope')) ||
									(params.get('grant_type') === 'authorization_code' &&
										params.has('code') &&
										params.has('redirect_uri') &&
										params.has('client_id'))
								);
							} catch (e) {
								return false;
							}
						},
						{ message: 'Invalid OAuth 2.0 token request' }
					),
				}),
				response: z.object({
					headers: SpecificationBasedDetection.defaultResponseHeadersSchema,
					body: z.string().refine(
						(body) => {
							try {
								const data = JSON.parse(body);
								return (
									typeof data.access_token === 'string' &&
									typeof data.token_type === 'string' &&
									typeof data.expires_in === 'number'
								);
							} catch (e) {
								return false;
							}
						},
						{ message: 'Invalid OAuth 2.0 token response' }
					),
				}),
			},
		},
	};

	private readonly requestHistory: Map<string, number[]> = new Map();

	private isRateLimitExceeded(clientId: string): boolean {
		const now = Date.now();
		const oneMinuteAgo = now - 60 * 1000;
		const oneHourAgo = now - 60 * 60 * 1000;

		// Initialize if not exists
		if (!this.requestHistory.has(clientId)) {
			this.requestHistory.set(clientId, [now]);
			return false;
		}

		// Get existing timestamps and add current
		const timestamps = this.requestHistory.get(clientId) || [];
		timestamps.push(now);

		// Clean old timestamps
		const recentTimestamps = timestamps.filter((time) => time >= oneHourAgo);
		this.requestHistory.set(clientId, recentTimestamps);

		// Check rate limits
		const requestsLastMinute = recentTimestamps.filter((time) => time >= oneMinuteAgo).length;
		const requestsLastHour = recentTimestamps.length;

		return (
			requestsLastMinute > SpecificationBasedDetection.rateLimiting.maxRequestsPerMinute ||
			requestsLastHour > SpecificationBasedDetection.rateLimiting.maxRequestsPerHour
		);
	}

	private isPayloadSizeExceeded(entry: LogEntry): { isExceeded: boolean; overloadedFields: string[] } {
		const overloadedFields: string[] = [];

		// Check request body
		if (entry.request.body.length > SpecificationBasedDetection.rateLimiting.maxPayloadSize) {
			overloadedFields.push('request.body');
		}

		// Check headers
		for (const [key, value] of Object.entries(entry.request)) {
			if (typeof value === 'string' && value.length > 1000) {
				overloadedFields.push(`request.${key}`);
			}
		}

		return {
			isExceeded: overloadedFields.length > 0,
			overloadedFields,
		};
	}

	detect(entry: LogEntry): DetectionResult {
		try {
			// Extract request URL
			const url = new URL(entry.request.url);
			const path = url.pathname;
			const method = entry.request.method;

			// 1. Check for payload size limits
			const payloadCheck = this.isPayloadSizeExceeded(entry);
			if (payloadCheck.isExceeded) {
				return {
					detected: true,
					reason: `Payload size exceeded limit in fields: ${payloadCheck.overloadedFields.join(', ')}`,
				};
			}

			// 2. Check for rate limiting
			const clientId = entry.request['x-api-tran-id'] || 'anonymous';
			if (this.isRateLimitExceeded(clientId)) {
				return {
					detected: true,
					reason: `Rate limit exceeded for client ${clientId}`,
				};
			}

			// 3. Find the schema for this endpoint and method
			const endpointSchema = SpecificationBasedDetection.apiSchemas[path]?.[method];
			if (!endpointSchema) {
				return {
					detected: false,
					reason: `No schema defined for ${method} ${path}`,
				};
			}

			// 4. Validate against the schema
			const result = endpointSchema.request.safeParse({
				headers: entry.request,
				body: entry.request.body,
			});

			if (!result.success) {
				const errors = result.error.errors.map((err) => `${err.path.join('.')}: ${err.message}`);
				return {
					detected: true,
					reason: `Schema violation: ${errors.join(', ')}`,
				};
			}

			return {
				detected: false,
				reason: 'Request conforms to specification',
			};
		} catch (error) {
			console.error('Error in specification detection:', error);
			return {
				detected: false,
				reason: `Error during detection: ${error instanceof Error ? error.message : String(error)}`,
			};
		}
	}
}

// Logging Function
async function logDetectionResult(entry: LogEntry, result: DetectionResult): Promise<void> {
	try {
		const csvPath = filePath('/public/specification_detection_logs.csv');

		// Ensure the CSV file exists
		await ensureLogFile(csvPath, 'timestamp,detectionType,detected,reason,request,response\n');

		const csvWriter = createCsvWriter({
			path: csvPath,
			append: true,
			header: detectionCSVLoggerHeader,
		});

		const record: LogRecord = {
			timestamp: new Date().toISOString(),
			detectionType: 'Specification',
			detected: result.detected,
			reason: result.reason,
			request: JSON.stringify(entry.request),
			response: JSON.stringify(entry.response),
		};

		await csvWriter.writeRecords([record]);

		if (result.detected) {
			console.log(`[${record.timestamp}] 🚨 Anomaly detected: ${result.reason}`);
		} else {
			console.log(`[${record.timestamp}] ✅ Request conforms to specification`);
		}
	} catch (error) {
		console.error('Error logging detection result:', error);
	}
}

// Main Detection Function
async function detectIntrusions(entry: LogEntry): Promise<void> {
	try {
		const detector = new SpecificationBasedDetection();
		const result = detector.detect(entry);
		await logDetectionResult(entry, result);
	} catch (error) {
		console.error('Error in intrusion detection:', error);
	}
}

// Start Detection Process
async function startDetection(logFilePath: string): Promise<void> {
	console.log('Starting specification-based detection...');
	console.log(`Monitoring log file: ${logFilePath}`);

	const filePosition = new FilePosition();

	// Create a detection cycle
	const runDetectionCycle = async () => {
		try {
			const entries = await readNewLogEntries(logFilePath, filePosition);

			if (entries.length > 0) {
				console.log(`Processing ${entries.length} new log entries`);

				// Process each entry
				for (const entry of entries) {
					await detectIntrusions(entry);
				}
			}
		} catch (error) {
			console.error('Error in detection cycle:', error);
		}

		// Schedule next cycle after a short delay
		setTimeout(runDetectionCycle, 5000);
	};

	// Start the cycle
	runDetectionCycle();
}

// Main execution - start detection on the requests_responses.txt file
const logFile = filePath('/public/requests_responses.txt');
startDetection(logFile);

// Export for testing/external use
export { SpecificationBasedDetection };
