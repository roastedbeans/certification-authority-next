import { z } from 'zod';
import {
	LogEntry,
	DetectionResult,
	filePath,
	initializeCSV,
	readNewCSVLogEntries,
	FilePosition,
	logDetectionResult,
	RequestData,
	detectionCSVLoggerHeader,
} from '../utils';

// Specification-based Detection Implementation
export class SpecificationBasedDetection {
	private static readonly defaultRequestHeadersSchema = z.object({
		'content-length': z.string().max(10, {
			message: 'Content-Length does NOT match the specification, possible Buffer Overflow Attack or Request Smuggling',
		}),
		'user-agent': z.string().max(50, {
			message: 'User-Agent does NOT match the specification, possible User-Agent Spoofing or Command Injection Attack',
		}),
		cookie: z.string().max(0, {
			message: 'Cookie header does NOT match the specification, possible Session Hijacking or Cookie Poisoning Attack',
		}),
		'set-cookie': z.string().max(0, {
			message:
				'Set-Cookie header does NOT match the specification, possible Cross-Site Cooking or Cookie Injection Attack',
		}),
		'x-csrf-token': z.string().max(0, {
			message: 'X-CSRF-Token header does NOT match the specification, possible Cross-Site Request Forgery Attack',
		}),
		'x-api-tran-id': z
			.string()
			.length(25, {
				message:
					'X-API-Tran-ID does NOT match the specification, possible Transaction ID Tampering or Request Replay Attack',
			})
			.refine((str) => ['M', 'S', 'R', 'C', 'P', 'A'].includes(str.charAt(10)), {
				message:
					'X-API-Tran-ID character does NOT match the specification, possible Transaction Format Manipulation Attack',
			}),
		'x-api-type': z.string().max(0, {
			message: 'X-API-Type header does NOT match the specification, possible API Injection or Request Forgery Attack',
		}),
	});

	private static readonly withTokenRequestHeadersSchema = {
		authorization: z.string().max(1500, {
			message:
				'Authorization header does NOT match the specification, possible Token Manipulation or JWT Tampering Attack',
		}),
		'content-type': z.string().refine((val) => val === 'application/json;charset=UTF-8', {
			message:
				'Content-Type does NOT match the specification, possible Content Type Manipulation, Spoofing, MIME Confusion Attack or Request Smuggling Attack',
		}),
	};

	private static readonly defaultResponseHeadersSchema = z.object({
		'x-api-tran-id': z
			.string()
			.length(25, {
				message:
					'Response X-API-Tran-ID does NOT match the specification, possible Response Tampering or Man-in-the-Middle Attack',
			})
			.refine((str) => ['M', 'S', 'R', 'C', 'P', 'A'].includes(str.charAt(10)), {
				message: 'Response X-API-Tran-ID does NOT match the specification, possible Response Integrity Attack',
			}),
	});

	private static readonly rateLimiting = {
		rateLimiting: {
			maxRequestsPerMinute: 100,
			maxPayloadSize: 1000,
		},
	};

	private static readonly apiSchemas: {
		[key: string]: { [method: string]: { request: z.ZodTypeAny; response: z.ZodTypeAny } };
	} = {
		'/api/v2/mgmts/oauth/2.0/token': {
			POST: {
				request: z.object({
					headers: SpecificationBasedDetection.defaultRequestHeadersSchema.extend({
						'content-type': z.string().refine((val) => val === 'application/x-www-form-urlencoded', {
							message:
								'Content-Type does NOT match the specification, possible OAuth Parameter Injection or Content Type Confusion Attack',
						}),
					}),
					body: z.object({
						grant_type: z.string().refine((val) => val === 'client_credentials', {
							message:
								'grant_type does NOT match the specification, possible Grant Type Confusion or OAuth Bypass Attack',
						}),
						client_id: z.string().length(50, {
							message:
								'client_id does NOT match the specification, possible Client Impersonation Attack, ID Injection or Enumeration Attack',
						}),
						client_secret: z.string().length(50, {
							message:
								'client_secret does NOT match the specification, possible Credential Stuffing, Brute Force Attack or possible Secret Injection Attack',
						}),
						scope: z.string().refine((val) => val === 'manage', {
							message: 'scope does NOT match the specification, possible Permission Escalation Attack',
						}),
					}),
				}),
				response: z.object({
					headers: SpecificationBasedDetection.defaultResponseHeadersSchema,
					body: z.object({
						token_type: z.string().refine((val) => val === 'Bearer', {
							message:
								'token_type does NOT match the specification, possible Token Type Manipulation or Confusion Attack',
						}),
						access_token: z.string().max(1500, {
							message:
								'access_token does NOT match the specification, possible Token Injection or JWT Tampering Attack',
						}),
						expires_in: z.number().max(999999999, {
							message: 'expires_in does NOT match the specification, possible Token Expiration Manipulation Attack',
						}),
						scope: z.string().refine((val) => val === 'manage', {
							message: 'scope does NOT match the specification, possible Scope Escalation or Scope Tampering Attack',
						}),
						timestamp: z.string().length(14, {
							message: 'timestamp does NOT match the specification, possible Timestamp Tampering or Injection Attack',
						}),
						rsp_code: z.string().max(30, {
							message: 'rsp_code does NOT match the specification, possible Response Code Manipulation Attack',
						}),
						rsp_msg: z.string().max(450, {
							message: 'rsp_msg does NOT match the specification, possible Response Message Manipulation Attack',
						}),
					}),
				}),
			},
		},
		'/api/v2/mgmts/orgs': {
			GET: {
				request: z.object({
					headers: SpecificationBasedDetection.defaultRequestHeadersSchema
						.extend({
							// find the search param search_timestamp
							url: z.string().refine(
								(val) => {
									try {
										const searchTimestamp = new URL(val).searchParams.get('search_timestamp');
										const timestamp =
											searchTimestamp !== null && (searchTimestamp.length === 0 || searchTimestamp.length === 14);
										if (timestamp) {
											return true;
										} else {
											return false;
										}
									} catch {
										return false;
									}
								},
								{
									message:
										'parameter in URL does NOT match the specification, possible Parameter Tampering or Injection Attack',
								}
							),
						})
						.extend(SpecificationBasedDetection.withTokenRequestHeadersSchema),
				}),
				response: z.object({
					headers: SpecificationBasedDetection.defaultResponseHeadersSchema,
					body: z.object({
						rsp_code: z.string().max(30, {
							message: 'rsp_code does NOT match the specification, possible Response Code Manipulation Attack',
						}),
						rsp_msg: z.string().max(100, {
							message:
								'rsp_msg does NOT match the specification, possible Response Injection or Information Disclosure Attack',
						}),
						search_timestamp: z.string().max(14, {
							message: 'search_timestamp does NOT match the specification, possible Timestamp Manipulation Attack',
						}),
						org_cnt: z.number().max(999, {
							message: 'org_cnt does NOT match the specification, possible Resource Enumeration or DoS Attack',
						}),
						org_list: z.array(z.object({}), {
							message: 'org_list does NOT match the specification, possible Data Structure Manipulation Attack',
						}),
					}),
				}),
			},
		},
		'/api/oauth/2.0/token': {
			POST: {
				request: z.object({
					headers: SpecificationBasedDetection.defaultRequestHeadersSchema.extend({
						'content-type': z.string().refine((val) => val === 'application/x-www-form-urlencoded', {
							message: 'Content-Type must be application/x-www-form-urlencoded for OAuth token request',
						}),
					}),
					body: z.object({
						grant_type: z.string().refine((val) => val === 'client_credentials', {
							message:
								'grant_type does NOT match the specification, possible OAuth Injection, Flow Tampering or Grant Type Manipulation Attack',
						}),
						client_id: z.string().length(50, {
							message:
								'client_id does NOT match the specification, possible Client Impersonation Attack, ID Injection or Enumeration Attack',
						}),
						client_secret: z.string().length(50, {
							message:
								'client_secret does NOT match the specification, possible Credential Stuffing, Brute Force Attack or possible Secret Injection Attack',
						}),
						scope: z.string().refine((val) => val === 'ca', {
							message: 'scope does NOT match the specification, possible Permission Escalation Attack',
						}),
					}),
				}),
				response: z.object({
					headers: SpecificationBasedDetection.defaultResponseHeadersSchema,
					body: z.object({
						token_type: z.string().refine((val) => val === 'Bearer', {
							message:
								'token_type does NOT match the specification, possible Token Type Manipulation or Confusion Attack',
						}),
						access_token: z.string().max(1500, {
							message:
								'access_token does NOT match the specification, possible Token Injection or JWT Signature Tampering Attack',
						}),
						expires_in: z.number().max(999999999, {
							message: 'expires_in does NOT match the specification, possible Token Lifetime Manipulation Attack',
						}),
						scope: z.string().refine((val) => val === 'ca', {
							message: 'scope does NOT match the specification, possible Permission Escalation Attack',
						}),
					}),
				}),
			},
		},

		'/api/ca/sign_request': {
			POST: {
				request: z.object({
					headers: SpecificationBasedDetection.defaultRequestHeadersSchema.extend(
						SpecificationBasedDetection.withTokenRequestHeadersSchema
					),
					body: z.object({
						sign_tx_id: z.string().length(49, {
							message: 'sign_tx_id does NOT match the specification, possible Signature Transaction Forgery Attack',
						}),
						user_ci: z
							.string()
							.max(100, {
								message: 'user_ci does NOT match the specification, possible Identity Spoofing Attack',
							})
							.base64({
								message:
									'user_ci does NOT match the specification, possible Base64 Encoding Attack or Injection Attack',
							}),
						real_name: z.string().max(30, {
							message: 'real_name does NOT match the specification, possible Identity Spoofing or Homograph Attack',
						}),
						phone_num: z
							.string()
							.max(15, {
								message: 'phone_num does NOT match the specification, possible Phone Number Spoofing Attack',
							})
							.startsWith('+82', {
								message: 'phone_num does NOT match the specification, possible Country Code Manipulation Attack',
							}),
						request_title: z.string().max(100, {
							message: 'request_title does NOT match the specification, possible Data Injection or XSS Attack',
						}),
						device_code: z.enum(['PC', 'TB', 'MO'], {
							message: 'device_code does NOT match the specification, possible Device Spoofing Attack',
						}),
						device_browser: z.enum(['WB', 'NA', 'HY'], {
							message:
								'device_browser does NOT match the specification, possible Browser Fingerprinting Evasion Attack',
						}),
						return_app_scheme_url: z
							.string()
							.max(100, {
								message:
									'return_app_scheme_url does NOT match the specification, possible Open Redirect or URL Scheme Injection Attack',
							})
							.optional(),
						consent_type: z.string().length(1, {
							message: 'consent_type does NOT match the specification, possible Consent Manipulation Attack',
						}),
						consent_cnt: z.number().max(9999, {
							message: 'consent_cnt does NOT match the specification, possible Consent Enumeration or DoS Attack',
						}),
						consent_list: z.array(
							z.object({
								consent_len: z.number().max(999, {
									message: 'consent_len does NOT match the specification, possible Content Length Manipulation Attack',
								}),
								consent_title: z.string().max(100, {
									message: 'consent_title does NOT match the specification, possible Content Injection or XSS Attack',
								}),
								consent: z.string().max(500, {
									message:
										'consent does NOT match the specification, possible Consent Forgery or Content Injection Attack',
								}),
								tx_id: z.string().length(74, {
									message: 'tx_id does NOT match the specification, possible Transaction ID Forgery Attack',
								}),
							}),
							{
								message: 'consent_list does NOT match the specification, possible Array Structure Manipulation Attack',
							}
						),
					}),
				}),
				response: z.object({
					headers: SpecificationBasedDetection.defaultResponseHeadersSchema,
					body: z.object({
						rsp_code: z.string().max(30, {
							message: 'rsp_code does NOT match the specification, possible Response Code Manipulation Attack',
						}),
						rsp_msg: z.string().max(450, {
							message: 'rsp_msg does NOT match the specification, possible Response Injection or XSS Attack',
						}),
						cert_tx_id: z.string().length(40, {
							message:
								'cert_tx_id does NOT match the specification, possible Certificate Transaction ID Forgery Attack',
						}),
					}),
				}),
			},
		},

		'/api/ca/sign_result': {
			POST: {
				request: z.object({
					headers: SpecificationBasedDetection.defaultRequestHeadersSchema.extend(
						SpecificationBasedDetection.withTokenRequestHeadersSchema
					),
					body: z.object({
						cert_tx_id: z.string().length(40, {
							message:
								'cert_tx_id does NOT match the specification, possible Certificate Transaction ID Forgery Attack',
						}),
						sign_tx_id: z.string().length(49, {
							message: 'sign_tx_id does NOT match the specification, possible Signature Transaction ID Forgery Attack',
						}),
					}),
				}),
				response: z.object({
					headers: SpecificationBasedDetection.defaultResponseHeadersSchema,
					body: z.object({
						rsp_code: z.string().max(30, {
							message: 'rsp_code does NOT match the specification, possible Response Code Manipulation Attack',
						}),
						rsp_msg: z.string().max(450, {
							message: 'rsp_msg does NOT match the specification, possible Response Injection or XSS Attack',
						}),
						signed_consent_cnt: z.number().max(9999, {
							message:
								'signed_consent_cnt does NOT match the specification, possible Consent Enumeration or DoS Attack',
						}),
						signed_consent_list: z.array(
							z.object({
								signed_consent_len: z.number().max(999, {
									message:
										'signed_consent_len does NOT match the specification, possible Content Length Manipulation Attack',
								}),
								signed_consent: z
									.string()
									.max(10000, {
										message:
											'signed_consent does NOT match the specification, possible Content Injection or XSS Attack',
									})
									.base64url({ message: 'signed_consent must be valid base64url encoded string' }),
								tx_id: z.string().length(74, {
									message: 'tx_id does NOT match the specification, possible Transaction ID Forgery Attack',
								}),
							}),
							{ message: 'signed_consent_list must be an array of valid signed consent objects' }
						),
					}),
				}),
			},
		},
		'/api/ca/sign_verification': {
			POST: {
				request: z.object({
					headers: SpecificationBasedDetection.defaultRequestHeadersSchema.extend(
						SpecificationBasedDetection.withTokenRequestHeadersSchema
					),
					body: z.object({
						tx_id: z.string().length(74, {
							message: 'tx_id does NOT match the specification, possible Transaction ID Forgery Attack',
						}),
						cert_tx_id: z.string().length(40, {
							message:
								'cert_tx_id does NOT match the specification, possible Certificate Transaction ID Forgery Attack',
						}),
						signed_consent_len: z.number().max(999, {
							message:
								'signed_consent_len does NOT match the specification, possible Content Length Manipulation Attack',
						}),
						signed_consent: z
							.string()
							.max(10000, {
								message: 'signed_consent does NOT match the specification, possible Content Injection or XSS Attack',
							})
							.base64url({ message: 'signed_consent must be valid base64url encoded string' }),
						consent_type: z.string().length(1, {
							message: 'consent_type does NOT match the specification, possible Consent Manipulation Attack',
						}),
						consent_len: z.number().max(999, {
							message: 'consent_len does NOT match the specification, possible Content Length Manipulation Attack',
						}),
						consent: z.string().max(500, {
							message: 'consent does NOT match the specification, possible Consent Forgery or Content Injection Attack',
						}),
					}),
				}),
				response: z.object({
					headers: SpecificationBasedDetection.defaultResponseHeadersSchema,
					body: z.object({
						tx_id: z.string().length(74, {
							message: 'tx_id does NOT match the specification, possible Transaction ID Forgery Attack',
						}),
						rsp_code: z.string().max(30, {
							message: 'rsp_code does NOT match the specification, possible Response Code Manipulation Attack',
						}),
						rsp_msg: z.string().max(450, {
							message: 'rsp_msg does NOT match the specification, possible Response Injection or XSS Attack',
						}),
						user_ci: z.string().max(100, {
							message: 'user_ci does NOT match the specification, possible Identity Spoofing Attack',
						}),
						result: z.boolean(),
					}),
				}),
			},
		},
	};

	private readonly requestHistory: Map<string, number[]> = new Map();

	private isRateLimitExceeded(clientId: string): boolean {
		const now = Date.now();
		const windowSize = 60000;
		let requests = this.requestHistory.get(clientId) || [];
		requests = requests.filter((timestamp) => now - timestamp < windowSize);
		requests.push(now);
		this.requestHistory.set(clientId, requests);
		return requests.length > SpecificationBasedDetection.rateLimiting.rateLimiting.maxRequestsPerMinute;
	}

	private isPayloadSizeExceeded(entry: LogEntry): { isExceeded: boolean; overloadedFields: string[] } {
		const maxSize = SpecificationBasedDetection.rateLimiting.rateLimiting.maxPayloadSize;
		const overloadedFields: string[] = [];

		if (entry.request) {
			// Check all fields individually
			const fieldsToCheck = {
				url: entry.request.url,
				method: entry.request.method,
				authorization: entry.request.authorization,
				'user-agent': entry.request['user-agent'],
				'x-api-tran-id': entry.request['x-api-tran-id'],
				'x-api-type': entry.request['x-api-type'],
				'x-csrf-token': entry.request['x-csrf-token'],
				cookie: entry.request.cookie,
				'set-cookie': entry.request['set-cookie'],
				'content-length': entry.request['content-length'],
				body: entry.request.body,
			};

			for (const [key, value] of Object.entries(fieldsToCheck)) {
				if (value) {
					let size: number;
					if (typeof value === 'string') {
						size = Buffer.from(value).length;
					} else {
						size = Buffer.from(JSON.stringify(value)).length;
					}

					if (size > maxSize) {
						console.log(`Overloaded field: ${key}, size: ${size}`);
						overloadedFields.push(key);
						entry.request[key as keyof RequestData] = 'overload here';
					}
				}
			}

			// Handle additional fields from index signature
			const standardKeys = Object.keys(fieldsToCheck);
			Object.entries(entry.request).forEach(([key, value]) => {
				if (!standardKeys.includes(key) && value) {
					let size: number;
					if (typeof value === 'string') {
						size = Buffer.from(value).length;
					} else {
						size = Buffer.from(JSON.stringify(value)).length;
					}

					if (size > maxSize) {
						console.log(`Overloaded field: ${key}, size: ${size}`);
						overloadedFields.push(key);
						entry.request[key] = 'overload here';
					}
				}
			});
		}

		return {
			isExceeded: overloadedFields.length > 0,
			overloadedFields,
		};
	}

	detect(entry: LogEntry): DetectionResult {
		// Check rate limiting
		const clientId = entry.request['x-api-tran-id'];
		if (clientId && this.isRateLimitExceeded(clientId)) {
			return {
				detected: true,
				reason: 'Rate limit exceeded',
			};
		}

		// Check payload size
		const payloadCheck = this.isPayloadSizeExceeded(entry);
		if (payloadCheck.isExceeded) {
			return {
				detected: true,
				reason: `Payload size exceeded in fields: ${payloadCheck.overloadedFields.join(', ')}`,
			};
		}

		try {
			// Validate URL format first
			if (!entry.request.url || !entry.request.url.trim()) {
				return {
					detected: true,
					reason: 'Missing URL in request',
				};
			}

			// Check if URL is valid
			let url;
			try {
				url = new URL(entry.request.url);
			} catch (error) {
				return {
					detected: true,
					reason: `Invalid URL format: ${entry.request.url}`,
				};
			}

			const pathname = url.pathname;
			const method = entry.request.method;
			const spec = SpecificationBasedDetection.apiSchemas[pathname]?.[method];

			// Path validation
			if (!spec) {
				return {
					detected: true,
					reason: `Unknown endpoint or method: ${pathname} ${method}`,
				};
			}

			try {
				spec.request.parse({
					headers: entry.request,
					body: entry.request.body,
				});
			} catch (error) {
				if (error instanceof z.ZodError) {
					return {
						detected: true,
						reason: `Request specification violation: ${error.errors[0].message}`,
					};
				}
				throw error;
			}

			try {
				spec.response.parse({
					headers: entry.request,
					body: entry.response.body,
				});
			} catch (error) {
				if (error instanceof z.ZodError) {
					return {
						detected: true,
						reason: `Response specification violation: ${error.errors[0].message}`,
					};
				}
				throw error;
			}

			return {
				detected: false,
				reason: 'Request/Response conform to specifications',
			};
		} catch (error) {
			console.error('Error during detection:', error);
			return {
				detected: true,
				reason: `Unexpected error: ${(error as Error).message}`,
			};
		}
	}
}

// Main Detection Function
async function detectIntrusions(entry: LogEntry): Promise<void> {
	try {
		// Start timing for overall request processing
		const requestStartTime = performance.now();

		console.log('--------------------------------------------------');
		console.log(`Processing request to: ${entry.request.url}`);

		const specificationDetector = new SpecificationBasedDetection();
		const specificationResult = specificationDetector.detect(entry);

		const requestEndTime = performance.now();
		const totalRequestDuration = requestEndTime - requestStartTime;

		if (specificationResult.detected) {
			await logDetectionResult(entry, 'specification', specificationResult);
			console.log('⚠️ INTRUSION DETECTED ⚠️');
			console.log(`Reason: ${specificationResult.reason}`);
			console.log(`URL: ${entry.request.url}`);
			console.log(`Method: ${entry.request.method}`);
		} else {
			await logDetectionResult(entry, 'specification', specificationResult);
			console.log('✅ Request conforms to specifications');
		}

		console.log(`########## Specification Detection Processing Time: ${totalRequestDuration.toFixed(10)}ms ##########`);
		console.log('--------------------------------------------------');
	} catch (error) {
		console.error('Error in detectIntrusions:', error);
		const errorResult: DetectionResult = {
			detected: true,
			reason: `Error processing entry: ${(error as Error).message}`,
		};
		await logDetectionResult(entry, 'specification', errorResult);
	}
}

// Main Function to Start Detection
export async function startSpecificationDetection(logFilePath: string) {
	try {
		await initializeCSV(filePath('/public/specification_detection_logs.csv'), 'detection');
		const filePosition = new FilePosition();

		// First, read the entire file initially to catch up
		console.log('Initial reading of the log file...');
		const initialEntries = await readNewCSVLogEntries(logFilePath, filePosition);

		if (initialEntries.length > 0) {
			console.log(`Processing ${initialEntries.length} existing entries from CSV...`);

			// Process a batch of entries at a time to avoid overwhelming the system
			const batchSize = 10;
			for (let i = 0; i < initialEntries.length; i += batchSize) {
				const batch = initialEntries.slice(i, i + batchSize);
				console.log(`Processing batch ${i / batchSize + 1}/${Math.ceil(initialEntries.length / batchSize)}`);

				for (const entry of batch) {
					await detectIntrusions(entry);
				}
			}
		} else {
			console.log('No existing entries found in the log file.');
		}

		return 'done';
	} catch (error) {
		console.error('Error starting detection:', error);
		return 'error';
	}
}
