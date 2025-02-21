import { createObjectCsvWriter as createCsvWriter } from 'csv-writer';
import fs from 'fs';
import { z } from 'zod';
import path from 'path';

const filePath = (pathString: string) => {
	return path.join(process.cwd(), pathString);
};

// Types and Interfaces
interface RequestData {
	url: string;
	method: string;
	authorization: string;
	'user-agent': string;
	'x-api-tran-id': string;
	'x-api-type': string;
	'x-csrf-token': string;
	cookie: string;
	'set-cookie': string;
	'content-length': string;
	body: string;
	[key: string]: string; // Add index signature for string keys
}

interface ResponseData {
	body: string;
}

interface LogEntry {
	request: RequestData;
	response: ResponseData;
	requestBody?: any;
	responseBody?: any;
}

interface DetectionResult {
	detected: boolean;
	reason: string;
}

interface LogRecord {
	timestamp: string;
	detectionType: 'Specification';
	detected: boolean;
	reason: string;
	request: string;
	response: string;
}

// CSV Logger Configuration
const detectionCSVLoggerHeader = [
	{ id: 'timestamp', title: 'Timestamp' },
	{ id: 'detectionType', title: 'Detection Type' },
	{ id: 'detected', title: 'Attack Detected' },
	{ id: 'reason', title: 'Detection Reason' },
	{ id: 'request', title: 'Request' },
	{ id: 'response', title: 'Response' },
];

// File Position Tracker
class FilePosition {
	private position: number;

	constructor() {
		this.position = 0;
	}

	getPosition(): number {
		return this.position;
	}

	setPosition(pos: number): void {
		this.position = pos;
	}
}

// Specification-based Detection Implementation
class SpecificationBasedDetection {
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
		'content-type': z.string().refine((val) => val === 'application/json', {
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
			maxPayloadSize: 1000000,
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

	private isPayloadSizeExceeded(entry: LogEntry): boolean {
		const bodySize = Buffer.from(
			typeof entry.request.body === 'string' ? entry.request.body : JSON.stringify(entry.request.body)
		).length;
		return bodySize > SpecificationBasedDetection.rateLimiting.rateLimiting.maxPayloadSize;
	}

	detect(entry: LogEntry): DetectionResult {
		// Check rate limiting
		const clientId = entry.request['x-api-tran-id']; // Assuming x-api-tran-id is the client ID
		if (this.isRateLimitExceeded(clientId)) {
			return {
				detected: true,
				reason: 'Rate limit exceeded',
			};
		}

		// Check payload size
		if (this.isPayloadSizeExceeded(entry)) {
			return {
				detected: true,
				reason: 'Payload size exceeded',
			};
		}

		try {
			const pathname = new URL(entry.request.url).pathname;
			const method = entry.request.method;
			const spec = SpecificationBasedDetection.apiSchemas[pathname]?.[method];

			// Path validation
			if (!spec) {
				return {
					detected: true,
					reason: 'Unknown endpoint or method',
				};
			}

			spec.request.parse({
				headers: entry.request,
				body: entry.request.body,
			});

			spec.response.parse({
				headers: entry.response,
				body: entry.response.body,
			});

			return {
				detected: false,
				reason: 'Request/Response conform to specifications',
			};
		} catch (error) {
			if (error instanceof z.ZodError) {
				console.log(entry.request, entry.response);
				return {
					detected: true,
					reason: `Specification violation: ${error.errors[0].message}`,
				};
			}

			return {
				detected: true,
				reason: `Unexpected error: ${(error as Error).message}`,
			};
		}
	}
}

// Log Processing Functions
async function readNewLogEntries(filePath: string, filePosition: FilePosition): Promise<LogEntry[]> {
	const fileSize = fs.statSync(filePath).size;
	if (fileSize <= filePosition.getPosition()) {
		return [];
	}

	const stream = fs.createReadStream(filePath, {
		start: filePosition.getPosition(),
		encoding: 'utf-8',
	});

	let buffer = '';
	const entries: LogEntry[] = [];

	for await (const chunk of stream) {
		buffer += chunk;
		const lines = buffer.split('\n');
		buffer = lines.pop() ?? '';

		entries.push(...parseLogLines(lines));
	}

	filePosition.setPosition(fileSize);
	return entries;
}

function parseLogLines(lines: string[]): LogEntry[] {
	const entries: LogEntry[] = [];
	const logPattern = /\|\|\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]\s\[request\s({.*?})\]\s\[response\s({.*?}})\]/;

	for (const line of lines) {
		const match = logPattern.exec(line);
		if (match) {
			const [, , requestStr, responseStr] = match;
			try {
				const request = JSON.parse(requestStr);
				const response = JSON.parse(responseStr);

				entries.push({
					request: request,
					response: response,
					requestBody: request.body,
					responseBody: response.body,
				});
			} catch (error) {
				console.error('Error parsing log entry:', error);
			}
		}
	}

	return entries;
}

// Logging Function
async function logDetectionResult(
	entry: LogEntry,
	detectionType: 'Specification',
	result: DetectionResult
): Promise<void> {
	if (!fs.existsSync(filePath('/public/specification_detection_logs.csv'))) {
		fs.writeFileSync(
			filePath('/public/specification_detection_logs.csv'),
			'timestamp,detectionType,detected,reason,request,response\n'
		);
	}

	const csvWriter2 = createCsvWriter({
		path: filePath('/public/specification_detection_logs.csv'),
		append: true,
		header: detectionCSVLoggerHeader,
	});

	const record: LogRecord = {
		timestamp: new Date().toISOString(),
		detectionType,
		detected: result.detected,
		reason: result.reason,
		request: JSON.stringify(entry.request),
		response: JSON.stringify(entry.response),
	};

	await csvWriter2.writeRecords([record]);
}

// Main Detection Function
async function detectIntrusions(entry: LogEntry): Promise<void> {
	const specificationDetector = new SpecificationBasedDetection();
	const specificationResult = specificationDetector.detect(entry);

	if (specificationResult.detected) {
		await logDetectionResult(entry, 'Specification', specificationResult);
		console.log('########## ⚠️ Intrusion Detected! ##########');
		console.log('Specification-based:', specificationResult);
	} else {
		await logDetectionResult(entry, 'Specification', specificationResult);
	}
}

// Initialize CSV
async function initializeCSV(filePath: string): Promise<void> {
	if (!fs.existsSync(filePath)) {
		const csvWriter = createCsvWriter({
			path: filePath,
			header: detectionCSVLoggerHeader,
		});
		await csvWriter.writeRecords([]);
	}
}

// Main Function to Start Detection
async function startDetection(logFilePath: string): Promise<void> {
	try {
		await initializeCSV(filePath('/public/detection_logs.csv'));
		const filePosition = new FilePosition();

		const runDetectionCycle = async () => {
			try {
				const newEntries = await readNewLogEntries(logFilePath, filePosition);
				for (const entry of newEntries) {
					await detectIntrusions(entry);
				}
			} catch (error) {
				console.error('Error in detection cycle:', error);
			}
		};

		// Initial run
		await runDetectionCycle();

		// Set up interval
		setInterval(runDetectionCycle, 5000);
	} catch (error) {
		console.error('Error starting detection:', error);
		throw error;
	}
}

// Start the detection system
startDetection(filePath('/public/requests_responses.txt')).catch(console.error);

export { SpecificationBasedDetection };
