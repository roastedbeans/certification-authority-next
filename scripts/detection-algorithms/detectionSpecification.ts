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
	// Session tracking for sequence pattern analysis
	private sessionStates: Map<string, {
		lastEndpoint: string;
		sequence: string[];
		timestamp: number;
		flowState: 'none' | 'support_completed' | 'ca_authenticated' | 'consent_requested' | 'consent_signed' | 'bank_authenticated' | 'verified' | 'completed';
		mandatorySteps: Set<string>;
		tokensUsed: Set<string>;
		lastBankAccess: number;
	}> = new Map();

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

	// Expected API call sequences for MyData/Open Banking flow
	// Note: Only CA endpoints are tracked here. External bank APIs are validated separately.
	private static readonly expectedSequences = {
		// Main flow: orgs -> mgmt_token -> ca_token -> sign_request -> sign_result -> bank_token -> sign_verification
		main: [
			'/api/v2/mgmts/orgs',          // getSupport002 - get organization list
			'/api/v2/mgmts/oauth/2.0/token', // getSupport001 - get management token
			'/api/oauth/2.0/token',         // getIA101 - get CA access token (scope: 'ca')
			'/api/ca/sign_request',         // getIA102 - request electronic signature
			'/api/ca/sign_result',          // getIA103 - get signature result
			'/api/oauth/2.0/token',         // getIA002 - get bank access token (external API)
			'/api/ca/sign_verification',    // getIA104 - verify signature
		],
		// Alternative flows
		management_only: ['/api/v2/mgmts/orgs', '/api/v2/mgmts/oauth/2.0/token'],
		signing_only: ['/api/oauth/2.0/token', '/api/ca/sign_request', '/api/ca/sign_result'],
		verification_only: ['/api/oauth/2.0/token', '/api/ca/sign_verification']
	};

	// Session timeout in milliseconds (30 minutes)
	private static readonly SESSION_TIMEOUT = 30 * 60 * 1000;

	// Mandatory endpoints that must be called before CA operations
	private static readonly MANDATORY_ENDPOINTS = new Set([
		'/api/v2/mgmts/oauth/2.0/token',  // Support001 - management token
		'/api/v2/mgmts/orgs'             // Support002 - organization list
	]);

	// Critical suspicious patterns from attack simulations
	// Note: These patterns focus on CA endpoint sequences. External API patterns are handled separately.
	private static readonly CRITICAL_ATTACK_PATTERNS = [
		// Skip verification: sign_request -> external token (without sign_result/sign_verification)
		{ pattern: ['/api/ca/sign_request', '/api/oauth/2.0/token'], external: true, reverse: false, reason: 'Skipping consent signing and verification before external API access' },
		// Skip signing entirely: CA token -> external token
		{ pattern: ['/api/oauth/2.0/token', '/api/oauth/2.0/token'], external: true, reverse: false, reason: 'Skipping entire consent process before external access' },
		// Out of order: sign_result before sign_request
		{ pattern: ['/api/ca/sign_result', '/api/ca/sign_request'], external: false, reverse: true, reason: 'Calling sign_result before sign_request' },
		// Verification without signing
		{ pattern: ['/api/oauth/2.0/token', '/api/ca/sign_verification'], external: false, reverse: false, reason: 'Sign verification without prior signing' },
	];

	// Flow state transitions
	private static readonly FLOW_TRANSITIONS = {
		'/api/v2/mgmts/oauth/2.0/token': 'support_completed',  // Support001
		'/api/v2/mgmts/orgs': 'support_completed',            // Support002
		'/api/oauth/2.0/token': 'ca_authenticated',           // IA101 (CA token)
		'/api/ca/sign_request': 'consent_requested',          // IA102
		'/api/ca/sign_result': 'consent_signed',              // IA103
		'/api/ca/sign_verification': 'verified',              // IA104
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
					body: z.union([
						// Success response format
						z.object({
							rsp_code: z.string().max(30, {
								message: 'rsp_code does NOT match the specification, possible Response Code Manipulation Attack',
							}),
							rsp_msg: z.string().max(450, {
								message: 'rsp_msg does NOT match the specification, possible Response Message Manipulation Attack',
							}),
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
						}),
						// Error response format
						z.object({
							code: z.string().max(10, {
								message: 'error code does NOT match the specification, possible Response Code Manipulation Attack',
							}),
							message: z.string().max(500, {
								message: 'error message does NOT match the specification, possible Response Message Manipulation Attack',
							}),
						}),
					]),
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
					body: z.union([
						// Success response format
						z.object({
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
						// Error response format
						z.object({
							code: z.string().max(10, {
								message: 'error code does NOT match the specification, possible Response Code Manipulation Attack',
							}),
							message: z.string().max(500, {
								message: 'error message does NOT match the specification, possible Response Message Manipulation Attack',
							}),
						}),
					]),
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
					body: z.union([
						// Success response format
						z.object({
							rsp_code: z.string().max(30, {
								message: 'rsp_code does NOT match the specification, possible Response Code Manipulation Attack',
							}),
							rsp_msg: z.string().max(450, {
								message: 'rsp_msg does NOT match the specification, possible Response Message Manipulation Attack',
							}),
							token_type: z.string().refine((val) => val === 'Bearer', {
								message:
									'token_type does NOT match the specification, possible Token Type Manipulation or Confusion Attack',
							}),
							access_token: z.string().max(1500, {
								message:
									'access_token does NOT match the specification, possible Token Injection or JWT Tampering Attack',
							}),
							expires_in: z.number().max(999999999, {
								message: 'expires_in does NOT match the specification, possible Token Lifetime Manipulation Attack',
							}),
							scope: z.string().refine((val) => val === 'ca', {
								message: 'scope does NOT match the specification, possible Permission Escalation Attack',
							}),
							issued_at: z.number().optional(),
						}),
						// Error response format
						z.object({
							code: z.string().max(10, {
								message: 'error code does NOT match the specification, possible Response Code Manipulation Attack',
							}),
							message: z.string().max(500, {
								message: 'error message does NOT match the specification, possible Response Message Manipulation Attack',
							}),
						}),
					]),
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
					body: z.union([
						// Success response format
						z.object({
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
						// Error response format
						z.object({
							code: z.string().max(10, {
								message: 'error code does NOT match the specification, possible Response Code Manipulation Attack',
							}),
							message: z.string().max(500, {
								message: 'error message does NOT match the specification, possible Response Message Manipulation Attack',
							}),
						}),
					]),
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
					body: z.union([
						// Success response format
						z.object({
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
						// Error response format
						z.object({
							code: z.string().max(10, {
								message: 'error code does NOT match the specification, possible Response Code Manipulation Attack',
							}),
							message: z.string().max(500, {
								message: 'error message does NOT match the specification, possible Response Message Manipulation Attack',
							}),
						}),
					]),
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
					body: z.union([
						// Success response format
						z.object({
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
						// Error response format
						z.object({
							code: z.string().max(10, {
								message: 'error code does NOT match the specification, possible Response Code Manipulation Attack',
							}),
							message: z.string().max(500, {
								message: 'error message does NOT match the specification, possible Response Message Manipulation Attack',
							}),
						}),
					]),
				}),
			},
		},
	};

	private readonly requestHistory: Map<string, number[]> = new Map();

	private validateSequencePattern(entry: LogEntry): { isValid: boolean; reason?: string } {
		try {
			const clientId = entry.request['x-api-tran-id'] || 'anonymous';
			const pathname = new URL(entry.request.url).pathname;
			const hostname = new URL(entry.request.url).hostname;
			const authorization = entry.request.authorization || '';
			const now = Date.now();

			// Clean up expired sessions
			for (const [sessionId, session] of this.sessionStates.entries()) {
				if (now - session.timestamp > SpecificationBasedDetection.SESSION_TIMEOUT) {
					this.sessionStates.delete(sessionId);
				}
			}

			let session = this.sessionStates.get(clientId);

			if (!session) {
				// New session - initialize with enhanced tracking
				session = {
					lastEndpoint: pathname,
					sequence: [pathname],
					timestamp: now,
					flowState: 'none',
					mandatorySteps: new Set(),
					tokensUsed: new Set(),
					lastBankAccess: 0
				};
				this.sessionStates.set(clientId, session);

				// Track initial mandatory step if applicable
				if (SpecificationBasedDetection.MANDATORY_ENDPOINTS.has(pathname)) {
					session.mandatorySteps.add(pathname);
				}

				// Extract initial token if present
				if (authorization.startsWith('Bearer ')) {
					session.tokensUsed.add(authorization.substring(7));
				}

				return { isValid: true }; // First request in sequence is always valid
			}

			// Update session tracking
			session.sequence.push(pathname);
			session.lastEndpoint = pathname;
			session.timestamp = now;

			// Extract and track tokens
			if (authorization.startsWith('Bearer ')) {
				const token = authorization.substring(7);
				session.tokensUsed.add(token);
			}

			// Track mandatory steps completion
			if (SpecificationBasedDetection.MANDATORY_ENDPOINTS.has(pathname)) {
				session.mandatorySteps.add(pathname);
			}

			// Update flow state
			const newState = SpecificationBasedDetection.FLOW_TRANSITIONS[pathname as keyof typeof SpecificationBasedDetection.FLOW_TRANSITIONS];
			if (newState) {
				session.flowState = newState as 'none' | 'support_completed' | 'ca_authenticated' | 'consent_requested' | 'consent_signed' | 'bank_authenticated' | 'verified' | 'completed';
			}

			// CRITICAL CHECK 1: Mandatory steps enforcement
			const isCAOperation = pathname.startsWith('/api/ca/') || pathname.startsWith('/api/oauth/2.0/token');
			const isBankOperation = hostname !== 'localhost' || pathname.includes('/api/v2/bank/');

			if ((isCAOperation || isBankOperation) && session.mandatorySteps.size === 0) {
				return {
					isValid: false,
					reason: `Critical violation: CA or bank operations (${pathname}) attempted without mandatory Support API calls. Must call /api/v2/mgmts/oauth/2.0/token and /api/v2/mgmts/orgs first.`
				};
			}

			// CRITICAL CHECK 2: External API access without proper flow completion
			if (isBankOperation && session.flowState !== 'verified' && session.flowState !== 'consent_signed') {
				return {
					isValid: false,
					reason: `Critical violation: External API access (${hostname}${pathname}) without completing consent signing and verification flow. Current state: ${session.flowState}`
				};
			}

			// CRITICAL CHECK 3: Detect attack patterns from simulate-invalid-flow-v3.ts
			const recentCalls = session.sequence.slice(-5); // Check last 5 calls

			for (const attackPattern of SpecificationBasedDetection.CRITICAL_ATTACK_PATTERNS) {
				const { pattern, external, reverse, reason } = attackPattern;

				// Check if pattern matches recent calls
				let patternFound = false;

				if (reverse) {
					// Check reverse order (e.g., result before request)
					patternFound = recentCalls.includes(pattern[1]) && recentCalls.includes(pattern[0]) &&
						recentCalls.indexOf(pattern[1]) < recentCalls.indexOf(pattern[0]);
				} else {
					// Check normal order
					const patternStr = pattern.join(',');
					const recentStr = recentCalls.slice(-pattern.length).join(',');
					patternFound = recentStr === patternStr;

					// For external patterns, also check if the second call is to external host
					if (patternFound && external && hostname !== 'localhost') {
						// This is a match for external API call pattern
					}
				}

				if (patternFound) {
					return {
						isValid: false,
						reason: `Attack pattern detected: ${reason}. Sequence: ${recentCalls.join(' -> ')}`
					};
				}
			}

			// ADDITIONAL CHECKS: Enhanced suspicious pattern detection

			// Check for out-of-order operations (e.g., IA103 before IA102)
			if (pathname === '/api/ca/sign_result' && !session.sequence.includes('/api/ca/sign_request')) {
				return {
					isValid: false,
					reason: 'Out-of-order operation: Calling sign_result without prior sign_request'
				};
			}

			if (pathname === '/api/ca/sign_verification' && !session.sequence.includes('/api/ca/sign_result')) {
				return {
					isValid: false,
					reason: 'Out-of-order operation: Calling sign_verification without sign_result'
				};
			}

			// Check for skipping verification (sign_request -> bank token without sign_result/sign_verification)
			const hasSignRequest = session.sequence.includes('/api/ca/sign_request');
			const hasSignResult = session.sequence.includes('/api/ca/sign_result');
			const hasVerification = session.sequence.includes('/api/ca/sign_verification');

			if (hasSignRequest && !hasSignResult && !hasVerification && hostname !== 'localhost') {
				return {
					isValid: false,
					reason: 'Skipping verification: Bank API access after sign_request without sign_result or sign_verification'
				};
			}

			// Check for direct bank access without CA token
			if (hostname !== 'localhost' && !session.tokensUsed.size) {
				return {
					isValid: false,
					reason: 'Direct external API access without authentication token'
				};
			}

			// Check for sequence length anomalies
			const sequenceLength = session.sequence.length;
			if (sequenceLength > 15) {
				return {
					isValid: false,
					reason: `Excessive API call sequence (${sequenceLength} calls). Possible probing attack.`
				};
			}

			// Check for rapid automated calls
			const recentTimestamps = this.requestHistory.get(clientId) || [];
			if (recentTimestamps.length >= 3) {
				const timeSpan = now - recentTimestamps[recentTimestamps.length - 3];
				const avgInterval = timeSpan / 2;

				if (avgInterval < 500 && sequenceLength >= 4) { // Very rapid calls
					console.warn(`Potential automated attack detected for client ${clientId}: ${avgInterval}ms intervals`);
					// Don't block, but log as suspicious
				}
			}

			// Update bank access timestamp
			if (hostname !== 'localhost' || pathname.includes('/api/v2/bank/')) {
				session.lastBankAccess = now;
			}

			return { isValid: true };

		} catch (error) {
			console.error('Error in sequence validation:', error);
			return { isValid: true }; // Don't block on sequence validation errors
		}
	}

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
				isAttack: true, // Rate limiting violations are definitely attacks
			};
		}

		// Check sequence patterns
		const sequenceCheck = this.validateSequencePattern(entry);
		if (!sequenceCheck.isValid) {
			return {
				detected: true,
				reason: sequenceCheck.reason || 'Sequence pattern violation detected',
				isAttack: true, // Sequence violations are suspicious and likely attacks
			};
		}

		// Check payload size
		const payloadCheck = this.isPayloadSizeExceeded(entry);
		if (payloadCheck.isExceeded) {
			return {
				detected: true,
				reason: `Payload size exceeded in fields: ${payloadCheck.overloadedFields.join(', ')}`,
				isAttack: true, // Payload size violations are definitely attacks
			};
		}

		try {
			// Validate URL format first
			if (!entry.request.url || !entry.request.url.trim()) {
				return {
					detected: true,
					reason: 'Missing URL in request',
					isAttack: true, // Missing URL is suspicious
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
					isAttack: true, // Invalid URL format is suspicious
				};
			}

			const pathname = url.pathname;
			const hostname = url.hostname;
			const method = entry.request.method;
			const spec = SpecificationBasedDetection.apiSchemas[pathname]?.[method];

			// Path validation - only validate CA endpoints, allow external APIs
			const isExternalAPI = hostname !== 'localhost' || url.port !== '3000' || pathname.startsWith('/api/v2/bank/') || url.href.includes(':4200') || url.href.includes(':4000');
			if (!spec && !isExternalAPI) {
				return {
					detected: true,
					reason: `Unknown CA endpoint or method: ${pathname} ${method}`,
					isAttack: true, // Accessing unknown CA endpoints is suspicious
				};
			}

			// Skip schema validation for external APIs (they have their own validators)
			if (isExternalAPI) {
				// Still perform sequence pattern validation for external calls
				const sequenceCheck = this.validateSequencePattern(entry);
				if (!sequenceCheck.isValid) {
					return {
						detected: true,
						reason: sequenceCheck.reason!,
						isAttack: true,
					};
				}

				return {
					detected: false,
					reason: 'External API call allowed, sequence pattern validated',
					isAttack: false,
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
						isAttack: true, // Request violations are generally attacks
					};
				}
				throw error;
			}

			try {
				// Extract only header fields from response
				const responseHeaders = {
					'x-api-tran-id': entry.response['x-api-tran-id'],
					'content-type': entry.response['content-type'],
				};

				spec.response.parse({
					headers: responseHeaders,
					body: entry.response.body,
				});
			} catch (error) {
				if (error instanceof z.ZodError) {
					// // Check if this is a legitimate error response
					// const responseBody = entry.response.body;
					// const isErrorResponse = responseBody &&
					// 	typeof responseBody === 'object' &&
					// 	(responseBody.code || responseBody.message) &&
					// 	!responseBody.token_type && // Not a success token response
					// 	!responseBody.rsp_code; // Not a success API response

					return {
						detected: true,
						reason: `Response specification violation: ${error.errors[0].message}`,
						isAttack: true, // Error responses are not attacks, but other violations are
					};
				}
				throw error;
			}

			return {
				detected: false,
				reason: 'Request/Response conform to specifications',
				isAttack: false,
			};
		} catch (error) {
			console.error('Error during detection:', error);
			return {
				detected: true,
				reason: `Unexpected error: ${(error as Error).message}`,
				isAttack: true,
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
			isAttack: true,
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
