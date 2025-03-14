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
	detectionType: 'Signature' | 'Specification' | 'Hybrid';
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

const securityPatterns = {
	xss: [
		// Script tag variations
		/(<script[^>]*>[\s\S]*?<\/script>)/i,
		/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/i, // More comprehensive script tag
		/(<script[^>]*>)/i, // Opening script tag

		// Event handlers and javascript: URLs
		/\b(on\w+\s*=\s*['"]*javascript:)/i, // Specific event handler format
		/\b(on(mouse|key|load|unload|click|dbl|focus|blur)\w+\s*=)/i, // Specific events
		/javascript:[^\w]*/i, // Refined javascript: pattern

		// Data injection
		/data:(?:image\/\w+;)?base64,[A-Za-z0-9+/]+={0,2}/i, // Base64 data
		/expression\s*\(|@import\s+|vbscript:/i, // CSS expressions and imports

		// HTML breaking refined
		// /<[^\w<>]*(?:[^<>"'\s]*:)?[^\w<>]*(?:\W*s\W*c\W*r\W*i\W*p\W*t|form|style|\w+:\w+)/i,
		/<img\s+[^>]*onerror\s*=\s*["'][^"']*["'][^>]*>/gi,

		// <script>alert(document.cookie)</script>
		/<script[^>]*>[^<]*document\.cookie[^<]*<\/script>/i,
	],

	sqlInjection: [
		// Complex UNION attacks
		/UNION[\s\/\*]+ALL[\s\/\*]+SELECT/i,
		/UNION[\s\/\*]+SELECT/i,

		// Refined time-based
		/WAITFOR[\s\/\*]+DELAY[\s\/\*]+'\d+'/i,
		/BENCHMARK\(\d+,[\w\s-]+\)/i,
		/pg_sleep\(\d+\)/i,

		// Stacked queries refined
		/;[\s\/\*]*(UPDATE|INSERT|DELETE)[\s\/\*]+/i,
		/;[\s\/\*]*DROP[\s\/\*]+/i,

		// Error-based refined
		/(SELECT|UPDATE|INSERT|DELETE)[\s\/\*]+CASE[\s\/\*]+WHEN/i,
		/CONVERT\([\w\s,]+\)/i,

		// Out-of-band attacks
		/SELECT[\s\/\*]+INTO[\s\/\*]+OUTFILE/i,
		/LOAD_FILE\s*\(/i,

		// Blind SQL injection
		/1[\s\/\*]+AND[\s\/\*]+\(SELECT/i,
		/1[\s\/\*]+AND[\s\/\*]+SLEEP\(/i,

		// ' OR '1'='1 regex
		/(?:'|\")(?:\s+OR\s+['|\"]1['|\"]=['|\"]1)/i,
		/(%|)\s*OR\s*%/i,
	],

	cookieInjection: [
		// Session manipulation refined
		/JSESSIONID=[^;]+/i,
		/PHPSESSID=[^;]+/i,
		/ASP\.NET_SessionId=[^;]+/i,

		// Role/privilege manipulation
		/role=(?:admin|superuser|root)/i,
		/privilege=(?:admin|superuser|root)/i,
		/access_level=(?:\d+|admin|root)/i,

		// Token manipulation
		/(?:auth|jwt|bearer)_token=[^;]+/i,
		/refresh_token=[^;]+/i,

		// Security flag tampering
		/;\s*secure\s*=\s*(?:false|0|off)/i,
		/;\s*httponly\s*=\s*(?:false|0|off)/i,

		// Domain scope manipulation
		/domain=(?:\.[^;]+)/i, // Starts with dot
		/path=(?:\/[^;]*)/i, // Starts with slash
		/Path=(?:\/[^;]*)/i, // Capitalized path
		/session=(?:true|false|)/i,
	],

	directoryTraversal: [
		// Complex traversal patterns
		/(?:\.{2,3}[\/\\]){1,}/i, // Multiple parent directory
		// /%(?:2e|2E){2,}(?:%2f|%2F|%5c|%5C)/i, // Double-encoded dots

		// System directory access
		/(?:\/|\\)(?:sys|proc|opt|usr|home|var|root)\b/i,
		// /(?:\/|\\)(?:etc|dev|tmp|bin|sbin)\b/i,

		// Windows specific
		/[A-Za-z]:\\+(?:windows|program\sfiles|boot|system\d+)/i,
		/\\(?:windows|system|config|sam)\b/i,

		// Special encoding
		/%(?:c0|c1|c2|c3)%(?:ae|af)/i, // UTF-8 encoding
		/%(?:u002e|u2215|u002f)/i, // Unicode encoding
	],

	xxe: [
		// Entity declarations refined
		/<!ENTITY\s+(?:%\s+)?\w+\s+SYSTEM\s+["'][^"']+["']/i,
		/<!ENTITY\s+(?:%\s+)?\w+\s+PUBLIC\s+["'][^"']+["']/i,

		// XXE specific
		/<\?xml[\s\/]+version=/i,
		/<!DOCTYPE[^>]+\[/i,
		/<!ATTLIST\s+\w+\s+\w+\s+ENTITY\s+/i,

		// Parameter entities
		/%(?:file|include|resource)\s*;/i,
		/%\w+\s*;/,

		// <foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>
		/<\w+\s+xmlns:xi="http:\/\/www\.w3\.org\/2001\/XInclude"><xi:include\s+parse="text"\s+href="file:\/\/\/etc\/passwd"\/><\/\w+>/i,
	],

	maliciousHeaders: {
		'user-agent': [
			/(?:sqlmap|havij|acunetix|nessus)/i,
			/(?:nikto|burp|nmap|wireshark)/i,
			/(?:metasploit|hydra|w3af|wfuzz)/i,
			/(?:masscan|zgrab|gobuster|dirbuster)/i,
		],
		'x-forwarded-for': [/^(?:127\.0\.0\.1|0\.0\.0\.0|::1)$/, /^(?:10\.|172\.(?:1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)/],
		referer: [
			/(?:\/\.git\/|\/\.svn\/|\/\.env)/i,
			/(?:\/wp-admin|\/wp-content|\/wp-includes)/i,
			/(?:\/administrator\/|\/admin\/|\/phpMyAdmin)/i,
		],
		authorization: [
			/^(?:null|undefined|admin|root):?/i,
			/(?:' OR '1'='1)/i,
			/['"\\;]/, // SQL injection in Basic Auth
		],
	},

	// New categories
	fileUpload: [
		// Dangerous extensions
		/\.(?:php[3-8]?|phtml|php\d*|exe|dll|jsp|asp|aspx|bat|cmd|sh|cgi|pl|py|rb)$/i,

		// Double extensions
		/\.[a-z]+\.(?:php|exe|jsp|asp|aspx|bat|sh)$/i,

		// MIME type manipulation
		/Content-Type:\s*(?:x-php|x-httpd-php|x-httpd-php-source)/i,

		// Null byte injection in filenames
		/.*%00.*/,
	],

	commandInjection: [
		// Shell commands
		/[;&|`]\s*(?:ls|pwd|cd|cp|mv|rm|cat|echo|touch|chmod|chown|kill|ps|top)/i,

		// Command chaining
		/(?:\|\||&&|\|\&|\&\||\|\&\&)/,

		// Input/output redirection
		/[><]\s*(?:\/dev\/(?:tcp|udp)|\w+\.(?:txt|log|php))/i,

		// Background execution
		/\&\s*$|\`[^`]*\`/,

		// Special shell variables
		/\$\{(?:IFS|PATH|HOME|SHELL|ENV)\}/i,
	],

	ssrf: [
		// Original patterns (Internal IP addresses)
		/^0\./, // 0.0.0.0/8
		/^10\./, // 10.0.0.0/8
		/^127\./, // 127.0.0.0/8
		/^169\.254\./, // 169.254.0.0/16
		/^172\.(1[6-9]|2[0-9]|3[0-1])\./, // 172.16.0.0/12
		/^192\.168\./, // 192.168.0.0/16
		/^fc00:/, // FC00::/7
		/^fe80:/, // FE80::/10

		// Added new SSRF patterns
		// DNS Spoofing Attempts
		/\d+\.0\.0\.1/, // DNS spoofing variants
		// /localhost\.(\w+)$/i, // Subdomain localhost variants
		/127\.(\d+)\.(\d+)\.1/, // 127.x.x.1 variants

		// Cloud Service Specific
		/\.internal\.cloudapp\.net$/i, // Azure internal endpoints
		/\.compute\.internal$/i, // GCP internal
		/\.ec2\.internal$/i, // AWS EC2 internal
		/\.service\.consul$/i, // Consul service discovery
		/\.(?:ecs|eks|elb)\.internal$/i, // AWS container services

		// Service Discovery
		/eureka\.client/i, // Eureka service discovery
		/zookeeper\.connect/i, // ZooKeeper
		/etcd\.endpoints/i, // etcd

		// Container Orchestration
		/docker\.sock/i, // Docker socket
		/kubelet\.service/i, // Kubernetes kubelet
		/\.cluster\.local$/i, // Kubernetes internal DNS

		// Database and Cache Services
		/\.rds\.amazonaws\.com$/i, // AWS RDS
		/\.cache\.amazonaws\.com$/i, // AWS ElastiCache
		/\.documentdb\.amazonaws\.com$/i, // AWS DocumentDB

		// Additional Internal Services
		/\.grafana\.net$/i, // Grafana
		/\.prometheus\.io$/i, // Prometheus
		/\.kibana\.net$/i, // Kibana
		/\.jenkins\.internal$/i, // Jenkins

		// Protocol Handlers (expanded)
		/^(file|gopher|dict|ldap|tftp|ftp|neo4j|redis|memcached|mongodb|cassandra|couchdb):/i,

		// Cloud Provider Metadata (expanded)
		/169\.254\.169\.254.*\/(?:latest|current)\/(?:meta-data|user-data|dynamic)/i, // AWS expanded
		/metadata\.google\.internal.*\/computeMetadata\/v1/i, // GCP expanded
		/metadata\.azure\.internal.*\/metadata\/instance/i, // Azure expanded

		// Additional Internal Systems
		/(?:rabbitmq|kafka|redis|memcached|elasticsearch)\.internal/i,
		/(?:gitea|gitlab|bitbucket)\.internal/i,
		/(?:jenkins|bamboo|teamcity)\.internal/i,
		/(?:jira|confluence|wiki)\.internal/i,

		// Expanded Sensitive Paths
		/\/var\/run\/docker\.sock/,
		/\/etc\/kubernetes\/admin\.conf/,
		/\/root\/\.kube\/config/,
		/\/var\/lib\/kubelet/,
		/\/etc\/rancher\/k3s\/k3s\.yaml/,
	],
};

// Signature-based Detection Implementation
class SignatureBasedDetection {
	private static readonly KNOWN_ATTACK_PATTERNS = {
		sqlInjection: securityPatterns.sqlInjection,
		ssrf: securityPatterns.ssrf,
		xss: securityPatterns.xss,
		xxe: securityPatterns.xxe,
		cookieInjection: securityPatterns.cookieInjection,
		pathTraversal: securityPatterns.directoryTraversal,
		maliciousHeaders: securityPatterns.maliciousHeaders,
		fileUpload: securityPatterns.fileUpload,
		commandInjection: securityPatterns.commandInjection,
	};

	detect(entry: LogEntry): DetectionResult {
		// Check entire request and response for known attack patterns
		const fullRequest = JSON.stringify(entry.request);
		const fullResponse = JSON.stringify(entry.response);

		const fullLines = fullRequest + ' ' + fullResponse;

		// Check request body for known attack patterns
		const bodyStr = typeof entry.requestBody === 'string' ? entry.requestBody : JSON.stringify(entry.requestBody);

		// Check SQL Injection
		if (SignatureBasedDetection.KNOWN_ATTACK_PATTERNS.sqlInjection.some((pattern) => pattern.test(fullLines))) {
			return {
				detected: true,
				reason: 'SQL Injection attempt detected',
			};
		}

		// Check SSRF
		if (SignatureBasedDetection.KNOWN_ATTACK_PATTERNS.ssrf.some((pattern) => pattern.test(fullLines))) {
			return {
				detected: true,
				reason: 'SSRF attempt detected',
			};
		}

		// Check XSS
		if (SignatureBasedDetection.KNOWN_ATTACK_PATTERNS.xss.some((pattern) => pattern.test(fullLines))) {
			return {
				detected: true,
				reason: 'XSS attempt detected',
			};
		}

		// Check XXE
		if (SignatureBasedDetection.KNOWN_ATTACK_PATTERNS.xxe.some((pattern) => pattern.test(fullLines))) {
			return {
				detected: true,
				reason: 'XXE attempt detected',
			};
		}

		// Check Path Traversal
		if (SignatureBasedDetection.KNOWN_ATTACK_PATTERNS.pathTraversal.some((pattern) => pattern.test(fullLines))) {
			return {
				detected: true,
				reason: 'Path traversal attempt detected',
			};
		}

		// Check Cookie Injection
		if (SignatureBasedDetection.KNOWN_ATTACK_PATTERNS.cookieInjection.some((pattern) => pattern.test(fullLines))) {
			return {
				detected: true,
				reason: 'Cookie Injection attempt detected',
			};
		}

		// Check File Upload
		if (SignatureBasedDetection.KNOWN_ATTACK_PATTERNS.fileUpload.some((pattern) => pattern.test(bodyStr))) {
			return {
				detected: true,
				reason: 'File Upload attempt detected',
			};
		}

		// Check Command Injection
		if (SignatureBasedDetection.KNOWN_ATTACK_PATTERNS.commandInjection.some((pattern) => pattern.test(bodyStr))) {
			return {
				detected: true,
				reason: 'Command Injection attempt detected',
			};
		}

		// Check headers
		for (const [headerName, patterns] of Object.entries(
			SignatureBasedDetection.KNOWN_ATTACK_PATTERNS.maliciousHeaders
		)) {
			if (entry.request[headerName] && patterns.some((pattern) => pattern.test(entry.request[headerName]))) {
				return {
					detected: true,
					reason: `Malicious ${headerName} detected`,
				};
			}
		}

		return {
			detected: false,
			reason: 'No known attack patterns detected',
		};
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

		if (entry.request && entry.requestBody) {
			console.log('entry.request', entry.request);
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
				console.log('key', key);
				if (value && typeof value === 'string') {
					const size = Buffer.from(String(value)).length;
					if (size > maxSize) {
						console.log('value', value, size);
						overloadedFields.push(key);
						entry.request[key as keyof RequestData] = 'overload here';
					}
				} else {
					const toString = JSON.stringify(value);
					const size = Buffer.from(toString).length;
					if (size > maxSize) {
						console.log('value', value, size);
						overloadedFields.push(key);
						entry.request[key as keyof RequestData] = 'overload here';
					}
				}
			}

			// Handle additional fields from index signature
			const standardKeys = Object.keys(fieldsToCheck);
			Object.entries(entry.request).forEach(([key, value]) => {
				if (!standardKeys.includes(key)) {
					const size = Buffer.from(String(value)).length;
					if (size > maxSize) {
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
		if (this.isRateLimitExceeded(clientId)) {
			return {
				detected: true,
				reason: 'Rate limit exceeded',
			};
		}

		// Check payload size
		const payloadCheck = this.isPayloadSizeExceeded(entry);
		console.log('payload check', payloadCheck);
		if (payloadCheck.isExceeded) {
			return {
				detected: true,
				reason: `Payload size exceeded in fields: ${payloadCheck.overloadedFields.join(', ')}`,
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
async function logDetectionResult(entry: LogEntry, result: DetectionResult): Promise<void> {
	if (!fs.existsSync(filePath('/public/hybrid_detection_logs.csv'))) {
		fs.writeFileSync(
			filePath('/public/hybrid_detection_logs.csv'),
			'timestamp,detectionType,detected,reason,request,response\n'
		);
	}

	const csvWriter2 = createCsvWriter({
		path: filePath('/public/hybrid_detection_logs.csv'),
		append: true,
		header: detectionCSVLoggerHeader,
	});

	const record: LogRecord = {
		timestamp: new Date().toISOString(),
		detectionType: 'Hybrid',
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
		console.log('########## Primary (Specification-based) Security Complete! ##########');
		await logDetectionResult(entry, specificationResult);
		console.log('########## ⚠️ Intrusion Detected! ##########');
		console.log('Specification-based:', specificationResult);
	} else {
		// await logDetectionResult(entry, 'Specification', specificationResult);
		console.log('########## Primary (Specification-based) Security Complete! ##########');
		console.log('########## Initializing Secondary (Signature-based) Detection! ##########');
		console.log('########## Matching attack patterns... ##########');
		const signatureDetector = new SignatureBasedDetection();
		const signatureResult = signatureDetector.detect(entry);

		if (signatureResult.detected) {
			await logDetectionResult(entry, signatureResult);
			console.log('########## ⚠️ Intrusion Detected! ##########');
			console.log('Signature-based:', signatureResult);
			console.log('########## Secondary (Signature-based) Security Complete! ##########');
		} else {
			await logDetectionResult(entry, signatureResult);
			console.log('########## Secondary (Signature-based) Security Complete! ##########');
		}
	}
}

// Main Function to Start Detection
async function startDetection(logFilePath: string): Promise<void> {
	try {
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

export { SignatureBasedDetection, SpecificationBasedDetection };
