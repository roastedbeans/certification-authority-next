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
	detectionType: 'Signature';
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
async function logDetectionResult(entry: LogEntry, detectionType: 'Signature', result: DetectionResult): Promise<void> {
	if (!fs.existsSync(filePath('/public/signature_detection_logs.csv'))) {
		fs.writeFileSync(
			filePath('/public/signature_detection_logs.csv'),
			'timestamp,detectionType,detected,reason,request,response\n'
		);
	}

	const csvWriter1 = createCsvWriter({
		path: filePath('/public/signature_detection_logs.csv'),
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

	await csvWriter1.writeRecords([record]);
}

// Main Detection Function
async function detectIntrusions(entry: LogEntry): Promise<void> {
	const signatureDetector = new SignatureBasedDetection();
	const signatureResult = signatureDetector.detect(entry);

	if (signatureResult.detected) {
		await logDetectionResult(entry, 'Signature', signatureResult);
		console.log('########## ⚠️ Intrusion Detected! ##########');
		console.log('Signature-based:', signatureResult);
	} else {
		await logDetectionResult(entry, 'Signature', signatureResult);
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

export { SignatureBasedDetection };
