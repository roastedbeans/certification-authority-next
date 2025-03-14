// detectionSignature.ts - Optimized signature-based detection for Certification Authority APIs
import { createObjectCsvWriter as createCsvWriter } from 'csv-writer';
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

// Regular expression patterns for detecting known attack signatures
const securityPatterns = {
	sqlInjection: [
		/('|"|`)\s*(OR|AND)\s*[0-9]+\s*=\s*[0-9]+/i,
		/('|"|`)\s*(OR|AND)\s*('|"|`)[^'"]*('|"|`)\s*=\s*('|"|`)/i,
		/('|"|`)\s*(OR|AND)\s*[0-9]+\s*=\s*[0-9]+\s*(--|#|\/\*)/i,
		/;\s*DROP\s+TABLE/i,
		/UNION\s+(ALL\s+)?SELECT/i,
		/SELECT\s+.*\s+FROM\s+information_schema/i,
		/ALTER\s+TABLE/i,
		/INSERT\s+INTO/i,
		/DELETE\s+FROM/i,
		/WAITFOR\s+DELAY/i,
		/SLEEP\s*\(/i,
		/BENCHMARK\s*\(/i,
		/EXEC\s*(xp_|sp_)/i,
	],
	xss: [
		/<script.*?>.*?<\/script>/i,
		/javascript:/i,
		/onerror\s*=/i,
		/onload\s*=/i,
		/onclick\s*=/i,
		/onmouseover\s*=/i,
		/onfocus\s*=/i,
		/onblur\s*=/i,
		/onkeydown\s*=/i,
		/onkeypress\s*=/i,
		/onkeyup\s*=/i,
		/ondblclick\s*=/i,
		/onchange\s*=/i,
		/alert\s*\(/i,
		/eval\s*\(/i,
		/document\.cookie/i,
		/document\.location/i,
		/document\.write/i,
		/document\.referrer/i,
		/window\.location/i,
		/window\.open/i,
		/<img.*?src=.*?onerror=.*?>/i,
	],
	xxe: [/<!DOCTYPE.*?SYSTEM/i, /<!ENTITY.*?SYSTEM/i, /<!\[CDATA\[.*?\]\]>/i],
	commandInjection: [/\s*\|\s*(\w+)/i, /`.*?`/, /\$\(.*?\)/, /;[\s\w\/]+/i, /&&[\s\w\/]+/i, /\|\|[\s\w\/]+/i],
	directoryTraversal: [
		/\.\.\//,
		/\.\.\\/,
		/%2e%2e\//i,
		/%2e%2e\\/i,
		/\.\.%2f/i,
		/\.\.%5c/i,
		/%252e%252e\//i,
		/%252e%252e\\/i,
	],
	fileUpload: [
		/\.php$/i,
		/\.asp$/i,
		/\.aspx$/i,
		/\.exe$/i,
		/\.jsp$/i,
		/\.jspx$/i,
		/\.sh$/i,
		/\.bash$/i,
		/\.csh$/i,
		/\.bat$/i,
		/\.cmd$/i,
		/\.dll$/i,
		/\.jar$/i,
		/\.war$/i,
	],
	cookieInjection: [/document\.cookie.*?=/i],
	maliciousHeaders: [/X-Forwarded-Host:\s*[^.]+\.[^.]+\.[^.]+/i, /Host:\s*[^.]+\.[^.]+\.[^.]+/i],
	ssrf: [
		/localhost/i,
		/127\.0\.0\.1/i,
		/0\.0\.0\.0/i,
		/::1/i,
		/192\.168\./i,
		/10\./i,
		/172\.(1[6-9]|2[0-9]|3[0-1])\./i,
		/169\.254\./i,
		/x00/i,
	],
};

// Signature-based Detection Implementation
class SignatureBasedDetection {
	private static readonly KNOWN_ATTACK_PATTERNS = securityPatterns;

	detect(entry: LogEntry): DetectionResult {
		try {
			// Convert entire request and response objects to strings for pattern matching
			const reqStr = JSON.stringify(entry.request);
			const resStr = JSON.stringify(entry.response);
			const combinedStr = reqStr + resStr;

			// Check against each pattern category
			for (const [category, patterns] of Object.entries(SignatureBasedDetection.KNOWN_ATTACK_PATTERNS)) {
				for (const pattern of patterns as RegExp[]) {
					if (pattern.test(combinedStr)) {
						return {
							detected: true,
							reason: `Signature match: ${category} pattern detected: ${pattern}`,
						};
					}
				}
			}

			return {
				detected: false,
				reason: 'No known attack signatures detected',
			};
		} catch (error) {
			console.error('Error in signature detection:', error);
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
		const csvPath = filePath('/public/signature_detection_logs.csv');

		// Ensure the CSV file exists
		await ensureLogFile(csvPath, 'timestamp,detectionType,detected,reason,request,response\n');

		const csvWriter = createCsvWriter({
			path: csvPath,
			append: true,
			header: detectionCSVLoggerHeader,
		});

		const record: LogRecord = {
			timestamp: new Date().toISOString(),
			detectionType: 'Signature',
			detected: result.detected,
			reason: result.reason,
			request: JSON.stringify(entry.request),
			response: JSON.stringify(entry.response),
		};

		await csvWriter.writeRecords([record]);

		if (result.detected) {
			console.log(`[${record.timestamp}] 🚨 Attack detected: ${result.reason}`);
		} else {
			console.log(`[${record.timestamp}] ✅ Clean request`);
		}
	} catch (error) {
		console.error('Error logging detection result:', error);
	}
}

// Main Detection Function
async function detectIntrusions(entry: LogEntry): Promise<void> {
	try {
		const detector = new SignatureBasedDetection();
		const result = detector.detect(entry);
		await logDetectionResult(entry, result);
	} catch (error) {
		console.error('Error in intrusion detection:', error);
	}
}

// Start Detection Process
async function startDetection(logFilePath: string): Promise<void> {
	console.log('Starting signature-based detection...');
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
export { SignatureBasedDetection };
