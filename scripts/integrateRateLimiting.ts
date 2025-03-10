import * as fs from 'fs';
import * as path from 'path';
import { LogEntry, DetectionResult, LogRecord } from './types';
import { RateLimiter, RateLimitResult, applyRateLimiting } from './rateLimit';
import { SpecificationBasedDetection } from './detectionSpecification';

/**
 * Example of integrating the new rate limiting feature with the existing detection specification
 * This demonstrates how to use both systems together for comprehensive API protection
 */

// File paths for logs
const LOG_FILE_PATH = path.join(process.cwd(), 'logs', 'api-logs.json');
const DETECTION_LOG_PATH = path.join(process.cwd(), 'logs', 'detection-logs.csv');

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

/**
 * Read new log entries from the log file
 */
async function readNewLogEntries(filePath: string, filePosition: FilePosition): Promise<LogEntry[]> {
	return new Promise((resolve, reject) => {
		fs.stat(filePath, (err, stats) => {
			if (err) {
				if (err.code === 'ENOENT') {
					return resolve([]);
				}
				return reject(err);
			}

			if (stats.size <= filePosition.getPosition()) {
				return resolve([]);
			}

			const stream = fs.createReadStream(filePath, {
				start: filePosition.getPosition(),
				end: stats.size - 1,
			});

			let data = '';
			stream.on('data', (chunk) => {
				data += chunk;
			});

			stream.on('end', () => {
				filePosition.setPosition(stats.size);
				const lines = data.split('\n').filter((line) => line.trim() !== '');
				const entries = parseLogLines(lines);
				resolve(entries);
			});

			stream.on('error', reject);
		});
	});
}

/**
 * Parse log lines into LogEntry objects
 */
function parseLogLines(lines: string[]): LogEntry[] {
	return lines
		.map((line) => {
			try {
				return JSON.parse(line) as LogEntry;
			} catch (e) {
				console.error('Error parsing log line:', e);
				return null;
			}
		})
		.filter((entry): entry is LogEntry => entry !== null);
}

/**
 * Log detection results to a CSV file
 */
async function logDetectionResult(
	entry: LogEntry,
	detectionType: 'Specification' | 'RateLimit',
	result: DetectionResult | RateLimitResult
): Promise<void> {
	// Check if the CSV file exists, if not create it with headers
	if (!fs.existsSync(DETECTION_LOG_PATH)) {
		await initializeCSV(DETECTION_LOG_PATH);
	}

	const timestamp = new Date().toISOString();
	const record: LogRecord = {
		timestamp,
		detectionType,
		detected: 'exceeded' in result ? result.exceeded : result.detected,
		reason: result.reason,
		request: JSON.stringify(entry.request),
		response: JSON.stringify(entry.response),
	};

	const csvLine = `${record.timestamp},${record.detectionType},${record.detected},${record.reason.replace(
		/,/g,
		';'
	)},${record.request.replace(/,/g, ';')},${record.response.replace(/,/g, ';')}\n`;

	return new Promise((resolve, reject) => {
		fs.appendFile(DETECTION_LOG_PATH, csvLine, (err) => {
			if (err) return reject(err);
			resolve();
		});
	});
}

/**
 * Initialize the CSV file with headers
 */
async function initializeCSV(filePath: string): Promise<void> {
	const headers = 'timestamp,detectionType,detected,reason,request,response\n';
	return new Promise((resolve, reject) => {
		fs.writeFile(filePath, headers, (err) => {
			if (err) return reject(err);
			resolve();
		});
	});
}

/**
 * Main detection function that combines rate limiting and specification checks
 */
async function detectIntrusions(entry: LogEntry): Promise<void> {
	// First, check rate limits
	const rateLimitResult = await applyRateLimiting(entry);

	// Log rate limit violations
	if (rateLimitResult.exceeded) {
		await logDetectionResult(entry, 'RateLimit', rateLimitResult);
		console.log(`[RATE LIMIT VIOLATION] ${rateLimitResult.reason}`);
		return; // No need to check specifications if rate limit is already exceeded
	}

	// If rate limits passed, check specifications
	const specDetection = new SpecificationBasedDetection();
	const specResult = specDetection.detect(entry as any);

	// Log specification violations
	if (specResult.detected) {
		await logDetectionResult(entry, 'Specification', specResult);
		console.log(`[SPECIFICATION VIOLATION] ${specResult.reason}`);
	}
}

/**
 * Start the detection process
 */
async function startDetection(logFilePath: string): Promise<void> {
	try {
		const filePosition = new FilePosition();

		// Run detection in a loop
		const runDetectionCycle = async () => {
			try {
				const entries = await readNewLogEntries(logFilePath, filePosition);
				for (const entry of entries) {
					await detectIntrusions(entry);
				}
			} catch (error) {
				console.error('Error in detection cycle:', error);
			}

			// Schedule next cycle
			setTimeout(runDetectionCycle, 1000);
		};

		// Start the detection cycle
		await runDetectionCycle();
	} catch (error) {
		console.error('Error starting detection:', error);
	}
}

/**
 * Example of direct usage for testing
 */
async function testWithSampleRequest(): Promise<void> {
	// Create a sample log entry
	const sampleEntry: LogEntry = {
		request: {
			url: 'https://api.example.com/api/v2/mgmts/oauth/2.0/token',
			method: 'POST',
			authorization: 'Bearer sample-token',
			'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
			'x-api-tran-id': 'ABCDEFGHIJK12345678901234',
			'x-api-type': 'certificate',
			'x-csrf-token': 'sample-csrf-token',
			cookie: 'session=sample-session-id',
			'set-cookie': '',
			'content-length': '256',
			body: 'grant_type=client_credentials&client_id=sample-client&client_secret=sample-secret',
		},
		response: {
			body: '{"access_token":"sample-access-token","expires_in":3600}',
		},
	};

	// Test with the integrated detection
	await detectIntrusions(sampleEntry);
}

// Run the test when executed directly
if (require.main === module) {
	testWithSampleRequest().catch(console.error);
}

// Export for use in other files
export { startDetection, detectIntrusions };
