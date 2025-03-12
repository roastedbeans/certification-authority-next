import * as fs from 'fs';
import * as path from 'path';
import { LogEntry } from './types';
import { RateLimiter, RateLimitResult } from './rateLimit';
import { createObjectCsvWriter } from 'csv-writer';

const LOG_FILE_PATH = path.join(process.cwd(), 'public', 'requests_responses.txt');
const RATE_LIMIT_LOG_PATH = path.join(process.cwd(), 'logs', 'rate_limit_detection.csv');

// Create logs directory if it doesn't exist
if (!fs.existsSync(path.dirname(RATE_LIMIT_LOG_PATH))) {
	fs.mkdirSync(path.dirname(RATE_LIMIT_LOG_PATH), { recursive: true });
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
 */
export async function runRateLimitDetection(logFilePath = LOG_FILE_PATH): Promise<void> {
	console.log(`Starting rate limit detection on: ${logFilePath}`);

	try {
		// Read log file
		const logContent = fs.readFileSync(logFilePath, 'utf8');
		const logLines = logContent.split('\n').filter((line) => line.trim() !== '');

		console.log(`Found ${logLines.length} log entries to analyze`);

		// Create rate limiter instance
		const rateLimiter = new RateLimiter();

		// Map to track client and endpoint requests
		const clientRequests = new Map<string, Map<string, number[]>>();

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
 * Main entry point
 */
if (require.main === module) {
	runRateLimitDetection()
		.then(() => console.log('Rate limit detection completed'))
		.catch((error) => console.error('Error:', error));
}
