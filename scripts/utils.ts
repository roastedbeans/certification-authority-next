import fs from 'fs';
import path from 'path';
import { parse as csvParse } from 'csv-parse/sync';
import { createObjectCsvWriter as createCsvWriter } from 'csv-writer';

// Central path helper function
export const filePath = (pathString: string) => {
	return path.join(process.cwd(), pathString);
};

// Shared interfaces
export interface RequestData {
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
	[key: string]: string;
}

export interface ResponseData {
	'x-api-tran-id': string;
	'content-type': string;
	status: string;
	body: string;
	[key: string]: string;
}

export interface LogEntry {
	timestamp?: string;
	request: RequestData;
	response: ResponseData;
}

export interface DetectionResult {
	detected: boolean;
	reason: string;
	isAttack: boolean;
}

export interface LogRecord {
	timestamp: string;
	detectionType: 'signature' | 'specification' | 'hybrid' | 'ratelimit';
	detected: boolean;
	reason: string;
	isAttack: boolean;
	request: string;
	response: string;
}

// File position tracking class
export class FilePosition {
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

// Helper to create sample log file if it doesn't exist
export function ensureSampleLogFile(filePath: string): void {
	const dir = path.dirname(filePath);

	// Ensure directory exists
	if (!fs.existsSync(dir)) {
		fs.mkdirSync(dir, { recursive: true });
	}

	// Create a sample log file if it doesn't exist
	if (!fs.existsSync(filePath)) {
		const sampleLog = `{"request":{"url":"http://localhost:3000/api/oauth/2.0/token","method":"POST","authorization":"","user-agent":"Mozilla/5.0","x-api-tran-id":"S123456789012","x-api-type":"CA","x-csrf-token":"","cookie":"","set-cookie":"","content-length":"85","body":"grant_type=client_credentials&client_id=example_id&client_secret=example_secret&scope=ca"},"response":{"body":"{\\"access_token\\":\\"example_token\\",\\"token_type\\":\\"Bearer\\",\\"expires_in\\":3600}"}}\n`;
		fs.writeFileSync(filePath, sampleLog);
		console.log(`Created sample log file at ${filePath}`);
	}
}

// Log Processing Functions for CSV format
export async function readNewCSVLogEntries(filePath: string, filePosition: FilePosition): Promise<LogEntry[]> {
	try {
		// Check if file exists
		if (!fs.existsSync(filePath)) {
			return [];
		}

		// Read file stats
		const stats = fs.statSync(filePath);

		// If no new data, return empty array
		if (stats.size <= filePosition.getPosition()) {
			return [];
		}

		// Read new data from file
		const fileData = fs.readFileSync(filePath, 'utf-8');
		const currentPosition = filePosition.getPosition();
		const newData = fileData.slice(currentPosition);

		// Update file position
		filePosition.setPosition(stats.size);

		// If no new data, return empty array
		if (!newData.trim()) {
			return [];
		}

		// Parse CSV data directly with headers in the file
		const records = csvParse(newData, {
			columns: true,
			skip_empty_lines: true,
			relax_column_count: true, // Handle potential inconsistencies in CSV
		});

		// Convert CSV records to LogEntry format
		return records.map((record: any) => {
			// Add logging for debugging
			console.log('Processing CSV record:', record['request.url']);
			console.log('record', record);

			// Map CSV fields to the format expected by the detection system
			const request: RequestData = {
				url: record['request.url'] || '',
				method: record['request.method'] || 'GET', // Default to GET if missing
				authorization: record['request.headers.authorization'] || '',
				'user-agent': record['request.headers.user-agent'] || '',
				'x-api-tran-id': record['request.headers.x-api-tran-id'] || '',
				'x-api-type': record['request.headers.x-api-type'] || '',
				'x-csrf-token': record['request.headers.x-csrf-token'] || '',
				cookie: record['request.headers.cookie'] || '',
				'set-cookie': record['request.headers.set_cookie'] || '',
				'content-type': record['request.headers.content-type'] || '',
				'content-length': record['request.headers.content-length'] || '0', // Default to 0 if missing
				body: record['request.body'] || '',
			};

			// Parse request body if it's a JSON string
			try {
				if (request.body && typeof request.body === 'string' && request.body.trim().startsWith('{')) {
					request.body = JSON.parse(request.body);
				}
			} catch (error) {
				console.warn('Failed to parse request body as JSON:', error);
			}

			// Ensure response status is included
			const response: ResponseData = {
				'x-api-tran-id': record['response.headers.x-api-tran-id'] || '',
				'content-type': record['response.headers.content-type'] || '',
				status: record['response.status'] || '',
				body: record['response.body'] || '',
			};

			// Parse response body if it's a JSON string
			try {
				if (response.body && typeof response.body === 'string' && response.body.trim().startsWith('{')) {
					response.body = JSON.parse(response.body);
				}
			} catch (error) {
				console.warn('Failed to parse response body as JSON:', error);
			}

			// Add response status to response object
			if (record['response.status']) {
				(response as any)['status'] = record['response.status'];
			}

			// Include attack type which may be useful for detection
			if (record['attack.type']) {
				request['attack-type'] = record['attack.type'];
			}

			return {
				request,
				response,
				requestBody: request.body,
				responseBody: response.body,
			};
		});
	} catch (error) {
		console.error('Error reading CSV log entries:', error);
		return [];
	}
}

// Initialize CSV
export async function initializeCSV(filePath: string, header: 'ratelimit' | 'detection'): Promise<void> {
	try {
		let headerArray: any[] = [];
		if (header === 'ratelimit') {
			headerArray = rateLimitCSVLoggerHeader;
		} else {
			headerArray = detectionCSVLoggerHeader;
		}

		// Ensure directory exists
		const dirPath = path.dirname(filePath);
		try {
			if (!fs.existsSync(dirPath)) {
				fs.mkdirSync(dirPath, { recursive: true });
				console.log(`Created directory: ${dirPath}`);
			}
		} catch (dirError) {
			console.error(`Error creating directory ${dirPath}:`, dirError);
			// If we can't create the directory, we can't initialize the CSV
			return;
		}

		if (!fs.existsSync(filePath)) {
			try {
				const csvWriter = createCsvWriter({
					path: filePath,
					header: headerArray,
				});
				await csvWriter.writeRecords([]);
				console.log(`Initialized CSV file: ${filePath}`);
			} catch (error) {
				console.error(`Error initializing CSV file ${filePath}:`, error);
				// Try to create empty file manually if csvWriter fails
				try {
					const headerRow = headerArray.map((h) => h.title).join(',') + '\n';
					fs.writeFileSync(filePath, headerRow);
					console.log(`Manually created CSV file: ${filePath}`);
				} catch (writeError) {
					console.error(`Failed manual creation of ${filePath}:`, writeError);
				}
			}
		}
	} catch (error) {
		console.error(`Error in initializeCSV for ${filePath}:`, error);
	}
}

// Parse log lines
export function parseLogLines(lines: string[]): LogEntry[] {
	return lines
		.filter((line) => line.trim() !== '')
		.map((line) => {
			try {
				return JSON.parse(line);
			} catch (error) {
				console.error(`Error parsing log line: ${error}`);
				return null;
			}
		})
		.filter((entry) => entry !== null);
}

// Logging Function
export async function logDetectionResult(
	entry: LogEntry,
	detectionType: 'signature' | 'specification' | 'hybrid' | 'ratelimit',
	result: DetectionResult
): Promise<void> {
	try {
		const logFilePath = filePath(`/public/${detectionType}_detection_logs.csv`);
		const dirPath = path.dirname(logFilePath);

		// Ensure directory exists
		try {
			if (!fs.existsSync(dirPath)) {
				fs.mkdirSync(dirPath, { recursive: true });
				console.log(`Created directory: ${dirPath}`);
			}
		} catch (dirError) {
			console.error(`Error creating directory ${dirPath}:`, dirError);
			// Continue execution - try to write to file anyway
		}

		if (!fs.existsSync(logFilePath)) {
			try {
				fs.writeFileSync(logFilePath, 'timestamp,detectionType,detected,reason,request,response\n');
				console.log(`Created log file: ${logFilePath}`);
			} catch (fileError) {
				console.error(`Error creating log file ${logFilePath}:`, fileError);
				// If we can't create the file, there's no point in trying to write to it
				return;
			}
		}

		const csvWriter2 = createCsvWriter({
			path: logFilePath,
			append: true,
			header: detectionCSVLoggerHeader,
		});

		const record: LogRecord = {
			timestamp: new Date().toISOString(),
			detectionType: detectionType,
			detected: result.detected,
			reason: result.reason,
			isAttack: result.isAttack,
			request: JSON.stringify(entry.request),
			response: JSON.stringify(entry.response),
		};

		await csvWriter2.writeRecords([record]);
	} catch (error) {
		console.error(`Error logging detection result for ${detectionType}:`, error);
		// Log to an alternative location if the main one failed
		try {
			const fallbackPath = filePath(`/logs/${detectionType}_detection_fallback.json`);
			const fallbackDir = path.dirname(fallbackPath);

			if (!fs.existsSync(fallbackDir)) {
				fs.mkdirSync(fallbackDir, { recursive: true });
			}

			const fallbackData = {
				timestamp: new Date().toISOString(),
				detectionType,
				detected: result.detected,
				reason: result.reason,
				request: JSON.stringify(entry.request),
				response: JSON.stringify(entry.response),
			};

			fs.appendFileSync(fallbackPath, JSON.stringify(fallbackData) + '\n');
			console.log(`Logged to fallback location: ${fallbackPath}`);
		} catch (fallbackError) {
			console.error('Even fallback logging failed:', fallbackError);
		}
	}
}

// CSV writer headers
export const detectionCSVLoggerHeader = [
	{ id: 'timestamp', title: 'timestamp' },
	{ id: 'detectionType', title: 'detectionType' },
	{ id: 'detected', title: 'detected' },
	{ id: 'reason', title: 'reason' },
	{ id: 'isAttack', title: 'isAttack' },
	{ id: 'request', title: 'request' },
	{ id: 'response', title: 'response' },
];

export const rateLimitCSVLoggerHeader = [
	{ id: 'timestamp', title: 'timestamp' },
	{ id: 'detectionType', title: 'detectionType' },
	{ id: 'detected', title: 'detected' },
	{ id: 'reason', title: 'reason' },
	{ id: 'clientId', title: 'clientId' },
	{ id: 'endpoint', title: 'endpoint' },
	{ id: 'requestCount', title: 'requestCount' },
	{ id: 'timeframeStart', title: 'timeframeStart' },
	{ id: 'timeframeEnd', title: 'timeframeEnd' },
];
