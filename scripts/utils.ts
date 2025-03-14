import fs from 'fs';
import path from 'path';

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
	request: RequestData;
	response: ResponseData;
}

export interface DetectionResult {
	detected: boolean;
	reason: string;
}

export interface LogRecord {
	timestamp: string;
	detectionType: 'Signature' | 'Specification' | 'Hybrid';
	detected: boolean;
	reason: string;
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

// Read new log entries with better error handling
export async function readNewLogEntries(logFilePath: string, filePosition: FilePosition): Promise<LogEntry[]> {
	try {
		// Ensure log file exists
		ensureSampleLogFile(logFilePath);

		const stats = fs.statSync(logFilePath);
		const fileSize = stats.size;

		if (filePosition.getPosition() >= fileSize) {
			return []; // No new data
		}

		const data = fs.readFileSync(logFilePath, 'utf8');
		const lines = data.substring(filePosition.getPosition()).split('\n');

		filePosition.setPosition(fileSize);

		return parseLogLines(lines);
	} catch (error) {
		console.error(`Error reading log entries: ${error}`);
		return [];
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

// Helper to ensure CSV file exists
export async function ensureLogFile(csvPath: string, headers: string): Promise<void> {
	const dir = path.dirname(csvPath);

	// Ensure directory exists
	if (!fs.existsSync(dir)) {
		fs.mkdirSync(dir, { recursive: true });
	}

	// Create CSV with headers if it doesn't exist
	if (!fs.existsSync(csvPath)) {
		fs.writeFileSync(csvPath, headers);
		console.log(`Created log file at ${csvPath}`);
	}
}

// CSV writer headers
export const detectionCSVLoggerHeader = [
	{ id: 'timestamp', title: 'timestamp' },
	{ id: 'detectionType', title: 'detectionType' },
	{ id: 'detected', title: 'detected' },
	{ id: 'reason', title: 'reason' },
	{ id: 'request', title: 'request' },
	{ id: 'response', title: 'response' },
];
