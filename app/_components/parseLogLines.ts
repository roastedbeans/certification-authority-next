import * as fs from 'fs';
import { createObjectCsvWriter as createCsvWriter } from 'csv-writer';

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

export type LogEntry = {
	request: RequestData;
	response: ResponseData;
	requestBody?: any;
	responseBody?: any;
};

// File Position Tracker
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

export function parseLogLines(lines: string[]): LogEntry[] {
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

// Log Processing Functions
export async function readNewLogEntries(filePath: string, filePosition: FilePosition): Promise<LogEntry[]> {
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

// CSV Logger Configuration
const detectionCSVLoggerHeader = [
	{ id: 'timestamp', title: 'Timestamp' },
	{ id: 'detectionType', title: 'Detection Type' },
	{ id: 'detected', title: 'Attack Detected' },
	{ id: 'reason', title: 'Detection Reason' },
	{ id: 'request', title: 'Request' },
	{ id: 'response', title: 'Response' },
];

// Initialize CSV
export async function initializeCSV(filePath: string): Promise<void> {
	if (!fs.existsSync(filePath)) {
		const csvWriter = createCsvWriter({
			path: filePath,
			header: detectionCSVLoggerHeader,
		});
		await csvWriter.writeRecords([]);
	}
}
