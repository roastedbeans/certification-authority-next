import { createObjectCsvWriter as createCsvWriter } from 'csv-writer';
import fs from 'fs';
import path from 'path';
import { z } from 'zod';

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
}

interface ResponseData {
	body: string;
}

interface LogEntry {
	request: RequestData;
	response: ResponseData;
	parsedRequestBody?: any;
	parsedResponseBody?: any;
}

const detectionCSVLoggerHeader = [
	{ id: 'timestamp', title: 'Timestamp' },
	{ id: 'detected', title: 'Detected' },
	{ id: 'request', title: 'Request' },
	{ id: 'response', title: 'Response' },
];

// Initialize CSV file with headers if it doesn't exist
const initializeCsv = async (csvFilePath: string) => {
	try {
		if (!fs.existsSync(csvFilePath)) {
			console.log(`Initializing CSV file at ${csvFilePath}`);
			const csvWriter = createCsvWriter({
				path: csvFilePath,
				header: detectionCSVLoggerHeader,
			});
			await csvWriter.writeRecords([]); // Write empty records to create the file with headers
			console.log('CSV file initialized successfully');
		} else {
			console.log(`CSV file already exists at ${csvFilePath}`);
		}
	} catch (error) {
		console.error('Error initializing CSV file:', error);
		throw error;
	}
};

// Class to keep track of file position
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

async function processNewLines(
	filePath: string,
	filePosition: FilePosition,
	detectionMethod: (entry: LogEntry) => boolean
): Promise<void> {
	try {
		const fileSize = fs.statSync(filePath).size;
		if (fileSize <= filePosition.getPosition()) {
			console.log('No new content to process', fileSize, fs.statSync(filePath));
			return; // No new content
		}

		const stream = fs.createReadStream(filePath, {
			start: filePosition.getPosition(),
			encoding: 'utf-8',
		});

		let buffer = '';

		for await (const chunk of stream) {
			buffer += chunk;
			const lines = buffer.split('\n');

			// Keep the last partial line in buffer
			buffer = lines.pop() || '';

			// Process all lines together to catch pairs that might span multiple lines
			const content = lines.join('\n');

			await processLogLine(content, detectionMethod);
		}

		filePosition.setPosition(fileSize);
	} catch (error) {
		console.error('Error processing new lines:', error);
	}
}

async function processLogLine(content: string, detectionMethod: (entry: LogEntry) => boolean): Promise<void> {
	try {
		// Pattern to match: ||[timestamp] request{} response{}
		const logPattern = /\|\|\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]\s\[request\s({.*?})\]\s\[response\s({.*?}})\]/g;

		const matches = content.matchAll(logPattern);
		const recordsToWrite = [];

		for (const match of matches) {
			const timestamp = match[1];
			const requestStr = match[2];
			const responseStr = match[3];

			if (!requestStr || !responseStr) {
				console.error('Incomplete log entry, skipping...');
				continue;
			}
			// Parse request and response JSON
			const request = JSON.parse(requestStr);
			const response = JSON.parse(responseStr);

			const parsedRequestBody = request.body;
			const parsedResponseBody = response.body;

			const entry: LogEntry = {
				request,
				response,
				parsedRequestBody,
				parsedResponseBody,
			};

			// Check if this entry indicates an intrusion
			const detected = detectionMethod(entry);

			recordsToWrite.push({
				timestamp: new Date().toISOString(),
				detected: detected,
				request: requestStr,
				response: responseStr,
			});

			if (detected) {
				console.log(`[${timestamp}] Intrusion detected!`);
				console.log('Entry:', JSON.stringify(entry, null, 2));
			}
		}

		if (recordsToWrite.length > 0) {
			console.log(`Writing ${recordsToWrite.length} records to CSV...`);
			// Create CSV writer with append mode
			const csvWriter = createCsvWriter({
				path: './ca_detection_logs.csv',
				append: true,
				header: detectionCSVLoggerHeader,
			});

			try {
				await csvWriter.writeRecords(recordsToWrite);
				console.log('CSV write completed successfully');
			} catch (csvError) {
				console.error('Error writing to CSV:', csvError);
			}
		}
	} catch (error) {
		console.error('Error processing log line:', error);
	}
}

async function startPeriodicDetection(
	filePath: string,
	detectionMethod: (entry: LogEntry) => boolean,
	intervalMs: number = 5000
): Promise<void> {
	try {
		// Initialize CSV file
		await initializeCsv('./ca_detection_logs.csv');

		// Initialize file position tracker
		const filePosition = new FilePosition();

		// Process existing content first
		await processNewLines(filePath, filePosition, detectionMethod);

		console.log(`Starting periodic detection every ${intervalMs}ms for ${filePath}...`);
		console.log(`Initial file size: ${fs.statSync(filePath).size} bytes`);

		// Set up interval for periodic checking
		const runDetectionCycle = async () => {
			console.log(`[${new Date().toISOString()}] Running detection cycle...`);
			try {
				await processNewLines(filePath, filePosition, detectionMethod);
				console.log(`[${new Date().toISOString()}] Detection cycle completed`);
			} catch (error) {
				console.error('Error in detection cycle:', error);
			}
		};

		// Run immediately and then set up interval
		await runDetectionCycle();
		setInterval(runDetectionCycle, intervalMs);
	} catch (error) {
		console.error('Error in periodic detection:', error);
		// Attempt to restart after a delay
		setTimeout(() => startPeriodicDetection(filePath, detectionMethod, intervalMs), intervalMs);
	}
}

// Default Headers Schemas
const defaultRequestHeadersSchema = z.object({
	'content-type': z.string().max(50).toLowerCase(),
	// user-agent accepted values: Mozilla, Chrome, Safari, Edge, Opera, Firefox
	'user-agent': z
		.string()
		.max(50)
		.refine((val) => /(Mozilla|Chrome|Safari|Edge|Opera|Firefox)/.test(val)),
	cookie: z.string().max(0),
	'set-cookie': z.string().max(0),
	'x-csrf-token': z.string().max(0),
	'x-api-tran-id': z
		.string()
		.max(25, 'Must be at most 25 characters long')
		.refine((str) => str.length >= 25, {
			message: 'Must be exactly 25 characters long',
		})
		.refine((str) => ['M', 'S', 'R', 'C', 'P', 'A'].includes(str.charAt(10)), {
			message: "11th character must be one of 'M', 'S', 'R', 'C', 'P', or 'A' (subject classification code)",
		})
		.refine(
			(str) =>
				str
					.slice(11)
					.split('')
					.every((char) => /[A-Z0-9]/.test(char)),
			{
				message: 'Last 14 characters must be uppercase letters or numbers',
			}
		),
	'x-api-type': z.string().max(0),
	authorization: z.string().max(1500),
});

const defaultResponseHeadersSchema = z.object({
	'x-api-tran-id': z
		.string()
		.max(25, 'Must be at most 25 characters long')
		.refine((str) => str.length >= 25, {
			message: 'Must be exactly 25 characters long',
		})
		.refine((str) => ['M', 'S', 'R', 'C', 'P', 'A'].includes(str.charAt(10)), {
			message: "11th character must be one of 'M', 'S', 'R', 'C', 'P', or 'A' (subject classification code)",
		})
		.refine(
			(str) =>
				str
					.slice(11)
					.split('')
					.every((char) => /[A-Z0-9]/.test(char)),
			{
				message: 'Last 14 characters must be uppercase letters or numbers',
			}
		),
});

// API Specifications
type ApiSchemas = Record<string, Record<string, { request: z.ZodType<any>; response: z.ZodType<any> }>>;

export const apiSchemas: ApiSchemas = {
	'/api/v2/mgmts/oauth/2.0/token': {
		POST: {
			request: z.object({
				headers: defaultRequestHeadersSchema.extend({
					'content-type': z
						.string()
						.max(50)
						.toLowerCase()
						.refine((val) => val === 'application/x-www-form-urlencoded'),
				}),
				body: z.object({
					grant_type: z
						.string()
						.max(18)
						.refine((val) => val === 'client_credentials'),
					client_id: z.string().max(50),
					client_secret: z.string().max(50),
					scope: z
						.string()
						.max(6)
						.refine((val) => val === 'manage'),
				}),
			}),
			response: z.object({
				headers: defaultResponseHeadersSchema,
				body: z.object({
					token_type: z
						.string()
						.max(6)
						.refine((val) => val === 'Bearer'),
					access_token: z.string().max(1500),
					expires_in: z.number().max(999999999),
					scope: z
						.string()
						.max(6)
						.refine((val) => val === 'manage'),
					timestamp: z.string().max(50),
					rsp_code: z.string().max(30),
					rsp_msg: z.string().max(450),
				}),
			}),
		},
	},
	'/api/v2/mgmts/orgs': {
		GET: {
			request: z.object({
				headers: defaultRequestHeadersSchema.extend({
					// find the search param search_timestamp
					url: z
						.string()
						.max(80)
						.refine((val) => new URL(val).searchParams.has('search_timestamp')),
				}),
			}),
			response: z.object({
				headers: defaultResponseHeadersSchema,
				body: z.object({
					rsp_code: z.string().max(30),
					rsp_msg: z.string().max(450),
					search_timestamp: z.string().max(14),
					org_cnt: z.number().max(999),
					org_list: z.array(z.object({})),
				}),
			}),
		},
	},
	'/api/oauth/2.0/token': {
		POST: {
			request: z.object({
				headers: defaultRequestHeadersSchema.extend({
					'content-type': z
						.string()
						.max(50)
						.toLowerCase()
						.refine((val) => val === 'application/x-www-form-urlencoded'),
				}),
				body: z.object({
					grant_type: z
						.string()
						.max(18)
						.toLowerCase()
						.refine((val) => val === 'client_credentials'),
					client_id: z.string().max(50),
					client_secret: z.string().max(50),
					scope: z
						.string()
						.max(6)
						.toLowerCase()
						.refine((val) => val === 'ca'),
				}),
			}),
			response: z.object({
				headers: defaultResponseHeadersSchema,
				body: z.object({
					token_type: z
						.string()
						.max(6)
						.refine((val) => val === 'Bearer'),
					access_token: z.string().max(1500),
					expires_in: z.number().max(999999999),
					scope: z
						.string()
						.max(6)
						.toLowerCase()
						.refine((val) => val === 'ca'),
				}),
			}),
		},
	},

	'/api/ca/sign_request': {
		POST: {
			request: z.object({
				headers: defaultRequestHeadersSchema,
				body: z.object({
					//sign_tx_id: anya123456_certauth00_20250212081423_bondserial00
					sign_tx_id: z.string().max(49),
					user_ci: z
						.string()
						.max(100)
						.regex(/^[A-Za-z0-9+/]*={0,2}$/),

					real_name: z.string().max(30),
					phone_num: z.string().max(15).startsWith('+82'),
					request_title: z.string().max(120),
					device_code: z.enum(['PC', 'TB', 'MO']),
					device_browser: z.enum(['WB', 'NA', 'HY']),
				}),
			}),
			response: z.object({
				headers: defaultResponseHeadersSchema,
				body: z.object({
					rsp_code: z.string().max(30),
					rsp_msg: z.string().max(450),
					cert_tx_id: z.string().max(40),
				}),
			}),
		},
	},

	'/api/ca/sign_result': {
		POST: {
			request: z.object({
				headers: defaultRequestHeadersSchema,
				body: z.object({
					cert_tx_id: z
						.string()
						.max(40)
						.regex(/^[0-9a-fA-F]+$/),
					sign_tx_id: z.string().max(49),
				}),
			}),
			response: z.object({
				headers: defaultResponseHeadersSchema,
				body: z.object({
					rsp_code: z.string().max(30),
					rsp_msg: z.string().max(450),
					signed_consent_cnt: z.number().max(9999),
					signed_consent_list: z.array(z.object({})),
				}),
			}),
		},
	},

	'/api/accounts/deposit/basic': {
		POST: {
			request: z.object({
				headers: defaultRequestHeadersSchema.extend({
					'content-type': z.string().max(50).toLowerCase(),
				}),
				body: z.object({
					org_code: z.string().max(10),
					account_num: z.string().max(20),
					seqno: z.string().max(7),
					search_timestamp: z.number().max(99999999999999),
				}),
			}),
			response: z.object({
				headers: defaultResponseHeadersSchema,
				body: z.object({
					rsp_code: z.string().max(5),
					rsp_msg: z.string().max(450),
					search_timestamp: z.number().max(99999999999999),
				}),
			}),
		},
	},

	'/api/accounts/deposit/detail': {
		POST: {
			request: z.object({
				headers: defaultRequestHeadersSchema.extend({
					'content-type': z.string().max(50).toLowerCase(),
				}),
				body: z.object({
					org_code: z.string().max(10),
					account_num: z.string().max(20),
					seqno: z.string().max(7),
					search_timestamp: z.number().max(99999999999999),
				}),
			}),
			response: z.object({
				headers: defaultResponseHeadersSchema,
				body: z.object({
					rsp_code: z.string().max(5),
					rsp_msg: z.string().max(450),
					search_timestamp: z.number().max(99999999999999),
					detail_cnt: z.number().max(999),
					detail_list: z.string().max(0),
					currency_code: z
						.string()
						.max(3)
						.toUpperCase()
						.refine((val) => ['KRW', 'USD', 'EUR', 'CNY', 'JPY'].includes(val)),
					Balance_amt: z.number().max(99999999999),
					withdrawable_amt: z.number().max(99999999999),
					offered_rate: z.number().max(9999999),
					last_paid_in_cnt: z.number().max(999999),
				}),
			}),
		},
	},
};

export function specificationBasedDetection(entry: LogEntry): boolean {
	const spec = apiSchemas[new URL(entry.request.url).pathname]?.[entry.request.method];

	if (!spec) {
		console.error('No specification found');
		return false;
	}

	console.log(entry.request);

	try {
		// Validate request
		spec.request.parse({
			headers: entry.request,
			body: entry.parsedRequestBody,
		});

		// Validate response
		spec.response.parse({
			headers: entry.response,
			body: entry.parsedResponseBody,
		});

		return false; // No validation errors
	} catch (error) {
		if (error instanceof z.ZodError) {
			console.log('Validation errors:', error.errors);
			return true; // Validation failed, potential intrusion
		}
		throw error;
	}
}

// Usage example
startPeriodicDetection('./requests_responses.txt', specificationBasedDetection, 5000).catch((error) =>
	console.error('Error starting periodic detection:', error)
);
