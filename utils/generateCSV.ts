import { createObjectCsvWriter as createCsvWriter } from 'csv-writer';
import fs from 'fs';
import path from 'path';

const csvFIlePath = path.join(process.cwd(), '/public/ca_formatted_logs.csv');
const csvFilePath = path.resolve(csvFIlePath);
// Define CSV headers
const csvHeaders = [
	{ id: 'timestamp', title: 'timestamp' },
	{ id: 'attack_type', title: 'attack.type' },
	{ id: 'request_url', title: 'request.url' },
	{ id: 'request_method', title: 'request.method' },
	{ id: 'request_authorization', title: 'request.headers.authorization' },
	{ id: 'request_user_agent', title: 'request.headers.user-agent' },
	{ id: 'request_x_api_tran_id', title: 'request.headers.x-api-tran-id' },
	{ id: 'request_x_api_type', title: 'request.headers.x-api-type' },
	{ id: 'request_x_csrf_token', title: 'request.headers.x-csrf-token' },
	{ id: 'request_cookie', title: 'request.headers.cookie' },
	{ id: 'request_set_cookie', title: 'request.headers.set_cookie' },
	{ id: 'request_content_type', title: 'request.headers.content-type' },
	{ id: 'request_content_length', title: 'request.headers.content-length' },
	{ id: 'request_body', title: 'request.body' },
	{ id: 'response_x_api_tran_id', title: 'response.headers.x-api-tran-id' },
	{ id: 'response_content_type', title: 'response.headers.content-type' },
	{ id: 'response_body', title: 'response.body' },
	{ id: 'response_status', title: 'response.status' },
];

// Initialize CSV file with headers if it doesn't exist
export const initializeCsv = async () => {
	if (!fs.existsSync(csvFilePath)) {
		const csvWriter = createCsvWriter({
			path: csvFilePath,
			header: csvHeaders,
		});
		await csvWriter.writeRecords([]); // Write empty records to create the file with headers
	}
};

// Append a new request to the CSV file
export const logger = async (request: string, response: string, status: number) => {
	await initializeCsv(); // Ensure the CSV file exists
	const req = JSON.parse(request);
	const res = JSON.parse(response);

	const csvWriter = createCsvWriter({
		path: csvFilePath,
		header: csvHeaders,
		append: true, // Append to the existing file
	});

	// Format request and response data for the detection system
	let formattedRequestBody = req?.body;
	let formattedResponseBody = res?.body;

	// Ensure request and response bodies are properly formatted as strings
	try {
		// If already a string representation of JSON, keep as is
		// Otherwise, stringify the object
		if (typeof res?.body === 'object') {
			formattedRequestBody = JSON.stringify(req.body);
		}

		if (typeof res?.body === 'object') {
			formattedResponseBody = JSON.stringify(res.body);
		}
	} catch (error) {
		console.error('Error formatting request/response bodies:', error);
	}

	console.log('formattedRequestBody', formattedRequestBody);

	await csvWriter.writeRecords([
		{
			timestamp: new Date().toISOString(),
			attack_type: req?.headers?.['attack-type'] || '',
			request_url: req?.url || '',
			request_method: req?.method || '',
			request_authorization: req?.headers?.['authorization'] || '',
			request_user_agent: req?.headers?.['user-agent'] || '',
			request_x_api_tran_id: req?.headers?.['x-api-tran-id'] || '',
			request_x_api_type: req?.headers?.['x-api-type'] || '',
			request_x_csrf_token: req?.headers?.['x-csrf-token'] || '',
			request_cookie: req?.headers?.cookie || '',
			request_set_cookie: req?.headers?.['set-cookie'] || '',
			request_content_type: req?.headers?.['content-type'] || '',
			request_content_length: req?.headers?.['content-length'] || '',
			request_body: formattedRequestBody,
			response_x_api_tran_id: res?.headers?.xApiTranId || '',
			response_content_type: res?.headers?.contentType || '',
			response_status: status || '',
			response_body: formattedResponseBody,
		},
	]);
};
