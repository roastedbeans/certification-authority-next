import { createObjectCsvWriter as createCsvWriter } from 'csv-writer';
import fs from 'fs';
import path from 'path';
import { generateTxtFile } from './generateLog';

const csvFilePath = path.resolve(`./ca_formatted_logs.csv`);
// Define CSV headers
const csvHeaders = [
	{ id: 'attack_type', title: 'attack.type' },
	{ id: 'request_url', title: 'request.url' },
	{ id: 'request_method', title: 'request.method' },
	{ id: 'request_authorization', title: 'request.header.authorization' },
	{ id: 'request_user_agent', title: 'request.headers.user-agent' },
	{ id: 'request_x_api_tran_id', title: 'request.header.x-api-tran-id' },
	{ id: 'request_x_api_type', title: 'request.header.x-api-type' },
	{ id: 'request_x_csrf_token', title: 'request.header.x-csrf-token' },
	{ id: 'request_cookie', title: 'request.headers.cookie' },
	{ id: 'request_set_cookie', title: 'request.headers.set_cookie' },
	{ id: 'request_content_type', title: 'request.headers.content-type' },
	{ id: 'request_content_length', title: 'request.headers.content-length' },
	{ id: 'request_body', title: 'request.body' },
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
export const logger = async (
	request: string,
	requestBody: string,
	responseBody: string,
	responseStatusCode: string
) => {
	await initializeCsv(); // Ensure the CSV file exists
	const req = JSON.parse(request);

	const csvWriter = createCsvWriter({
		path: csvFilePath,
		header: csvHeaders,
		append: true, // Append to the existing file
	});

	const requestContent = {
		'attack-type': req?.headers?.['attack-type'] || '',
		url: req?.url || '',
		method: req?.method || '',
		authorization: req?.headers?.authorization || '',
		'user-agent': req?.headers?.['user-agent'] || '',
		'x-api-tran-id': req?.headers?.['x-api-tran-id'] || '',
		'x-api-type': req?.headers?.['x-api-type'] || '',
		'x-csrf-token': req?.headers?.['x-csrf-token'] || '',
		cookie: req?.headers?.cookie || '',
		'content-type': req?.headers?.['content-type'] || '',
		'set-cookie': req?.headers?.['set-cookie'] || '',
		'content-length': req?.headers?.['content-length'] || '',
		body: JSON.parse(requestBody),
	};

	const responseContent = {
		'x-api-tran-id': req?.headers?.['x-api-tran-id'] || '',
		body: JSON.parse(responseBody),
	};

	const stringRequestContent = JSON.stringify(requestContent);
	const stringResponseContent = JSON.stringify(responseContent);

	generateTxtFile('./requests_responses.txt', { request: stringRequestContent, response: stringResponseContent });

	await csvWriter.writeRecords([
		{
			attack_type: req?.headers?.['attack-type'] || '',
			request_url: req?.url || '',
			request_method: req?.method || '',
			request_authorization: req?.headers?.authorization || '',
			request_user_agent: req?.headers?.['user-agent'] || '',
			request_x_api_tran_id: req?.headers?.['x-api-tran-id'] || '',
			request_x_api_type: req?.headers?.['x-api-type'] || '',
			request_x_csrf_token: req?.headers?.['x-csrf-token'] || '',
			request_cookie: req?.headers?.cookie || '',
			request_set_cookie: req?.headers?.['set-cookie'] || '',
			request_content_type: req?.headers?.['content-type'] || '',
			request_content_length: req?.headers?.['content-length'] || '',
			request_body: JSON.stringify(requestBody),
			response_body: JSON.stringify(responseBody),
			response_status: responseStatusCode,
		},
	]);
};
