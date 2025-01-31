import { faker } from '@faker-js/faker';
import { createObjectCsvWriter as createCsvWriter } from 'csv-writer';
import fs from 'fs';
import path from 'path';

const csvFilePath = path.resolve(`./api_requests_${process.env.CA_CODE}.csv`);

// Initialize CSV file with headers if it doesn't exist
export const initializeCsv = async () => {
	if (!fs.existsSync(csvFilePath)) {
		const csvWriter = createCsvWriter({
			path: csvFilePath,
			header: [
				{ id: 'seq_no', title: 'seq_no' },
				{ id: 'busr', title: 'busr' },
				{ id: 'api_id', title: 'api_id' },
				{ id: 'org_code', title: 'org_code' },
				{ id: 'own_org_code', title: 'own_org_code' },
				{ id: 'ast_id', title: 'ast_id' },
				{ id: 'scope', title: 'scope' },
				{ id: 'res_data', title: 'res_data' },
			],
		});

		await csvWriter.writeRecords([]); // Write empty records to create the file with headers
	}
};

// Get the last seq_no from the CSV file
const getLastSeqNo = async (): Promise<number> => {
	if (!fs.existsSync(csvFilePath)) {
		return 0;
	}

	const fileContent = fs.readFileSync(csvFilePath, 'utf-8');
	const lines = fileContent.split('\n').filter((line) => line.trim() !== '');

	if (lines.length <= 1) {
		return 0; // Only headers are present
	}

	const lastLine = lines[lines.length - 1];
	const lastSeqNo = parseInt(lastLine.split(',')[0], 10);

	return isNaN(lastSeqNo) ? 0 : lastSeqNo;
};

// Append a new request to the CSV file
export const logRequestToCsv = async (scope: string, res_data: string, orgCode?: string) => {
	await initializeCsv(); // Ensure the CSV file exists

	// Get the last seq_no and increment it
	const lastSeqNo = await getLastSeqNo();
	const seqNo = lastSeqNo + 1;

	// Create the new request data
	const requestData = {
		seq_no: seqNo,
		busr: faker.string.alphanumeric(10),
		api_id: faker.string.alphanumeric(10),
		org_code: orgCode as string,
		own_org_code: process.env.CA_CODE as string,
		ast_id: faker.string.alphanumeric(10),
		scope: scope,
		res_data: res_data,
	};

	// Append the new request data to the CSV file
	const csvWriter = createCsvWriter({
		path: csvFilePath,
		header: [
			{ id: 'seq_no', title: 'seq_no' },
			{ id: 'busr', title: 'busr' },
			{ id: 'api_id', title: 'api_id' },
			{ id: 'org_code', title: 'org_code' },
			{ id: 'own_org_code', title: 'own_org_code' },
			{ id: 'ast_id', title: 'ast_id' },
			{ id: 'scope', title: 'scope' },
			{ id: 'res_data', title: 'res_data' },
		],
		append: true, // Append to the existing file
	});

	await csvWriter.writeRecords([requestData]);
};
