import * as fs from 'fs';

interface RequestResponsePair {
	request: string;
	response: string;
}

export function generateTxtFile(filePath: string, data: RequestResponsePair): void {
	const timestamp = formatTimestampWithSeparators();

	const content = `||[${timestamp}] [request ${data.request}] [response ${data.response}]\n`;
	fs.appendFileSync(filePath, content, 'utf-8');
}

function formatTimestampWithSeparators(date: Date = new Date()): string {
	const pad = (num: number): string => num.toString().padStart(2, '0');

	const year = date.getFullYear();
	const month = pad(date.getMonth() + 1);
	const day = pad(date.getDate());
	const hours = pad(date.getHours());
	const minutes = pad(date.getMinutes());
	const seconds = pad(date.getSeconds());

	return `${year}-${month}-${day} ${hours}:${minutes}:${seconds}`;
}
