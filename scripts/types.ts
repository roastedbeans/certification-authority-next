/**
 * Type definitions for the certification authority system
 */

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
	'x-forwarded-for'?: string;
	body: string;
	[key: string]: string | undefined; // Allow both string and undefined values
}

export interface ResponseData {
	body: string;
	[key: string]: string | undefined; // Allow both string and undefined values
}

export interface LogEntry {
	request: RequestData;
	response: ResponseData;
	requestBody?: any;
	responseBody?: any;
}

export interface DetectionResult {
	detected: boolean;
	reason: string;
}

export interface LogRecord {
	timestamp: string;
	detectionType: 'Specification' | 'RateLimit';
	detected: boolean;
	reason: string;
	request: string;
	response: string;
}
