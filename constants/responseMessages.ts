// app/api/constants/responseMessages.ts

export interface ResponseData {
	headers: {
		contentType: string;
		xApiTranId: string;
	};
	body: any;
}
export interface ResponseMessage {
	code: string;
	message: string;
}

export const ResponseCodes = {
	// Success codes (0000-0999)
	SUCCESS: {
		code: '0000',
		message: 'Success',
	},
	SUCCESS_WITH_NO_DATA: {
		code: '0001',
		message: 'Success but no data found',
	},

	// Authentication/Authorization errors (1000-1999)
	INVALID_TOKEN: {
		code: '1000',
		message: 'Invalid or expired access token',
	},
	UNAUTHORIZED: {
		code: '1001',
		message: 'Unauthorized access',
	},
	MISSING_TOKEN: {
		code: '1002',
		message: 'Access token is missing',
	},
	INVALID_API_TRAN_ID: {
		code: '1003',
		message: 'Invalid or missing x-api-tran-id',
	},
	NO_CERTIFICATE_FOUND: {
		code: '1004',
		message: 'No certificate found',
	},

	// Validation errors (2000-2999)
	INVALID_PARAMETERS: {
		code: '2000',
		message: 'Invalid parameters provided',
	},
	MISSING_REQUIRED_FIELD: {
		code: '2001',
		message: 'Required field is missing',
	},
	INVALID_TRANSACTION_ID: {
		code: '2002',
		message: 'Invalid transaction ID format',
	},
	INVALID_CERT_TX_ID: {
		code: '2003',
		message: 'Invalid certificate transaction ID',
	},
	INVALID_SIGN_TX_ID: {
		code: '2004',
		message: 'Invalid signature transaction ID',
	},
	INVALID_TX_ID: {
		code: '2005',
		message: 'Invalid transaction ID',
	},

	// Business logic errors (3000-3999)
	SIGNATURE_GENERATION_FAILED: {
		code: '3000',
		message: 'Failed to generate electronic signature',
	},
	INVALID_SIGNATURE_FORMAT: {
		code: '3001',
		message: 'Invalid signature format',
	},
	DUPLICATE_TRANSACTION: {
		code: '3002',
		message: 'Duplicate transaction detected',
	},

	// Data not found errors (4000-4999)
	NO_ORGANIZATION_FOUND: {
		code: '4000',
		message: 'No organization found',
	},

	// System errors (9000-9999)
	INTERNAL_SERVER_ERROR: {
		code: '9000',
		message: 'Internal server error',
	},
	DATABASE_ERROR: {
		code: '9001',
		message: 'Database operation failed',
	},
	EXTERNAL_SERVICE_ERROR: {
		code: '9002',
		message: 'External service unavailable',
	},
} as const;

// Helper function to get response message with optional details
export function getResponseMessage(code: keyof typeof ResponseCodes, details?: string): ResponseMessage {
	const response = ResponseCodes[code];
	return {
		code: response.code,
		message: details ? `${response.message}: ${details}` : response.message,
	};
}

export function getResponseContent({ headers, body }: ResponseData): ResponseData {
	return {
		headers,
		body,
	};
}
