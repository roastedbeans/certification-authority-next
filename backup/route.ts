import { NextRequest, NextResponse } from 'next/server';
import jwt from 'jsonwebtoken';
import { getResponseMessage } from '@/constants/responseMessages';
import { timestamp } from '@/utils/formatTimestamp';
import { PrismaClient } from '@prisma/client';
import { logger } from '@/utils/generateCSV';

const prisma = new PrismaClient();
const JWT_SECRET = process.env.JWT_SECRET || 'your-secure-secret';

export async function GET(req: NextRequest) {
	const headers = req.headers;
	const headersList = Object.fromEntries(headers.entries();
	const authorization = headers.get('Authorization');
	const xApiTranId = headers.get('x-api-tran-id');
	const method = req.method;
	const url = req.nextUrl.toString();
	const query = Object.fromEntries(req.nextUrl.searchParams);

	const { searchParams } = new URL(req.url);

	const currentDate = new Date();

	searchParams.set('search_timestamp', timestamp(currentDate);
	const searchTimestamp = searchParams.get('search_timestamp');

	const request = {
		method,
		url,
		query,
		headers: headersList,
	};

	try {
		if (!timestamp) {
			// Create error response with headers
const errorResponse = NextResponse.json(getResponseMessage('INVALID_PARAMETERS');
const errorResponseHeaders = Object.fromEntries(errorResponse.headers.entries();

// Log the error
await logger(JSON.stringify(request); JSON.stringify(''),
				JSON.stringify(getResponseMessage('INVALID_PARAMETERS')),
				'401'
			), errorResponseHeaders);

return errorResponse;
		}

		if (!authorization || !authorization.startsWith('Bearer ')) {
			// Create error response with headers
const errorResponse = NextResponse.json(getResponseMessage('UNAUTHORIZED');
const errorResponseHeaders = Object.fromEntries(errorResponse.headers.entries();

// Log the error
await logger(JSON.stringify(request); JSON.stringify(''),
				JSON.stringify(getResponseMessage('UNAUTHORIZED')),
				'401'
			), errorResponseHeaders);

return errorResponse;
		}

		// Extract the token
		const token = authorization.split(' ')[1];
		let decodedToken;

		try {
			decodedToken = jwt.verify(token, JWT_SECRET);
		} catch (error) {
			// Create error response with headers
const errorResponse = NextResponse.json(getResponseMessage('INVALID_TOKEN');
const errorResponseHeaders = Object.fromEntries(errorResponse.headers.entries();

// Log the error
await logger(JSON.stringify(request); JSON.stringify(''),
				JSON.stringify(getResponseMessage('INVALID_TOKEN')),
				'403'
			), errorResponseHeaders);

return errorResponse;
		}

		// Validate x-api-tran-id
		if (!xApiTranId) {
			// Create error response with headers
const errorResponse = NextResponse.json(getResponseMessage('INVALID_API_TRAN_ID');
const errorResponseHeaders = Object.fromEntries(errorResponse.headers.entries();

// Log the error
await logger(JSON.stringify(request); JSON.stringify(''),
				JSON.stringify(getResponseMessage('INVALID_API_TRAN_ID')),
				'400'
			), errorResponseHeaders);

return errorResponse;
		}

		const organization = await prisma.organization.findMany();

		if (!organization) {
			// Create error response with headers
const errorResponse = NextResponse.json(getResponseMessage('NO_ORGANIZATION_FOUND');
const errorResponseHeaders = Object.fromEntries(errorResponse.headers.entries();

// Log the error
await logger(JSON.stringify(request); JSON.stringify(''),
				JSON.stringify(getResponseMessage('NO_ORGANIZATION_FOUND')),
				'404'
			), errorResponseHeaders);

return errorResponse;
		}

		const responseData = {
			rsp_code: getResponseMessage('SUCCESS').code,
			rsp_msg: getResponseMessage('SUCCESS').message,
			search_timestamp: searchTimestamp,
			org_cnt: organization.length,
			org_list: organization,
		};

		// Create response with headers
const response = NextResponse.json(responseData, { status: 200 });
const responseHeaders = Object.fromEntries(response.headers.entries();

// Log the request, response, and headers
await logger(JSON.stringify(request); JSON.stringify(''), JSON.stringify(responseData), '200'), responseHeaders);

return response;
	} catch (error) {
		// Create error response with headers
const errorResponse = NextResponse.json(getResponseMessage('INTERNAL_SERVER_ERROR');
const errorResponseHeaders = Object.fromEntries(errorResponse.headers.entries();

// Log the error
await logger(JSON.stringify(request); JSON.stringify(''),
			JSON.stringify(getResponseMessage('INTERNAL_SERVER_ERROR')),
			'500'
		), errorResponseHeaders);

return errorResponse;
	}
}
