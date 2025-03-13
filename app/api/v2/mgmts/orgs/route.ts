import { NextRequest, NextResponse } from 'next/server';
import jwt from 'jsonwebtoken';
import { getResponseMessage } from '@/constants/responseMessages';
import { PrismaClient } from '@prisma/client';
import { logger } from '@/utils/generateCSV';
import { validateAuthorizationHeader } from '@/utils/validation';

const prisma = new PrismaClient();
const JWT_SECRET = process.env.JWT_SECRET || 'your-secure-secret';

export async function GET(req: NextRequest) {
	const headers = req.headers;
	const headersList = Object.fromEntries(headers.entries());
	const authorization = headers.get('Authorization');
	const xApiTranId = headers.get('x-api-tran-id');
	const method = req.method;
	const url = req.nextUrl.toString();
	const query = Object.fromEntries(req.nextUrl.searchParams);
	const searchTimestamp = query.search_timestamp || '';
	const timestamp = query.timestamp || '';

	const request = {
		method,
		url,
		query,
		headers: headersList,
	};

	try {
		if (!timestamp) {
			const response = NextResponse.json(getResponseMessage('INVALID_PARAMETERS'), { status: 400 });
			await logger(
				JSON.stringify(request),
				JSON.stringify(''),
				JSON.stringify(getResponseMessage('INVALID_PARAMETERS')),
				'400'
			);
			return response;
		}

		if (!validateAuthorizationHeader(authorization)) {
			const response = NextResponse.json(getResponseMessage('UNAUTHORIZED'), { status: 401 });
			await logger(
				JSON.stringify(request),
				JSON.stringify(''),
				JSON.stringify(getResponseMessage('UNAUTHORIZED')),
				'401'
			);
			return response;
		}

		// Extract the token
		const token = authorization!.split(' ')[1];
		let decodedToken;

		try {
			decodedToken = jwt.verify(token, JWT_SECRET);
		} catch (error) {
			const response = NextResponse.json(getResponseMessage('INVALID_TOKEN'), { status: 403 });
			await logger(
				JSON.stringify(request),
				JSON.stringify(''),
				JSON.stringify(getResponseMessage('INVALID_TOKEN')),
				'403'
			);
			return response;
		}

		// Validate x-api-tran-id
		if (!xApiTranId) {
			const response = NextResponse.json(getResponseMessage('INVALID_API_TRAN_ID'), { status: 400 });
			await logger(
				JSON.stringify(request),
				JSON.stringify(''),
				JSON.stringify(getResponseMessage('INVALID_API_TRAN_ID')),
				'400'
			);
			return response;
		}

		const organization = await prisma.organization.findMany();

		if (!organization) {
			const response = NextResponse.json(getResponseMessage('NO_ORGANIZATION_FOUND'), { status: 404 });
			await logger(
				JSON.stringify(request),
				JSON.stringify(''),
				JSON.stringify(getResponseMessage('NO_ORGANIZATION_FOUND')),
				'404'
			);
			return response;
		}

		const responseData = {
			rsp_code: getResponseMessage('SUCCESS').code,
			rsp_msg: getResponseMessage('SUCCESS').message,
			search_timestamp: searchTimestamp,
			org_cnt: organization.length,
			org_list: organization,
		};

		await logger(JSON.stringify(request), JSON.stringify(''), JSON.stringify(responseData), '200');

		return NextResponse.json(responseData, { status: 200 });
	} catch (error) {
		const response = NextResponse.json(getResponseMessage('INTERNAL_SERVER_ERROR'), { status: 500 });
		await logger(
			JSON.stringify(request),
			JSON.stringify(''),
			JSON.stringify(getResponseMessage('INTERNAL_SERVER_ERROR')),
			'500'
		);
		console.error('Error retrieving organizations:', error);
		return response;
	} finally {
		await prisma.$disconnect();
	}
}
