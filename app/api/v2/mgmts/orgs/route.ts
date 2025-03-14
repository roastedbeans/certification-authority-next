import { NextRequest, NextResponse } from 'next/server';
import jwt from 'jsonwebtoken';
import { getResponseContent, getResponseMessage } from '@/constants/responseMessages';
import { timestamp } from '@/utils/formatTimestamp';
import { PrismaClient } from '@prisma/client';
import { logger } from '@/utils/generateCSV';

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

	const { searchParams } = new URL(req.url);

	const currentDate = new Date();

	console.log('authorization', authorization);

	searchParams.set('search_timestamp', timestamp(currentDate));
	const searchTimestamp = searchParams.get('search_timestamp');

	const request = {
		method,
		url,
		query,
		headers: headersList,
		body: '',
	};

	try {
		if (!timestamp) {
			const response = getResponseContent({
				headers: {
					contentType: 'application/json;charset=UTF-8',
					xApiTranId: xApiTranId || '',
				},
				body: getResponseMessage('INVALID_PARAMETERS'),
			});
			await logger(JSON.stringify(request), JSON.stringify(response), 400);
			return NextResponse.json(response, { status: 400 });
		}

		if (!authorization || !authorization.startsWith('Bearer ')) {
			const response = getResponseContent({
				headers: {
					contentType: 'application/json;charset=UTF-8',
					xApiTranId: xApiTranId || '',
				},
				body: getResponseMessage('UNAUTHORIZED'),
			});
			await logger(JSON.stringify(request), JSON.stringify(response), 401);
			return NextResponse.json(response, { status: 401 });
		}

		// Extract the token
		const token = authorization.split(' ')[1];
		let decodedToken;

		try {
			decodedToken = jwt.verify(token, JWT_SECRET);
		} catch (error) {
			const response = getResponseContent({
				headers: {
					contentType: 'application/json;charset=UTF-8',
					xApiTranId: xApiTranId || '',
				},
				body: getResponseMessage('INVALID_TOKEN'),
			});
			await logger(JSON.stringify(request), JSON.stringify(response), 403);
			return NextResponse.json(response, { status: 403 });
		}

		// Validate x-api-tran-id
		if (!xApiTranId) {
			const response = getResponseContent({
				headers: {
					contentType: 'application/json;charset=UTF-8',
					xApiTranId: xApiTranId || '',
				},
				body: getResponseMessage('INVALID_API_TRAN_ID'),
			});
			await logger(JSON.stringify(request), JSON.stringify(response), 400);
			return NextResponse.json(response, { status: 400 });
		}

		const organization = await prisma.organization.findMany();

		if (!organization) {
			const response = getResponseContent({
				headers: {
					contentType: 'application/json;charset=UTF-8',
					xApiTranId: xApiTranId || '',
				},
				body: getResponseMessage('NO_ORGANIZATION_FOUND'),
			});
			await logger(JSON.stringify(request), JSON.stringify(response), 404);
			return NextResponse.json(response, { status: 404 });
		}

		const responseData = {
			rsp_code: getResponseMessage('SUCCESS').code,
			rsp_msg: getResponseMessage('SUCCESS').message,
			search_timestamp: searchTimestamp,
			org_cnt: organization.length,
			org_list: organization,
		};

		const response = getResponseContent({
			headers: {
				contentType: 'application/json;charset=UTF-8',
				xApiTranId: xApiTranId || '',
			},
			body: responseData,
		});

		console.log('headers orgs', request.headers);
		await logger(JSON.stringify(request), JSON.stringify(response), 200);

		return NextResponse.json(response, { status: 200 });
	} catch (error) {
		const response = getResponseContent({
			headers: {
				contentType: 'application/json;charset=UTF-8',
				xApiTranId: xApiTranId || '',
			},
			body: getResponseMessage('INTERNAL_SERVER_ERROR'),
		});
		await logger(JSON.stringify(request), JSON.stringify(response), 500);

		return NextResponse.json(response, { status: 500 });
	}
}
