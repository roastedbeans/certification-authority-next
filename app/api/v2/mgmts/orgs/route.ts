import { NextRequest, NextResponse } from 'next/server';
import jwt from 'jsonwebtoken';
import { getResponseMessage } from '@/constants/responseMessages';
import { timestamp } from '@/utils/formatTimestamp';
import { PrismaClient } from '@prisma/client';
import { initializeCsv, logRequestToCsv } from '@/utils/generateCSV';

const prisma = new PrismaClient();
const JWT_SECRET = process.env.JWT_SECRET || 'your-secure-secret';

export async function GET(request: NextRequest) {
	await initializeCsv(); // Ensure the CSV file exists
	const { searchParams } = new URL(request.url);

	const currentDate = new Date();

	searchParams.set('search_timestamp', timestamp(currentDate));
	const searchTimestamp = searchParams.get('search_timestamp');

	try {
		const headers = request.headers;
		const authorization = headers.get('Authorization');
		const xApiTranId = headers.get('x-api-tran-id');

		if (!timestamp || timestamp.length > 14) {
			await logRequestToCsv('manage', JSON.stringify(getResponseMessage('INVALID_PARAMETERS')));
			return NextResponse.json(getResponseMessage('INVALID_PARAMETERS'), { status: 400 });
		}

		if (!authorization || !authorization.startsWith('Bearer ')) {
			await logRequestToCsv('manage', JSON.stringify(getResponseMessage('UNAUTHORIZED')));
			return NextResponse.json(getResponseMessage('UNAUTHORIZED'), { status: 401 });
		}

		// Extract the token
		const token = authorization.split(' ')[1];
		let decodedToken;

		try {
			decodedToken = jwt.verify(token, JWT_SECRET);
		} catch (error) {
			await logRequestToCsv('manage', JSON.stringify(getResponseMessage('INVALID_TOKEN')));
			return NextResponse.json(getResponseMessage('INVALID_TOKEN'), { status: 403 });
		}

		// Validate x-api-tran-id
		if (!xApiTranId || xApiTranId.length > 25) {
			await logRequestToCsv('manage', JSON.stringify(getResponseMessage('INVALID_API_TRAN_ID')));
			return NextResponse.json(getResponseMessage('INVALID_API_TRAN_ID'), { status: 400 });
		}

		const organization = await prisma.organization.findMany();

		if (!organization) {
			await logRequestToCsv('manage', JSON.stringify(getResponseMessage('NO_ORGANIZATION_FOUND')));
			return NextResponse.json(getResponseMessage('NO_ORGANIZATION_FOUND'), { status: 404 });
		}

		const responseData = {
			rsp_code: getResponseMessage('SUCCESS').code,
			rsp_msg: getResponseMessage('SUCCESS').message,
			search_timestamp: searchTimestamp,
			org_cnt: organization.length,
			org_list: organization,
		};

		await logRequestToCsv('manage', JSON.stringify(responseData));

		return NextResponse.json(responseData, { status: 200 });
	} catch (error) {
		await logRequestToCsv('manage', JSON.stringify(getResponseMessage('INTERNAL_SERVER_ERROR')));
		console.error('Error in token generation:', error);
		return NextResponse.json(getResponseMessage('INTERNAL_SERVER_ERROR'), { status: 500 });
	}
}
