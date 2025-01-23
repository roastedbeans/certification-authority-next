import { NextRequest, NextResponse } from 'next/server';
import jwt from 'jsonwebtoken';
import { getResponseMessage } from '@/constants/responseMessages';
import { timestamp } from '@/utils/formatTimestamp';
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();
const JWT_SECRET = process.env.JWT_SECRET || 'your-secure-secret';

export async function GET(request: NextRequest) {
	const { searchParams } = new URL(request.url);

	const currentDate = new Date();

	searchParams.set('search_timestamp', timestamp(currentDate));
	const searchTimestamp = searchParams.get('search_timestamp');

	try {
		const headers = request.headers;
		const authorization = headers.get('Authorization');
		const xApiTranId = headers.get('x-api-tran-id');

		if (!timestamp || timestamp.length > 14) {
			return NextResponse.json({ error: 'Invalid or missing timestamp' }, { status: 400 });
		}

		if (!authorization || !authorization.startsWith('Bearer ')) {
			return NextResponse.json(getResponseMessage('UNAUTHORIZED'), { status: 401 });
		}

		// Extract the token
		const token = authorization.split(' ')[1];
		let decodedToken;

		try {
			decodedToken = jwt.verify(token, JWT_SECRET);
		} catch (error) {
			return NextResponse.json(getResponseMessage('INVALID_TOKEN'), { status: 403 });
		}

		// Validate x-api-tran-id
		if (!xApiTranId || xApiTranId.length > 25) {
			return NextResponse.json(getResponseMessage('INVALID_API_TRAN_ID'), { status: 400 });
		}

		const organization = await prisma.organization.findMany();

		if (!organization) {
			return NextResponse.json(getResponseMessage('NO_ORGANIZATION_FOUND'), { status: 404 });
		}

		const message = {
			rsp_code: getResponseMessage('SUCCESS').code,
			rsp_msg: getResponseMessage('SUCCESS').message,
			search_timestamp: searchTimestamp,
			org_cnt: organization.length,
			org_list: organization,
		};

		return NextResponse.json(message, { status: 200 });
	} catch (error) {
		console.error('Error in token generation:', error);
		return NextResponse.json(getResponseMessage('INTERNAL_SERVER_ERROR'), { status: 500 });
	}
}
