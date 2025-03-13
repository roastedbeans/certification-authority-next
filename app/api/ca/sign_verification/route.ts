// app/api/ca/sign_result/route.ts

import { NextRequest, NextResponse } from 'next/server';
import { getResponseMessage } from '@/constants/responseMessages';
import { PrismaClient } from '@prisma/client';
import { logger } from '@/utils/generateCSV';
import { validateAuthorizationHeader } from '@/utils/validation';

const prisma = new PrismaClient();

export async function POST(req: NextRequest) {
	const headers = req.headers;
	const headersList = Object.fromEntries(headers.entries());
	const authorization = headers.get('Authorization');
	const xApiTranId = headers.get('x-api-tran-id');
	const method = req.method;
	const url = req.nextUrl.toString();
	const query = Object.fromEntries(req.nextUrl.searchParams);
	const body = await req.json();

	const { cert_tx_id, tx_id, signed_consent_len, signed_consent, consent_type, consent_len, consent } = body;

	const request = {
		method,
		url,
		query,
		headers: headersList,
	};

	try {
		if (!validateAuthorizationHeader(authorization)) {
			const response = NextResponse.json(getResponseMessage('UNAUTHORIZED'), { status: 401 });
			await logger(
				JSON.stringify(request),
				JSON.stringify(body),
				JSON.stringify(getResponseMessage('UNAUTHORIZED')),
				'401'
			);
			return response;
		}

		// Validate x-api-tran-id
		if (!xApiTranId || xApiTranId.length > 25) {
			const response = NextResponse.json(getResponseMessage('INVALID_API_TRAN_ID'), { status: 400 });
			await logger(
				JSON.stringify(request),
				JSON.stringify(body),
				JSON.stringify(getResponseMessage('INVALID_API_TRAN_ID')),
				'400'
			);
			return response;
		}

		if (!cert_tx_id || cert_tx_id.length > 40) {
			const response = NextResponse.json(getResponseMessage('INVALID_CERT_TX_ID'), { status: 400 });
			await logger(
				JSON.stringify(request),
				JSON.stringify(body),
				JSON.stringify(getResponseMessage('INVALID_CERT_TX_ID')),
				'400'
			);
			return response;
		}

		if (!tx_id || tx_id.length > 74) {
			const response = NextResponse.json(getResponseMessage('INVALID_TX_ID'), { status: 400 });
			await logger(
				JSON.stringify(request),
				JSON.stringify(body),
				JSON.stringify(getResponseMessage('INVALID_TX_ID')),
				'400'
			);
			return response;
		}

		if (!signed_consent_len || !signed_consent || !consent_type || !consent_len || !consent) {
			const response = NextResponse.json(getResponseMessage('INVALID_PARAMETERS'), { status: 400 });
			await logger(
				JSON.stringify(request),
				JSON.stringify(body),
				JSON.stringify(getResponseMessage('INVALID_PARAMETERS')),
				'400'
			);
			return response;
		}

		const account = await prisma.certificate.findFirst({
			where: {
				certTxId: cert_tx_id,
			},
			select: {
				id: true,
				userCI: true,
			},
		});

		let result = false;
		let user_ci = '';

		if (account) {
			result = true;
			user_ci = account.userCI;
		}

		const responseData = {
			tx_id: tx_id,
			rsp_code: getResponseMessage('SUCCESS').code,
			rsp_msg: getResponseMessage('SUCCESS').message,
			result: result,
			user_ci: user_ci,
		};

		await logger(JSON.stringify(request), JSON.stringify(body), JSON.stringify(responseData), '200');

		return NextResponse.json(responseData, { status: 200 });
	} catch (error) {
		const response = NextResponse.json(getResponseMessage('INTERNAL_SERVER_ERROR'), { status: 500 });
		await logger(
			JSON.stringify(request),
			JSON.stringify(body),
			JSON.stringify(getResponseMessage('INTERNAL_SERVER_ERROR')),
			'500'
		);
		console.error('Error in processing request:', error);
		return response;
	}
}
