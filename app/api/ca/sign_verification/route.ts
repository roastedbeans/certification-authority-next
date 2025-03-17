// app/api/ca/sign_verification/route.ts

import { getResponseContent, getResponseMessage } from '@/constants/responseMessages';
import { NextRequest, NextResponse } from 'next/server';
import { PrismaClient } from '@prisma/client';
import { logger } from '@/utils/generateCSV';

const prisma = new PrismaClient();

const validateAuthorizationHeader = (header: string | null): boolean => {
	if (!header) return false;
	const [type, token] = header.split(' ');
	return type === 'Bearer' && !!token;
};

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
		body,
	};

	try {
		if (!validateAuthorizationHeader(authorization)) {
			const response = getResponseContent({
				headers: {
					xApiTranId: xApiTranId || '',
					contentType: 'application/json;charset=UTF-8',
				},
				body: getResponseMessage('UNAUTHORIZED'),
			});
			await logger(JSON.stringify(request), JSON.stringify(response), 401);
			return NextResponse.json(response, { status: 401 });
		}

		// Validate x-api-tran-id
		if (!xApiTranId || xApiTranId.length > 25) {
			const response = getResponseContent({
				headers: {
					xApiTranId: xApiTranId || '',
					contentType: 'application/json;charset=UTF-8',
				},
				body: getResponseMessage('INVALID_API_TRAN_ID'),
			});
			await logger(JSON.stringify(request), JSON.stringify(response), 400);
			return NextResponse.json(response, { status: 400 });
		}

		if (!cert_tx_id || cert_tx_id.length > 40) {
			const response = getResponseContent({
				headers: {
					xApiTranId: xApiTranId || '',
					contentType: 'application/json;charset=UTF-8',
				},
				body: getResponseMessage('INVALID_CERT_TX_ID'),
			});
			await logger(JSON.stringify(request), JSON.stringify(response), 400);
			return NextResponse.json(response, { status: 400 });
		}

		if (!tx_id || tx_id.length > 74) {
			const response = getResponseContent({
				headers: {
					contentType: 'application/json;charset=UTF-8',
					xApiTranId: xApiTranId || '',
				},
				body: getResponseMessage('INVALID_TX_ID'),
			});
			await logger(JSON.stringify(request), JSON.stringify(response), 400);
			return NextResponse.json(response, { status: 400 });
		}

		if (!signed_consent_len || !signed_consent || !consent_type || !consent_len || !consent) {
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

		const response = getResponseContent({
			headers: {
				xApiTranId: xApiTranId || '',
				contentType: 'application/json;charset=UTF-8',
			},
			body: responseData,
		});

		await logger(JSON.stringify(request), JSON.stringify(response), 200);

		return NextResponse.json(response);
	} catch (error) {
		const response = getResponseContent({
			headers: {
				xApiTranId: xApiTranId || '',
				contentType: 'application/json;charset=UTF-8',
			},
			body: getResponseMessage('INTERNAL_SERVER_ERROR'),
		});
		await logger(JSON.stringify(request), JSON.stringify(response), 500);
		console.error('Error processing sign result:', error);
		return NextResponse.json(response, { status: 500 });
	}
}
