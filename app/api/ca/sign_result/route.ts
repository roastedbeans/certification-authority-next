// app/api/ca/sign_result/route.ts

import { getResponseMessage } from '@/constants/responseMessages';
import { NextRequest, NextResponse } from 'next/server';
import crypto from 'crypto';
import { createSignatureResponse } from '@/utils/signatureGenerator';

// Types for the request body
interface SignResultRequestBody {
	cert_tx_id: string; // Certificate Authority Transaction ID
	sign_tx_id: string; // Signature Request Transaction ID
}

// Types for API response
interface SignResultResponse {
	status: 'success' | 'error';
	message: string;
	data?: {
		cert_tx_id: string;
		sign_tx_id: string;
	};
}

// Validation functions
const isValidTransactionId = (id: string): boolean => {
	return typeof id === 'string' && id.length <= 40;
};

const validateAuthorizationHeader = (header: string | null): boolean => {
	if (!header) return false;
	const [type, token] = header.split(' ');
	return type === 'Bearer' && !!token;
};

export async function POST(request: NextRequest) {
	try {
		// 1. Validate headers
		const authHeader = request.headers.get('authorization');
		const transactionId = request.headers.get('x-api-tran-id');

		if (!validateAuthorizationHeader(authHeader)) {
			return NextResponse.json(
				{
					rsp_code: '2000',
					rsp_msg: 'Invalid or missing authorization header',
				},
				{ status: 401 }
			);
		}

		if (!transactionId || !isValidTransactionId(transactionId)) {
			return NextResponse.json(getResponseMessage('INVALID_TRANSACTION_ID'), { status: 400 });
		}

		// 2. Parse and validate body
		const body: SignResultRequestBody = await request.json();

		if (!body.cert_tx_id || !isValidTransactionId(body.cert_tx_id)) {
			return NextResponse.json(getResponseMessage('INVALID_CERT_TX_ID'), { status: 400 });
		}

		if (!body.sign_tx_id || !isValidTransactionId(body.sign_tx_id)) {
			return NextResponse.json(getResponseMessage('INVALID_SIGN_TX_ID'), { status: 400 });
		}

		// Generate signature
		const { signed_consent, signed_consent_len } = createSignatureResponse(body.cert_tx_id, body.sign_tx_id);

		const successResponse = {
			rsp_code: getResponseMessage('SUCCESS').code,
			rsp_msg: getResponseMessage('SUCCESS').message,
			signed_consent_cnt: 1,
			signed_consent_list: [
				{
					tx_id: body.cert_tx_id,
					signed_consent: signed_consent, // Base64 encoded signature
				},
			],
			signed_consent_len: signed_consent_len, // Example length
			signed_consent: signed_consent, // Base64 encoded signature
			tx_id: body.cert_tx_id,
		};

		return NextResponse.json(successResponse, {
			status: 200,
			headers: {
				'Content-Type': 'application/json; charset=UTF-8',
			},
		});
	} catch (error) {
		console.error('Error processing sign result:', error);
		return NextResponse.json(
			{
				rsp_code: getResponseMessage('INTERNAL_SERVER_ERROR').code,
				rsp_msg: getResponseMessage('INTERNAL_SERVER_ERROR').message,
				signed_consent_cnt: 0,
				signed_consent_list: [],
				signed_consent_len: 0,
				signed_consent: '',
				tx_id: '',
			},
			{
				status: 500,
				headers: {
					'x-api-tran-id': request.headers.get('x-api-tran-id') || '',
				},
			}
		);
	}
}
