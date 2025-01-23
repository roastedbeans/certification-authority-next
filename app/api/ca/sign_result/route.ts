// app/api/ca/sign_result/route.ts

import { getResponseMessage } from '@/constants/responseMessages';
import { NextRequest, NextResponse } from 'next/server';
import { createSignedConsentList } from '@/utils/signatureGenerator';
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

// Types for the request body
interface SignResultRequestBody {
	cert_tx_id: string; // Certificate Authority Transaction ID
	sign_tx_id: string; // Signature Request Transaction ID
}

const validateAuthorizationHeader = (header: string | null): boolean => {
	if (!header) return false;
	const [type, token] = header.split(' ');
	return type === 'Bearer' && !!token;
};

export async function POST(request: NextRequest) {
	try {
		// 1. Validate headers
		const authHeader = request.headers.get('authorization');
		const xApiTranId = request.headers.get('x-api-tran-id');

		if (!validateAuthorizationHeader(authHeader)) {
			return NextResponse.json(
				{
					rsp_code: '2000',
					rsp_msg: 'Invalid or missing authorization header',
				},
				{ status: 401 }
			);
		}

		// Validate x-api-tran-id
		if (!xApiTranId || xApiTranId.length > 25) {
			return NextResponse.json(getResponseMessage('INVALID_API_TRAN_ID'), { status: 400 });
		}

		// 2. Parse and validate body
		const body: SignResultRequestBody = await request.json();
		const { cert_tx_id, sign_tx_id } = body;

		if (!cert_tx_id || cert_tx_id.length !== 40) {
			return NextResponse.json(getResponseMessage('INVALID_CERT_TX_ID'), { status: 400 });
		}

		if (!sign_tx_id || sign_tx_id.length !== 49) {
			return NextResponse.json(getResponseMessage('INVALID_SIGN_TX_ID'), { status: 400 });
		}

		// 3. Fetch consent list from the database
		const certificate = await prisma.certificate.findUnique({
			where: {
				certTxId: cert_tx_id,
			},
			select: {
				id: true,
				signTxId: true,
				consentList: true,
			},
		});

		if (!certificate) {
			return NextResponse.json(getResponseMessage('NO_CERTIFICATE_FOUND'), { status: 404 });
		}

		// 4. Check if sign_tx_id matches the certificate sign_tx_id
		if (certificate.signTxId !== sign_tx_id) {
			return NextResponse.json(getResponseMessage('INVALID_SIGN_TX_ID'), { status: 400 });
		}

		const privateKey = process.env.CA_PRIVATE_KEY || 'certification-authority-private-key';

		const signedConsentList = createSignedConsentList(certificate.consentList, privateKey);
		console.log('Signed consent list:', signedConsentList);

		const updateCertificate = await prisma.signedConsent.updateMany({
			where: {
				certificateId: certificate.id,
			},
			data: [signedConsentList],
		});

		console.log('Certificate updated with signature:', updateCertificate);

		const successResponse = {
			rsp_code: getResponseMessage('SUCCESS').code,
			rsp_msg: getResponseMessage('SUCCESS').message,
			signed_consent_list: signedConsentList,
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
			},
			{ status: 500 }
		);
	}
}
