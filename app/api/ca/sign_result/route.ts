// app/api/ca/sign_result/route.ts

import { getResponseMessage } from '@/constants/responseMessages';
import { NextRequest, NextResponse } from 'next/server';
import { createSignedConsentList } from '@/utils/signatureGenerator';
import { PrismaClient } from '@prisma/client';
import { initializeCsv, logRequestToCsv } from '@/utils/generateCSV';

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

export async function POST(req: NextRequest) {
	await initializeCsv(); // Ensure the CSV file exists
	try {
		// 1. Validate headers
		const authHeader = req.headers.get('authorization');
		const xApiTranId = req.headers.get('x-api-tran-id');

		if (!validateAuthorizationHeader(authHeader)) {
			await logRequestToCsv(
				'ca',
				'unknown',
				JSON.stringify({ req_header: req.headers, req_body: req.body }),
				JSON.stringify(getResponseMessage('UNAUTHORIZED'))
			);
			return NextResponse.json(getResponseMessage('UNAUTHORIZED'), { status: 401 });
		}

		// Validate x-api-tran-id
		if (!xApiTranId || xApiTranId.length > 25) {
			await logRequestToCsv(
				'ca',
				'unknown',
				JSON.stringify({ req_header: req.headers, req_body: req.body }),
				JSON.stringify(getResponseMessage('INVALID_API_TRAN_ID'))
			);
			return NextResponse.json(getResponseMessage('INVALID_API_TRAN_ID'), { status: 400 });
		}

		// 2. Parse and validate body
		const body: SignResultRequestBody = await req.json();
		const { cert_tx_id, sign_tx_id } = body;

		if (!cert_tx_id || cert_tx_id.length !== 40) {
			await logRequestToCsv(
				'ca',
				'unknown',
				JSON.stringify({ req_header: req.headers, req_body: req.body }),
				JSON.stringify(getResponseMessage('INVALID_CERT_TX_ID'))
			);
			return NextResponse.json(getResponseMessage('INVALID_CERT_TX_ID'), { status: 400 });
		}

		if (!sign_tx_id || sign_tx_id.length !== 49) {
			await logRequestToCsv(
				'ca',
				'unknown',
				JSON.stringify({ req_header: req.headers, req_body: req.body }),
				JSON.stringify(getResponseMessage('INVALID_SIGN_TX_ID'))
			);
			return NextResponse.json(getResponseMessage('INVALID_SIGN_TX_ID'), { status: 400 });
		}

		// 3. Fetch consent list from the database
		const certificate = await prisma.certificate.findFirst({
			where: {
				certTxId: cert_tx_id,
			},
			select: {
				id: true,
				signTxId: true,
				consentList: true,
				userId: true,
			},
		});

		if (!certificate) {
			return NextResponse.json(getResponseMessage('NO_CERTIFICATE_FOUND'), { status: 404 });
		}

		// 4. Check if sign_tx_id matches the certificate sign_tx_id
		if (certificate.signTxId !== sign_tx_id) {
			return NextResponse.json(getResponseMessage('INVALID_SIGN_TX_ID'), { status: 400 });
		}

		if (certificate.consentList === null) {
			return NextResponse.json({ rsp_code: 2000, rsp_msg: 'No consent list found' }, { status: 400 });
		}

		const orgCode = sign_tx_id.split('_')[0];
		const caCode = sign_tx_id.split('_')[1];

		const certificateAuthority = await prisma.certificateAuthority.findUnique({
			where: {
				caCode: caCode,
			},
		});

		if (!certificateAuthority) {
			return NextResponse.json(
				{ rsp_code: 2000, rsp_msg: 'Invalid or missing certificate authority' },
				{ status: 400 }
			);
		}

		const consent = await prisma.consent.findMany({
			where: {
				certificateId: certificate.id,
			},
		});

		const signedConsentList = createSignedConsentList(
			consent,
			certificate.userId,
			certificate.id,
			certificateAuthority.privateKey
		);

		for (const signedConsent of signedConsentList) {
			await prisma.signedConsent.create({
				data: signedConsent,
			});
		}

		//format signed consent list
		let signedConsentListFormatted = signedConsentList.map((signedConsent) => {
			return {
				signed_consent_len: signedConsent.signedConsentLen,
				signed_consent: signedConsent.signedConsent,
				tx_id: signedConsent.txId,
				user_id: signedConsent.userId,
				certificate_id: signedConsent.certificateId,
			};
		});

		const responseData = {
			rsp_code: getResponseMessage('SUCCESS').code,
			rsp_msg: getResponseMessage('SUCCESS').message,
			signed_consent_list: signedConsentListFormatted,
		};

		await logRequestToCsv(
			'ca',
			orgCode,
			JSON.stringify({ req_header: req.headers, req_body: req.body }),
			JSON.stringify(responseData)
		);

		return NextResponse.json(responseData, {
			status: 200,
			headers: {
				'Content-Type': 'application/json; charset=UTF-8',
			},
		});
	} catch (error) {
		await logRequestToCsv(
			'ca',
			'unknown',
			JSON.stringify({ req_header: req.headers, req_body: req.body }),
			JSON.stringify(getResponseMessage('INTERNAL_SERVER_ERROR'))
		);
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
