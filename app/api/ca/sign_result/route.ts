// app/api/ca/sign_result/route.ts

import { getResponseMessage } from '@/constants/responseMessages';
import { NextRequest, NextResponse } from 'next/server';
import { createSignedConsentList } from '@/utils/signatureGenerator';
import { PrismaClient } from '@prisma/client';
import { logger } from '@/utils/generateCSV';

const prisma = new PrismaClient();

const validateAuthorizationHeader = (header: string | null): boolean => {
	if (!header) return false;
	const [type, token] = header.split(' ');
	return type === 'Bearer' && !!token;
};

/**
 * @swagger
 * /api/ca/sign_result:
 *   post:
 *     summary: Processes signing result and creates signed consent records
 *     description: Endpoint for handling certificate signing results. Validates input parameters,
 *                  creates signed consent records from the certificate data, and returns the formatted list.
 *     tags:
 *       - Certificate Authority
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - cert_tx_id
 *               - sign_tx_id
 *             properties:
 *               cert_tx_id:
 *                 type: string
 *                 description: Certificate transaction ID
 *                 example: "1234567890abcdef1234567890abcdef12345678"
 *               sign_tx_id:
 *                 type: string
 *                 description: Sign transaction ID
 *                 example: "ORG001_CA001_1234567890abcdef1234567890abcdef12345678"
 *     parameters:
 *       - in: header
 *         name: Authorization
 *         required: true
 *         schema:
 *           type: string
 *         description: Authorization header for API access
 *       - in: header
 *         name: x-api-tran-id
 *         required: true
 *         schema:
 *           type: string
 *           maxLength: 25
 *         description: Transaction ID for request tracking
 *     responses:
 *       200:
 *         description: Successful operation
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 rsp_code:
 *                   type: string
 *                   description: Response code
 *                 rsp_msg:
 *                   type: string
 *                   description: Response message
 *                 signed_consent_cnt:
 *                   type: integer
 *                   description: Count of signed consents
 *                 signed_consent_list:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       signed_consent_len:
 *                         type: integer
 *                         description: Length of signed consent data
 *                       signed_consent:
 *                         type: string
 *                         description: Signed consent data
 *                       tx_id:
 *                         type: string
 *                         description: Transaction ID
 *                       user_id:
 *                         type: string
 *                         description: User ID
 *                       certificate_id:
 *                         type: string
 *                         description: Certificate ID
 *       400:
 *         description: Bad request (Invalid parameters)
 *       401:
 *         description: Unauthorized
 *       500:
 *         description: Internal server error
 */
export async function POST(req: NextRequest) {
	const headers = req.headers;
	const headersList = Object.fromEntries(headers.entries());
	const authorization = headers.get('Authorization');
	const xApiTranId = headers.get('x-api-tran-id');
	const method = req.method;
	const url = req.nextUrl.toString();
	const query = Object.fromEntries(req.nextUrl.searchParams);
	const body = await req.json();

	const { cert_tx_id, sign_tx_id } = body;

	const request = {
		method,
		url,
		query,
		headers: headersList,
	};

	try {
		if (!validateAuthorizationHeader(authorization)) {
			await logger(
				JSON.stringify(request),
				JSON.stringify(body),
				JSON.stringify(getResponseMessage('UNAUTHORIZED')),
				'400'
			);
			return NextResponse.json(getResponseMessage('UNAUTHORIZED'), { status: 401 });
		}

		// Validate x-api-tran-id
		if (!xApiTranId || xApiTranId.length > 25) {
			await logger(
				JSON.stringify(request),
				JSON.stringify(body),
				JSON.stringify(getResponseMessage('INVALID_API_TRAN_ID')),
				'400'
			);
			return NextResponse.json(getResponseMessage('INVALID_API_TRAN_ID'), { status: 400 });
		}

		if (!cert_tx_id || cert_tx_id.length !== 40) {
			await logger(
				JSON.stringify(request),
				JSON.stringify(body),
				JSON.stringify(getResponseMessage('INVALID_CERT_TX_ID')),
				'400'
			);
			return NextResponse.json(getResponseMessage('INVALID_CERT_TX_ID'), { status: 400 });
		}

		if (!sign_tx_id || sign_tx_id.length !== 49) {
			await logger(
				JSON.stringify(request),
				JSON.stringify(body),
				JSON.stringify(getResponseMessage('INVALID_SIGN_TX_ID')),
				'400'
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

		const orgCode = sign_tx_id.split('_')[0];
		const caCode = sign_tx_id.split('_')[1];

		const certificateAuthority = await prisma.certificateAuthority.findUnique({
			where: {
				caCode: caCode,
			},
		});

		const consent = await prisma.consent.findMany({
			where: {
				certificateId: certificate?.id,
			},
		});

		const signedConsentList = createSignedConsentList(
			consent,
			certificate?.userId || '',
			certificate?.id || '',
			certificateAuthority?.privateKey || ''
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
			signed_consent_cnt: signedConsentList.length,
			signed_consent_list: signedConsentListFormatted,
		};

		await logger(JSON.stringify(request), JSON.stringify(body), JSON.stringify(responseData), '200');

		return NextResponse.json(responseData, {
			status: 200,
			headers: {
				'Content-Type': 'application/json; charset=UTF-8',
			},
		});
	} catch (error) {
		await logger(
			JSON.stringify(request),
			JSON.stringify(body),
			JSON.stringify(getResponseMessage('INTERNAL_SERVER_ERROR')),
			'500'
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
