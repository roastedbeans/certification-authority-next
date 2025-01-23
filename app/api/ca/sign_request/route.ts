import { NextResponse } from 'next/server';
import jwt from 'jsonwebtoken';
import { getResponseMessage } from '@/constants/responseMessages';
import { createSignedConsentList, generateCertTxId, generateSignature } from '@/utils/signatureGenerator';
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();
const JWT_SECRET = process.env.JWT_SECRET || 'your-secure-secret';

type Consent = {
	txId: string;
	consentTitle: string;
	consent: string;
	consentLen: number;
};

export async function POST(req: Request) {
	try {
		const headers = req.headers;
		const authorization = headers.get('Authorization');
		const xApiTranId = headers.get('x-api-tran-id'); // e.g. 1234567890123456789012345

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

		// Validate request body
		const body = await req.json();
		const {
			sign_tx_id, // ORG2025001_CA20250001_20250117120000_RITFHJGITORP
			user_ci, // e.g. 1234567890123456789012345678901234567890123456789012345678901234
			real_name,
			phone_num, // E.164 standard applied, e.g. +821012345678
			request_title, // e.g. "Request for personal information"
			device_code, // PC - authorized method, TB - tablet, MO - mobile (default)
			device_browser, // WB - web browser, NA - native app (default), HY - mobile
			return_app_scheme_url, // e.g. mydata://auth
			consent_cnt, // Length of consent_list
			consent_type, // 0: Original text, 1: Hash value (SHA-256)
			consent_list, // List of consents
			// --consent "958675948576879"
			// --consent_len Number of characters in consent
			// --consent_title e.g. "Consent to share personal information"
			// --tx_id MD1234567890_0987654321_1234567890_20250117120000_E349RU3IDKFJ
		} = body;

		if (!sign_tx_id || sign_tx_id.length > 49) {
			return NextResponse.json(getResponseMessage('INVALID_SIGN_TX_ID'), { status: 400 });
		}

		if (!user_ci || user_ci.length > 100) {
			return NextResponse.json({ rsp_code: 2000, rsp_msg: 'Invalid or missing user_ci' }, { status: 400 });
		}

		if (!real_name || real_name.length > 30) {
			return NextResponse.json({ rsp_code: 2000, rsp_msg: 'Invalid or missing real_name' }, { status: 400 });
		}

		if (!phone_num || phone_num.length > 15) {
			return NextResponse.json({ rsp_code: 2000, rsp_msg: 'Invalid or missing phone_num' }, { status: 400 });
		}

		if (!request_title || request_title.length > 200) {
			return NextResponse.json({ rsp_code: 2000, rsp_msg: 'Invalid or missing request_title' }, { status: 400 });
		}

		if (!device_code || device_code.length > 50) {
			return NextResponse.json({ rsp_code: 2000, rsp_msg: 'Invalid or missing device_code' }, { status: 400 });
		}

		if (!device_browser || device_browser.length > 50) {
			return NextResponse.json({ rsp_code: 2000, rsp_msg: 'Invalid or missing device_browser' }, { status: 400 });
		}

		if (!return_app_scheme_url || return_app_scheme_url.length > 200) {
			return NextResponse.json(
				{ rsp_code: 2000, rsp_msg: 'Invalid or missing return_app_scheme_url' },
				{ status: 400 }
			);
		}

		if (!consent_cnt || typeof consent_cnt !== 'number') {
			return NextResponse.json({ rsp_code: 2000, rsp_msg: 'Invalid or missing consent_cnt' }, { status: 400 });
		}

		if (!consent_list || (consent_list as Consent[]).length !== consent_cnt) {
			return NextResponse.json({ rsp_code: 2000, rsp_msg: 'Invalid or missing consent' }, { status: 400 });
		}

		if (!consent_type || typeof consent_type !== 'number') {
			return NextResponse.json({ rsp_code: 2000, rsp_msg: 'Invalid or missing consent_type' }, { status: 400 });
		}

		const certTxId = generateCertTxId();

		// 1 year from now expiry date
		const expiresAt = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000);

		const organizationId = sign_tx_id.split('_')[0];
		const serialNumber = sign_tx_id.split('_')[3];

		const userResponse = await prisma.user.create({
			data: {
				name: real_name,
				organizationId: organizationId || 'default-organization-id',
			},
		});

		console.log('User data added to database:', userResponse);

		const certificateResponse = await prisma.certificate.create({
			data: {
				userId: userResponse.id,
				serialNumber: serialNumber,
				certTxId: certTxId,
				signTxId: sign_tx_id,
				phoneNumber: phone_num,
				userCI: user_ci,
				requestTitle: request_title,
				consentType: consent_type,
				deviceCode: device_code,
				deviceBrowser: device_browser,
				expiresAt: expiresAt,
			},
		});

		const consentListResponse = await prisma.consent.updateMany({
			where: {
				certificateId: certificateResponse.id,
			},
			data: [consent_list],
		});

		console.log('Certificate data added to database:', certificateResponse);
		console.log('Consent data added to database:', consentListResponse);

		const responseBody = {
			rsp_code: getResponseMessage('SUCCESS').code,
			rsp_msg: 'Electronic signature request successful, cert_tx_id has been provided.',
			sign_ios_app_scheme_url: `mydataauth://auth?tx_id=${organizationId}`, // Replace with actual iOS scheme
			sign_aos_app_scheme_url: `mydataauth://auth?tx_id=${organizationId}`, // Replace with actual Android scheme
			sign_web_url: `https://mydataauth.com/auth?tx_id=${organizationId}`, // Replace with actual web URL
			cert_tx_id: certTxId, // Transaction ID for certification
		};

		// If all validations pass
		return NextResponse.json(responseBody, { status: 200 });
	} catch (error) {
		console.error('Error in processing request:', error);
		return NextResponse.json({ error: 'Internal Server Error' }, { status: 500 });
	}
}
