import { NextRequest, NextResponse } from 'next/server';
import jwt from 'jsonwebtoken';
import { getResponseMessage } from '@/constants/responseMessages';
import { generateCertTxId } from '@/utils/signatureGenerator';
import { PrismaClient } from '@prisma/client';
import { logger } from '@/utils/generateCSV';

const prisma = new PrismaClient();
const JWT_SECRET = process.env.JWT_SECRET || 'your-secure-secret';

type Consent = {
	txId: string;
	consentTitle: string;
	consent: string;
	consentLen: number;
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

	const request = {
		method,
		url,
		query,
		headers: headersList,
	};

	try {
		if (!authorization?.startsWith('Bearer ')) {
			await logger(
				JSON.stringify(request),
				JSON.stringify(body),
				JSON.stringify(getResponseMessage('UNAUTHORIZED')),
				'401'
			);
			return NextResponse.json(getResponseMessage('UNAUTHORIZED'), { status: 401 });
		}

		// Extract the token
		const token = authorization.split(' ')[1];
		let decodedToken;

		try {
			decodedToken = jwt.verify(token, JWT_SECRET);
		} catch (error) {
			await logger(
				JSON.stringify(request),
				JSON.stringify(body),
				JSON.stringify(getResponseMessage('INVALID_TOKEN')),
				'403'
			);
			return NextResponse.json(getResponseMessage('INVALID_TOKEN'), { status: 403 });
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

		if (!sign_tx_id || sign_tx_id.length > 49) {
			await logger(
				JSON.stringify(request),
				JSON.stringify(body),
				JSON.stringify(getResponseMessage('INVALID_SIGN_TX_ID')),
				'400'
			);
			return NextResponse.json(getResponseMessage('INVALID_SIGN_TX_ID'), { status: 400 });
		}

		if (!user_ci || user_ci.length > 100) {
			await logger(
				JSON.stringify(request),
				JSON.stringify(body),
				JSON.stringify(getResponseMessage('INVALID_PARAMETERS')),
				'400'
			);
			return NextResponse.json(getResponseMessage('INVALID_PARAMETERS'), { status: 400 });
		}

		if (!real_name || real_name.length > 30) {
			await logger(
				JSON.stringify(request),
				JSON.stringify(body),
				JSON.stringify(getResponseMessage('INVALID_PARAMETERS')),
				'400'
			);
			return NextResponse.json(getResponseMessage('INVALID_PARAMETERS'), { status: 400 });
		}

		if (!phone_num || phone_num.length > 15) {
			await logger(
				JSON.stringify(request),
				JSON.stringify(body),
				JSON.stringify(getResponseMessage('INVALID_PARAMETERS')),
				'400'
			);
			return NextResponse.json(getResponseMessage('INVALID_PARAMETERS'), { status: 400 });
		}

		if (!request_title || request_title.length > 200) {
			await logger(
				JSON.stringify(request),
				JSON.stringify(body),
				JSON.stringify(getResponseMessage('INVALID_PARAMETERS')),
				'400'
			);
			return NextResponse.json(getResponseMessage('INVALID_PARAMETERS'), { status: 400 });
		}

		if (!device_code || device_code.length > 50) {
			await logger(
				JSON.stringify(request),
				JSON.stringify(body),
				JSON.stringify(getResponseMessage('INVALID_PARAMETERS')),
				'400'
			);
			return NextResponse.json(getResponseMessage('INVALID_PARAMETERS'), { status: 400 });
		}

		if (!device_browser || device_browser.length > 50) {
			await logger(
				JSON.stringify(request),
				JSON.stringify(body),
				JSON.stringify(getResponseMessage('INVALID_PARAMETERS')),
				'400'
			);
			return NextResponse.json(getResponseMessage('INVALID_PARAMETERS'), { status: 400 });
		}

		if (!return_app_scheme_url || return_app_scheme_url.length > 200) {
			await logger(
				JSON.stringify(request),
				JSON.stringify(body),
				JSON.stringify(getResponseMessage('INVALID_PARAMETERS')),
				'400'
			);
			return NextResponse.json(getResponseMessage('INVALID_PARAMETERS'), { status: 400 });
		}

		if (!consent_cnt || typeof consent_cnt !== 'number') {
			await logger(
				JSON.stringify(request),
				JSON.stringify(body),
				JSON.stringify(getResponseMessage('INVALID_PARAMETERS')),
				'400'
			);
			return NextResponse.json(getResponseMessage('INVALID_PARAMETERS'), { status: 400 });
		}

		if (!consent_list || (consent_list as Consent[]).length !== consent_cnt) {
			await logger(
				JSON.stringify(request),
				JSON.stringify(body),
				JSON.stringify(getResponseMessage('INVALID_PARAMETERS')),
				'400'
			);
			return NextResponse.json(getResponseMessage('INVALID_PARAMETERS'), { status: 400 });
		}

		if (!consent_type || consent_type.length > 1) {
			await logger(
				JSON.stringify(request),
				JSON.stringify(body),
				JSON.stringify(getResponseMessage('INVALID_PARAMETERS')),
				'400'
			);
			return NextResponse.json(getResponseMessage('INVALID_PARAMETERS'), { status: 400 });
		}

		const certTxId = generateCertTxId();

		// 1 year from now expiry date
		const expiresAt = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000);

		const orgCode = sign_tx_id.split('_')[0];
		const caCode = sign_tx_id.split('_')[1];
		const serialNumber = sign_tx_id.split('_')[3];

		const userResponse = await prisma.user.create({
			data: {
				name: real_name,
				orgCode: orgCode || 'default-organization-id',
			},
		});

		const firstName = real_name.split(' ')[0];
		const lastName = real_name.split(' ')[1];

		const accountExist = await prisma.account.findFirst({
			where: {
				firstName: firstName,
				lastName: lastName,
			},
		});

		const account = await prisma.account.update({
			where: {
				accountNum: accountExist?.accountNum,
			},
			data: {
				userId: userResponse.id,
			},
		});

		const certificateAuthority = await prisma.certificateAuthority.findUnique({
			where: {
				caCode: caCode,
			},
		});

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
				certificateAuthorityId: certificateAuthority?.id || '',
				expiresAt: expiresAt,
			},
		});

		for (const consent of consent_list) {
			const resConsent = await prisma.consent.create({
				data: {
					txId: consent.tx_id,
					consentLen: consent.consent_len,
					consentTitle: consent.consent_title,
					consent: consent.consent,
					certificateId: certificateResponse.id,
					userId: userResponse.id,
				},
			});
		}

		const responseData = {
			rsp_code: getResponseMessage('SUCCESS').code,
			rsp_msg: 'Electronic signature request successful, cert_tx_id has been provided.',
			sign_ios_app_scheme_url: `mydataauth://auth?tx_id=${orgCode}`, // Replace with actual iOS scheme
			sign_aos_app_scheme_url: `mydataauth://auth?tx_id=${orgCode}`, // Replace with actual Android scheme
			sign_web_url: `https://mydataauth.com/auth?tx_id=${orgCode}`, // Replace with actual web URL
			cert_tx_id: certTxId, // Transaction ID for certification
		};

		await logger(JSON.stringify(request), JSON.stringify(body), JSON.stringify(responseData), '200');

		// If all validations pass
		return NextResponse.json(responseData, { status: 200 });
	} catch (error) {
		await logger(
			JSON.stringify(request),
			JSON.stringify(body),
			JSON.stringify(getResponseMessage('INTERNAL_SERVER_ERROR')),
			'500'
		);

		console.error('Error in processing request:', error);
		return NextResponse.json({ error: 'Internal Server Error' }, { status: 500 });
	}
}
