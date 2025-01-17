import { NextResponse } from 'next/server';
import jwt from 'jsonwebtoken';
import { getResponseMessage } from '@/constants/responseMessages';
import { generateCertTxId } from '@/utils/signatureGenerator';

const JWT_SECRET = process.env.JWT_SECRET || 'your-secure-secret';

export async function POST(req: Request) {
	try {
		const headers = req.headers;
		const authorization = headers.get('Authorization');
		const xApiTranId = headers.get('x-api-tran-id');

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
			user_ci,
			real_name,
			phone_num,
			request_title,
			device_code,
			device_browser,
			return_app_scheme_url,
			consent_cnt,
			consent_list,
			consent_len,
			consent_title,
			consent,
			tx_id,
		} = body;

		if (!sign_tx_id || sign_tx_id.length > 49) {
			return NextResponse.json(getResponseMessage('INVALID_SIGN_TX_ID'), { status: 400 });
		}

		if (!user_ci || user_ci.length > 64) {
			return NextResponse.json({ rsp_code: 2000, rsp_msg: 'Invalid or missing user_ci' }, { status: 400 });
		}

		if (!real_name || real_name.length > 100) {
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

		if (!Array.isArray(consent_list) || consent_list.length !== consent_cnt) {
			return NextResponse.json({ rsp_code: 2000, rsp_msg: 'Invalid or missing consent_list' }, { status: 400 });
		}

		if (!consent_len || typeof consent_len !== 'number') {
			return NextResponse.json({ rsp_code: 2000, rsp_msg: 'Invalid or missing consent_len' }, { status: 400 });
		}

		if (!consent_title || consent_title.length > 200) {
			return NextResponse.json({ rsp_code: 2000, rsp_msg: 'Invalid or missing consent_title' }, { status: 400 });
		}

		if (!consent || typeof consent !== 'boolean') {
			return NextResponse.json({ rsp_code: 2000, rsp_msg: 'Invalid or missing consent' }, { status: 400 });
		}

		if (!tx_id || tx_id.length > 50) {
			return NextResponse.json({ rsp_code: 2000, rsp_msg: 'Invalid or missing tx_id' }, { status: 400 });
		}

		const certTxId = generateCertTxId();

		const responseBody = {
			rsp_code: getResponseMessage('SUCCESS').code,
			rsp_msg: 'Electronic signature request successful, cert_tx_id has been provided.',
			sign_ios_app_scheme_url: `mydataauth://auth?tx_id=${sign_tx_id}`, // Replace with actual iOS scheme
			sign_aos_app_scheme_url: `mydataauth://auth?tx_id=${sign_tx_id}`, // Replace with actual Android scheme
			sign_web_url: `https://mydataauth.com/auth?tx_id=${sign_tx_id}`, // Replace with actual web URL
			cert_tx_id: certTxId, // Transaction ID for certification
		};

		// If all validations pass
		return NextResponse.json(responseBody, { status: 200 });
	} catch (error) {
		console.error('Error in processing request:', error);
		return NextResponse.json({ error: 'Internal Server Error' }, { status: 500 });
	}
}
