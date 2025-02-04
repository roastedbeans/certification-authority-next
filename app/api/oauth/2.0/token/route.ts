import { NextResponse } from 'next/server';
import jwt from 'jsonwebtoken';
import { PrismaClient } from '@prisma/client';
import { getResponseMessage } from '@/constants/responseMessages';
import { initializeCsv, logRequestToCsv } from '@/utils/generateCSV';

const prisma = new PrismaClient();
const JWT_SECRET = process.env.JWT_SECRET || 'your-secure-secret'; // Replace with your secure environment variable

export async function POST(req: Request) {
	await initializeCsv(); // Ensure the CSV file exists

	try {
		// Parse and validate headers
		const headers = req.headers;
		const xApiTranId = headers.get('x-api-tran-id');

		if (!xApiTranId || xApiTranId.length > 25) {
			await logRequestToCsv('ca', JSON.stringify(getResponseMessage('INVALID_API_TRAN_ID')), '400');
			return NextResponse.json(getResponseMessage('INVALID_API_TRAN_ID'), { status: 400 });
		}

		// Parse body
		const body = await req.formData();
		const grant_type = body.get('grant_type');
		const client_id = body.get('client_id');
		const client_secret = body.get('client_secret');
		const scope = body.get('scope');

		// Validate body parameters
		if (grant_type !== 'client_credential' || !client_id || !client_secret || scope !== 'ca') {
			await logRequestToCsv(JSON.stringify(body), JSON.stringify(getResponseMessage('INVALID_PARAMETERS')), '400');
			return NextResponse.json(getResponseMessage('INVALID_PARAMETERS'), { status: 400 });
		}

		// Authenticate client using Supabase via Prisma
		// const clientSecret = process.env.CLIENT_SECRET;
		const oAuthClientRes = await prisma.oAuthClient.findUnique({
			where: {
				clientId: client_id as string,
			},
		});

		const clientSecret = oAuthClientRes?.clientSecret;

		if (!clientSecret || clientSecret !== client_secret) {
			await logRequestToCsv('ca', JSON.stringify(getResponseMessage('INVALID_PARAMETERS')), '401');
			return NextResponse.json(getResponseMessage('INVALID_PARAMETERS'), { status: 401 });
		}

		// Generate JWT token
		const token = generateAccessToken(client_id as string, scope as string);

		const responseData = {
			rsp_code: getResponseMessage('SUCCESS').code,
			rsp_msg: getResponseMessage('SUCCESS').message,
			token_type: 'Bearer',
			access_token: token,
			expires_in: 3600, // token expiry in seconds (1 hour)
			scope: scope,
		};

		const orgCode = client_id.toString().split('-')[0];

		await logRequestToCsv(JSON.stringify(req), JSON.stringify(body), JSON.stringify(responseData), '200');

		return NextResponse.json(responseData, { status: 200 });
	} catch (error) {
		const body = await req.formData();

		await logRequestToCsv(
			JSON.stringify(req),
			JSON.stringify(body),
			JSON.stringify(getResponseMessage('INTERNAL_SERVER_ERROR')),
			'500'
		);
		console.error('Error in token generation:', error);
		return NextResponse.json(getResponseMessage('INTERNAL_SERVER_ERROR'), { status: 500 });
	} finally {
		await prisma.$disconnect();
	}
}

// JWT Token generation function
function generateAccessToken(clientId: string, scope: string): string {
	// Generate the JWT payload
	const payload = {
		iss: 'certification-authority', // Issuer: Institution code
		aud: clientId, // Audience: Replace with appropriate institution code
		jti: crypto.randomUUID(), // Unique token identifier
		exp: Math.floor(Date.now() / 1000) + 3600, // Expiry time (1 hour from now)
		scope: scope, // Scope of access
	};

	return jwt.sign(payload, JWT_SECRET);
}
