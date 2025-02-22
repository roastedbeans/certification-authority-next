import { NextRequest, NextResponse } from 'next/server';
import jwt from 'jsonwebtoken';
import { PrismaClient } from '@prisma/client';
import { getResponseMessage } from '@/constants/responseMessages';
import { logger } from '@/utils/generateCSV';

const prisma = new PrismaClient();
const JWT_SECRET = process.env.JWT_SECRET || 'your-secure-secret'; // Replace with your secure environment variable

interface RequestBody {
	grant_type: string;
	client_id: string;
	client_secret: string;
	scope: string;
}

// API Gateway

// a request is sent -> attack detection module https:attackfinder.com/api/detectattack -> certification authority

const SignatureDetection = (request: any) => {
	// signature code
	// return boolean

	return true;
};

export async function POST(req: NextRequest) {
	const headers = req.headers;
	const headersList = Object.fromEntries(headers.entries());
	const authorization = headers.get('Authorization');
	const xApiTranId = headers.get('x-api-tran-id');
	const method = req.method;
	const url = req.nextUrl.toString();
	const query = Object.fromEntries(req.nextUrl.searchParams);

	const reqBody = await req.formData();
	const body: RequestBody = Object.fromEntries(reqBody) as unknown as RequestBody;

	const request = {
		method,
		url,
		query,
		headers: headersList,
	};

	try {
		if (!xApiTranId || xApiTranId.length > 25) {
			await logger(
				JSON.stringify(request),
				JSON.stringify(body),
				JSON.stringify(getResponseMessage('INVALID_API_TRAN_ID')),
				'401'
			);
			return NextResponse.json(getResponseMessage('INVALID_API_TRAN_ID'), { status: 400 });
		}

		// Validate body parameters
		if (body.grant_type !== 'client_credential' || !body.client_id || !body.client_secret || body.scope !== 'ca') {
			await logger(
				JSON.stringify(request),
				JSON.stringify(body),
				JSON.stringify(getResponseMessage('INVALID_PARAMETERS')),
				'401'
			);
			return NextResponse.json(getResponseMessage('INVALID_PARAMETERS'), { status: 400 });
		}

		// Authenticate client using Supabase via Prisma
		// const clientSecret = process.env.CLIENT_SECRET;
		const oAuthClientRes = await prisma.oAuthClient.findUnique({
			where: {
				clientId: body.client_id,
			},
		});

		const clientSecret = oAuthClientRes?.clientSecret;

		if (!clientSecret || clientSecret !== body.client_secret) {
			await logger(
				JSON.stringify(request),
				JSON.stringify(body),
				JSON.stringify(getResponseMessage('INVALID_PARAMETERS')),
				'401'
			);
			return NextResponse.json(getResponseMessage('INVALID_PARAMETERS'), { status: 401 });
		}

		// Generate JWT token
		const token = generateAccessToken(body.client_id, body.scope);

		const responseData = {
			rsp_code: getResponseMessage('SUCCESS').code,
			rsp_msg: getResponseMessage('SUCCESS').message,
			token_type: 'Bearer',
			access_token: token,
			expires_in: 3600, // token expiry in seconds (1 hour)
			scope: body.scope,
		};

		await logger(JSON.stringify(request), JSON.stringify(body), JSON.stringify(responseData), '200');

		return NextResponse.json(responseData, { status: 200 });
	} catch (error) {
		await logger(
			JSON.stringify(request),
			JSON.stringify(body),
			JSON.stringify(getResponseMessage('INTERNAL_SERVER_ERROR')),
			'500'
		);
		console.error('Error in token generation:', error);
		return NextResponse.json(getResponseMessage('INTERNAL_SERVER_ERROR'), { status: 500 });
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
