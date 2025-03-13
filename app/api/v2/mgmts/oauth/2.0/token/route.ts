import { NextRequest, NextResponse } from 'next/server';
import { getResponseMessage } from '@/constants/responseMessages';
import { PrismaClient } from '@prisma/client';
import { logger } from '@/utils/generateCSV';
import jwt from 'jsonwebtoken';

const prisma = new PrismaClient();

export async function POST(req: NextRequest) {
	const headers = req.headers;
	const headersList = Object.fromEntries(headers.entries());
	const xApiTranId = headers.get('x-api-tran-id');
	const method = req.method;
	const url = req.nextUrl.toString();
	const query = Object.fromEntries(req.nextUrl.searchParams);

	// Handle both JSON and form data
	let body: any;
	let grantType: string | null;
	let clientId: string | null;
	let clientSecret: string | null;
	let scope: string | null;

	const contentType = headers.get('content-type');
	if (contentType?.includes('application/json')) {
		body = await req.json();
		grantType = body.grant_type;
		clientId = body.client_id;
		clientSecret = body.client_secret;
		scope = body.scope;
	} else {
		const formData = await req.formData();
		body = Object.fromEntries(formData);
		grantType = formData.get('grant_type') as string;
		clientId = formData.get('client_id') as string;
		clientSecret = formData.get('client_secret') as string;
		scope = formData.get('scope') as string;
	}

	const request = {
		method,
		url,
		query,
		headers: headersList,
	};

	try {
		if (!xApiTranId) {
			const response = NextResponse.json(getResponseMessage('INVALID_API_TRAN_ID'), { status: 400 });
			await logger(
				JSON.stringify(request),
				JSON.stringify(body),
				JSON.stringify(getResponseMessage('INVALID_API_TRAN_ID')),
				'400'
			);
			return response;
		}

		// Validate body parameters
		if (grantType !== 'client_credentials' || !clientId || !clientSecret || scope !== 'manage') {
			const response = NextResponse.json(getResponseMessage('INVALID_PARAMETERS'), { status: 400 });
			await logger(
				JSON.stringify(request),
				JSON.stringify(body),
				JSON.stringify(getResponseMessage('INVALID_PARAMETERS')),
				'400'
			);
			return response;
		}

		// Authenticate client using Supabase via Prisma
		const client = await prisma.oAuthClient.findUnique({
			where: { clientId: clientId },
		});

		if (!client || client.clientSecret !== clientSecret) {
			const response = NextResponse.json(getResponseMessage('INVALID_PARAMETERS'), { status: 401 });
			await logger(
				JSON.stringify(request),
				JSON.stringify(body),
				JSON.stringify(getResponseMessage('INVALID_PARAMETERS')),
				'401'
			);
			return response;
		}

		const orgCode = client.clientId.split('-')[0];

		// Generate JWT token
		const token = generateAccessToken(clientId, scope);

		const responseData = {
			access_token: token,
			token_type: 'Bearer',
			expires_in: 3600, // 1 hour
			scope: scope,
			client_id: clientId,
			org_code: orgCode,
		};

		await logger(JSON.stringify(request), JSON.stringify(body), JSON.stringify(responseData), '200');

		return NextResponse.json(responseData, { status: 200 });
	} catch (error) {
		const response = NextResponse.json(getResponseMessage('INTERNAL_SERVER_ERROR'), { status: 500 });
		await logger(
			JSON.stringify(request),
			JSON.stringify(body),
			JSON.stringify(getResponseMessage('INTERNAL_SERVER_ERROR')),
			'500'
		);
		console.error('Error in token request:', error);
		return response;
	} finally {
		await prisma.$disconnect();
	}
}

// JWT Token generation function
function generateAccessToken(clientId: string, scope: string): string {
	// Generate the JWT payload
	const payload = {
		iss: 'comprehensive-portal', // Issuer: Institution code
		aud: clientId, // Audience: Replace with appropriate institution code
		jti: crypto.randomUUID(), // Unique token identifier
		exp: Math.floor(Date.now() / 1000) + 3600, // Expiry time (1 hour from now)
		scope: scope, // Scope of access
	};

	return jwt.sign(payload, JWT_SECRET);
}
