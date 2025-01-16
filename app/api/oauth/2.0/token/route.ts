import { NextResponse } from 'next/server';
import jwt from 'jsonwebtoken';
import { PrismaClient } from '@prisma/client';
import { getResponseMessage } from '@/constants/responseMessages';

const prisma = new PrismaClient();
const JWT_SECRET = process.env.JWT_SECRET || 'your-secure-secret'; // Replace with your secure environment variable

export async function POST(req: Request) {
	try {
		// Parse and validate headers
		const headers = req.headers;
		const xApiTranId = headers.get('x-api-tran-id');
		if (!xApiTranId || xApiTranId.length > 25) {
			return NextResponse.json({ error: 'Invalid or missing x-api-tran-id' }, { status: 400 });
		}

		// Parse body
		const body = await req.formData();
		const grantType = body.get('grant_type');
		const clientId = body.get('client_id');
		const clientSecret = body.get('client_secret');
		const scope = body.get('scope');

		// Validate body parameters
		if (grantType !== 'client_credential' || !clientId || !clientSecret || scope !== 'ca') {
			return NextResponse.json(getResponseMessage('INVALID_PARAMETERS'), { status: 400 });
		}

		// Authenticate client using Supabase via Prisma
		const client = await prisma.organization.findUnique({
			where: { clientId: clientId as string },
		});

		if (!client || client.clientSecret !== clientSecret) {
			return NextResponse.json(getResponseMessage('INVALID_PARAMETERS'), { status: 401 });
		}

		// Generate JWT token
		const token = generateAccessToken(clientId as string, scope as string);

		return NextResponse.json(
			{
				rsp_code: getResponseMessage('SUCCESS').code,
				rsp_msg: getResponseMessage('SUCCESS').message,
				token_type: 'Bearer',
				access_token: token,
				expires_in: 3600, // token expiry in seconds (1 hour)
				scope: 'ca',
			},
			{ status: 200 }
		);
	} catch (error) {
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
		iss: clientId, // Issuer: Institution code
		aud: 'certification-authority', // Audience: Replace with appropriate institution code
		jti: crypto.randomUUID(), // Unique token identifier
		exp: Math.floor(Date.now() / 1000) + 3600, // Expiry time (1 hour from now)
		scope: scope, // Scope of access
	};

	const options = {
		expiresIn: '1h', // Token validity period
	};

	return jwt.sign(payload, JWT_SECRET, options);
}
