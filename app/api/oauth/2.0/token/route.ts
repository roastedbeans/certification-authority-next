import { NextRequest, NextResponse } from 'next/server';
import jwt from 'jsonwebtoken';
import { PrismaClient } from '@prisma/client';
import { getResponseContent, getResponseMessage, ResponseData } from '@/constants/responseMessages';
import { logger } from '@/utils/generateCSV';

const prisma = new PrismaClient();
// Remove fallback JWT secret - this should be required
const JWT_SECRET = process.env.JWT_SECRET;
// Add additional JWT configuration
const JWT_ISSUER = process.env.JWT_ISSUER || 'certification-authority';
const JWT_TOKEN_EXPIRY = parseInt(process.env.JWT_TOKEN_EXPIRY || '3600', 10); // Default 1 hour

interface RequestBody {
	grant_type: string;
	client_id: string;
	client_secret: string;
	scope: string;
}

// Token response interface
interface TokenResponse {
	rsp_code: string;
	rsp_msg: string;
	token_type: string;
	access_token: string;
	expires_in: number;
	scope: string;
	issued_at?: number;
}

export async function POST(req: NextRequest) {
	const headers = req.headers;
	const headersList = Object.fromEntries(headers.entries());
	const authorization = headers.get('Authorization');
	const xApiTranId = headers.get('x-api-tran-id');
	const method = req.method;
	const url = req.nextUrl.toString();
	const query = Object.fromEntries(req.nextUrl.searchParams);

	// Start timing for performance monitoring
	const startTime = Date.now();

	// Create request object for logging
	const requestInfo = JSON.stringify({
		method,
		url,
		query,
		headers: headersList,
	});

	try {
		// Check if JWT_SECRET is configured
		if (!JWT_SECRET) {
			console.error('JWT_SECRET environment variable is not configured');
			const responseData: ResponseData = {
				headers: {
					contentType: 'application/json;charset=UTF-8',
					xApiTranId: xApiTranId || '',
				},
				body: getResponseMessage('INTERNAL_SERVER_ERROR'),
			};
			const response = getResponseContent(responseData);
			await logger(requestInfo, JSON.stringify(response), 500);
			return NextResponse.json(response, { status: 500 });
		}

		// Validate API transaction ID header
		if (!xApiTranId) {
			const responseData: ResponseData = {
				headers: {
					contentType: 'application/json;charset=UTF-8',
					xApiTranId: xApiTranId || '',
				},
				body: getResponseMessage('INVALID_API_TRAN_ID'),
			};
			const response = getResponseContent(responseData);
			await logger(requestInfo, JSON.stringify(response), 400);
			return NextResponse.json(response, { status: 400 });
		}

		const reqBody = await req.formData();
		const body: RequestBody = Object.fromEntries(reqBody) as unknown as RequestBody;

		const request = JSON.stringify({
			method,
			url,
			query,
			headers: headersList,
			body,
		});

		// Validate grant type
		if (body.grant_type !== 'client_credentials') {
			const responseData: ResponseData = {
				headers: {
					contentType: 'application/json;charset=UTF-8',
					xApiTranId: xApiTranId || '',
				},
				body: getResponseMessage('INVALID_PARAMETERS', 'Unsupported grant_type'),
			};
			const response = getResponseContent(responseData);
			await logger(request, JSON.stringify(response), 400);
			return NextResponse.json(response, { status: 400 });
		}

		// Validate required parameters
		if (!body.client_id || !body.client_secret) {
			const responseData: ResponseData = {
				headers: {
					contentType: 'application/json;charset=UTF-8',
					xApiTranId: xApiTranId || '',
				},
				body: getResponseMessage('MISSING_REQUIRED_FIELD', 'client_id and client_secret are required'),
			};
			const response = getResponseContent(responseData);
			await logger(request, JSON.stringify(response), 400);
			return NextResponse.json(response, { status: 400 });
		}

		// Validate scope
		const allowedScopes = ['ca', 'ca:sign_request', 'ca:sign_result', 'ca:sign_verification'];
		if (!body.scope || !allowedScopes.includes(body.scope)) {
			const responseData: ResponseData = {
				headers: {
					contentType: 'application/json;charset=UTF-8',
					xApiTranId: xApiTranId || '',
				},
				body: getResponseMessage('INVALID_PARAMETERS', `Invalid scope. Allowed values: ${allowedScopes.join(', ')}`),
			};
			const response = getResponseContent(responseData);
			await logger(request, JSON.stringify(response), 400);
			return NextResponse.json(response, { status: 400 });
		}

		// Authenticate client - wrap in try/catch for database errors
		try {
			// Query OAuth client with relation to organization
			const oAuthClient = await prisma.oAuthClient.findUnique({
				where: {
					clientId: body.client_id,
				},
				include: {
					organization: {
						select: {
							orgCode: true,
							name: true,
						},
					},
				},
			});

			// Check if client exists
			if (!oAuthClient) {
				const responseData: ResponseData = {
					headers: {
						contentType: 'application/json;charset=UTF-8',
						xApiTranId: xApiTranId || '',
					},
					body: getResponseMessage('UNAUTHORIZED', 'Invalid client'),
				};
				const response = getResponseContent(responseData);
				await logger(request, JSON.stringify(response), 401);
				return NextResponse.json(response, { status: 401 });
			}

			// Verify client secret (consider using a secure hash comparison)
			if (oAuthClient.clientSecret !== body.client_secret) {
				const responseData: ResponseData = {
					headers: {
						contentType: 'application/json;charset=UTF-8',
						xApiTranId: xApiTranId || '',
					},
					body: getResponseMessage('UNAUTHORIZED', 'Invalid client credentials'),
				};
				const response = getResponseContent(responseData);
				await logger(request, JSON.stringify(response), 401);
				return NextResponse.json(response, { status: 401 });
			}

			// Generate JWT token with enhanced security
			const now = Math.floor(Date.now() / 1000);
			const jwtId = crypto.randomUUID();

			// Generate JWT token
			const token = generateAccessToken(body.client_id, body.scope, jwtId, oAuthClient.organization?.orgCode);

			// Prepare response
			const tokenResponse: TokenResponse = {
				rsp_code: getResponseMessage('SUCCESS').code,
				rsp_msg: getResponseMessage('SUCCESS').message,
				token_type: 'Bearer',
				access_token: token,
				expires_in: JWT_TOKEN_EXPIRY,
				scope: body.scope,
				issued_at: now,
			};

			const responseData: ResponseData = {
				headers: {
					contentType: 'application/json;charset=UTF-8',
					xApiTranId: xApiTranId || '',
				},
				body: tokenResponse,
			};

			const response = getResponseContent(responseData);

			// Calculate response time for monitoring
			const responseTime = Date.now() - startTime;
			console.log(`Token request processed in ${responseTime}ms`);

			await logger(request, JSON.stringify(response), 200);
			return NextResponse.json(response, { status: 200 });
		} catch (dbError) {
			console.error('Database error during client authentication:', dbError);
			const responseData: ResponseData = {
				headers: {
					contentType: 'application/json;charset=UTF-8',
					xApiTranId: xApiTranId || '',
				},
				body: getResponseMessage('DATABASE_ERROR'),
			};
			const response = getResponseContent(responseData);
			await logger(request, JSON.stringify(response), 500);
			return NextResponse.json(response, { status: 500 });
		}
	} catch (error) {
		console.error('Error in token generation:', error);
		const errorMsg = error instanceof Error ? error.message : 'Unknown error';

		const responseData: ResponseData = {
			headers: {
				contentType: 'application/json;charset=UTF-8',
				xApiTranId: xApiTranId || '',
			},
			body: getResponseMessage('INTERNAL_SERVER_ERROR'),
		};
		const response = getResponseContent(responseData);

		// Log the error but don't include sensitive information
		const sanitizedError = JSON.stringify({
			method,
			url,
			headers: headersList,
			error: { message: errorMsg },
		});

		await logger(sanitizedError, JSON.stringify(response), 500);
		return NextResponse.json(response, { status: 500 });
	} finally {
		// Always ensure prisma connection is closed properly
		await prisma.$disconnect();
	}
}

// Enhanced JWT Token generation function with better security
function generateAccessToken(clientId: string, scope: string, jwtId: string, orgCode?: string): string {
	// Current timestamp in seconds
	const now = Math.floor(Date.now() / 1000);

	// Generate the JWT payload with more security features
	const payload = {
		iss: JWT_ISSUER, // Issuer: Set from environment or default
		sub: clientId, // Subject: The client ID
		aud: orgCode ? [orgCode, 'certification-authority'] : ['certification-authority'], // Audience: Organization code and service
		jti: jwtId, // JWT ID: Unique identifier for potential revocation
		iat: now, // Issued at: Current time
		exp: now + JWT_TOKEN_EXPIRY, // Expiry: Current time + configured expiry
		scope: scope.split(' '), // Scope: Convert space-delimited to array for easier verification
	};

	// Make sure JWT_SECRET is defined
	if (!JWT_SECRET) {
		throw new Error('JWT_SECRET is not properly configured');
	}

	// Sign with more secure options
	return jwt.sign(payload, JWT_SECRET, {
		algorithm: 'HS256', // Specify algorithm explicitly
	});
}
