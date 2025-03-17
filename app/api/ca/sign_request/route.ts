import { NextRequest, NextResponse } from 'next/server';
import jwt from 'jsonwebtoken';
import { getResponseContent, getResponseMessage, ResponseCodes } from '@/constants/responseMessages';
import { generateCertTxId } from '@/utils/signatureGenerator';
import { PrismaClient } from '@prisma/client';
import { logger } from '@/utils/generateCSV';

// Import the type from responseMessages
import type { ResponseMessage } from '@/constants/responseMessages';

// Define allowed response code types based on the keys of ResponseCodes
type ResponseCodeType = keyof typeof ResponseCodes;

const prisma = new PrismaClient();
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_ISSUER = process.env.JWT_ISSUER;
const JWT_AUDIENCE = process.env.JWT_AUDIENCE;

interface JwtPayload {
	sub: string; // subject (user ID)
	iss?: string; // issuer
	aud?: string[]; // audience
	exp?: number; // expiration time
	iat?: number; // issued at time
	scope?: string[]; // permissions
	jti?: string; // JWT ID (for revocation)
}

type Consent = {
	txId: string;
	consentTitle: string;
	consent: string;
	consentLen: number;
};

// Define RevokedToken schema since it's referenced in the checkTokenRevocation function
interface RevokedToken {
	jti: string;
	expiresAt: Date;
}

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
		sign_tx_id,
		user_ci,
		real_name,
		phone_num,
		request_title,
		device_code,
		device_browser,
		return_app_scheme_url,
		consent_cnt,
		consent_type,
		consent_list,
	} = body;

	const request = {
		method,
		url,
		query,
		headers: headersList,
		body,
	};

	try {
		if (!JWT_SECRET) {
			console.error('JWT_SECRET is not defined');
			const response = getResponseContent({
				headers: {
					xApiTranId: xApiTranId || '',
					contentType: 'application/json;charset=UTF-8',
				},
				body: getResponseMessage('INTERNAL_SERVER_ERROR'),
			});
			await logger(JSON.stringify(request), JSON.stringify(response), 500);
			return NextResponse.json(response, { status: 500 });
		}

		if (!authorization?.startsWith('Bearer ')) {
			const response = getResponseContent({
				headers: {
					xApiTranId: xApiTranId || '',
					contentType: 'application/json;charset=UTF-8',
				},
				body: getResponseMessage('UNAUTHORIZED'),
			});
			await logger(JSON.stringify(request), JSON.stringify(response), 401);
			return NextResponse.json(response, { status: 401 });
		}

		const token = authorization.split(' ')[1];
		let payload: JwtPayload;

		try {
			payload = jwt.verify(token, JWT_SECRET, {
				issuer: JWT_ISSUER,
				audience: JWT_AUDIENCE,
				clockTolerance: 30,
			}) as JwtPayload;

			if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
				throw new Error('Token has expired');
			}

			if (payload.iat && payload.iat > Math.floor(Date.now() / 1000) + 60) {
				throw new Error('Token iat is in the future');
			}

			if (payload.scope && !payload.scope.includes('ca')) {
				throw new Error('Token does not have required scope');
			}

			if (payload.jti) {
				const isRevoked = await checkTokenRevocation(payload.jti);
				if (isRevoked) {
					throw new Error('Token has been revoked');
				}
			}
		} catch (error) {
			console.error('JWT verification error:', error);

			const errorMessage = error instanceof Error ? error.message : 'Unknown error';
			// Define responseCode with the correct type
			let responseCode: ResponseCodeType = 'INVALID_TOKEN';

			// Log specific errors but use standard error codes that exist in the ResponseCodes object
			if (errorMessage.includes('expired')) {
				console.log('Token has expired');
				// Still using INVALID_TOKEN
			} else if (errorMessage.includes('scope')) {
				responseCode = 'UNAUTHORIZED';
			} else if (errorMessage.includes('revoked')) {
				console.log('Token has been revoked');
				// Still using INVALID_TOKEN
			} else if (errorMessage.includes('audience') || errorMessage.includes('issuer')) {
				console.log('Token has invalid claims (issuer/audience)');
				// Still using INVALID_TOKEN
			}

			const response = getResponseContent({
				headers: {
					xApiTranId: xApiTranId || '',
					contentType: 'application/json;charset=UTF-8',
				},
				body: getResponseMessage(responseCode),
			});
			await logger(JSON.stringify(request), JSON.stringify(response), 403);
			return NextResponse.json(response, { status: 403 });
		}

		if (!xApiTranId) {
			const response = getResponseContent({
				headers: {
					xApiTranId: xApiTranId || '',
					contentType: 'application/json;charset=UTF-8',
				},
				body: getResponseMessage('INVALID_API_TRAN_ID'),
			});
			await logger(JSON.stringify(request), JSON.stringify(response), 400);
			return NextResponse.json(response, { status: 400 });
		}

		if (!sign_tx_id || sign_tx_id.length > 49) {
			const response = getResponseContent({
				headers: {
					xApiTranId: xApiTranId || '',
					contentType: 'application/json;charset=UTF-8',
				},
				body: getResponseMessage('INVALID_SIGN_TX_ID'),
			});
			await logger(JSON.stringify(request), JSON.stringify(response), 400);
			return NextResponse.json(response, { status: 400 });
		}

		if (!user_ci || user_ci.length > 100) {
			const response = getResponseContent({
				headers: {
					xApiTranId: xApiTranId || '',
					contentType: 'application/json;charset=UTF-8',
				},
				body: getResponseMessage('INVALID_PARAMETERS'),
			});
			await logger(JSON.stringify(request), JSON.stringify(response), 400);
			return NextResponse.json(response, { status: 400 });
		}

		if (!real_name || real_name.length > 30) {
			const response = getResponseContent({
				headers: {
					xApiTranId: xApiTranId || '',
					contentType: 'application/json;charset=UTF-8',
				},
				body: getResponseMessage('INVALID_PARAMETERS'),
			});
			await logger(JSON.stringify(request), JSON.stringify(response), 400);
			return NextResponse.json(response, { status: 400 });
		}

		if (!phone_num || phone_num.length > 15) {
			const response = getResponseContent({
				headers: {
					xApiTranId: xApiTranId || '',
					contentType: 'application/json;charset=UTF-8',
				},
				body: getResponseMessage('INVALID_PARAMETERS'),
			});
			await logger(JSON.stringify(request), JSON.stringify(response), 400);
			return NextResponse.json(response, { status: 400 });
		}

		if (!request_title || request_title.length > 200) {
			const response = getResponseContent({
				headers: {
					xApiTranId: xApiTranId || '',
					contentType: 'application/json;charset=UTF-8',
				},
				body: getResponseMessage('INVALID_PARAMETERS'),
			});
			await logger(JSON.stringify(request), JSON.stringify(response), 400);
			return NextResponse.json(response, { status: 400 });
		}

		if (!device_code || device_code.length > 50) {
			const response = getResponseContent({
				headers: {
					xApiTranId: xApiTranId || '',
					contentType: 'application/json;charset=UTF-8',
				},
				body: getResponseMessage('INVALID_PARAMETERS'),
			});
			await logger(JSON.stringify(request), JSON.stringify(response), 400);
			return NextResponse.json(response, { status: 400 });
		}

		if (!device_browser || device_browser.length > 50) {
			const response = getResponseContent({
				headers: {
					xApiTranId: xApiTranId || '',
					contentType: 'application/json;charset=UTF-8',
				},
				body: getResponseMessage('INVALID_PARAMETERS'),
			});
			await logger(JSON.stringify(request), JSON.stringify(response), 400);
			return NextResponse.json(response, { status: 400 });
		}

		if (!return_app_scheme_url || return_app_scheme_url.length > 200) {
			const response = getResponseContent({
				headers: {
					xApiTranId: xApiTranId || '',
					contentType: 'application/json;charset=UTF-8',
				},
				body: getResponseMessage('INVALID_PARAMETERS'),
			});
			await logger(JSON.stringify(request), JSON.stringify(response), 400);
			return NextResponse.json(response, { status: 400 });
		}

		if (!consent_cnt || typeof consent_cnt !== 'number') {
			const response = getResponseContent({
				headers: {
					xApiTranId: xApiTranId || '',
					contentType: 'application/json;charset=UTF-8',
				},
				body: getResponseMessage('INVALID_PARAMETERS'),
			});
			await logger(JSON.stringify(request), JSON.stringify(response), 400);
			return NextResponse.json(response, { status: 400 });
		}

		if (!consent_list || (consent_list as Consent[]).length !== consent_cnt) {
			const response = getResponseContent({
				headers: {
					xApiTranId: xApiTranId || '',
					contentType: 'application/json;charset=UTF-8',
				},
				body: getResponseMessage('INVALID_PARAMETERS'),
			});
			await logger(JSON.stringify(request), JSON.stringify(response), 400);
			return NextResponse.json(response, { status: 400 });
		}

		if (!consent_type || consent_type.length > 1) {
			const response = getResponseContent({
				headers: {
					xApiTranId: xApiTranId || '',
					contentType: 'application/json;charset=UTF-8',
				},
				body: getResponseMessage('INVALID_PARAMETERS'),
			});
			await logger(JSON.stringify(request), JSON.stringify(response), 400);
			return NextResponse.json(response, { status: 400 });
		}

		const certTxId = generateCertTxId();

		const expiresAt = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000);

		const orgCode = sign_tx_id.split('_')[0];
		const caCode = sign_tx_id.split('_')[1];
		const serialNumber = sign_tx_id.split('_')[3];

		try {
			const result = await prisma.$transaction(async (tx) => {
				let userResponse;
				const existingUser = await tx.user.findFirst({
					where: {
						name: real_name,
						orgCode: orgCode,
					},
				});

				if (existingUser) {
					userResponse = existingUser;
				} else {
					userResponse = await tx.user.create({
						data: {
							name: real_name,
							orgCode: orgCode || 'default-organization-id',
						},
					});
				}

				const nameParts = real_name.split(' ');
				const firstName = nameParts[0] || '';
				const lastName = nameParts.length > 1 ? nameParts[1] : '';

				const accountExist = await tx.account.findFirst({
					where: {
						firstName: firstName,
						lastName: lastName,
					},
				});

				let account;
				if (accountExist) {
					account = await tx.account.update({
						where: {
							accountNum: accountExist.accountNum,
						},
						data: {
							userId: userResponse.id,
						},
					});
				}

				const certificateAuthority = await tx.certificateAuthority.findUnique({
					where: {
						caCode: caCode,
					},
				});

				if (!certificateAuthority) {
					throw new Error('Certificate Authority not found');
				}

				const certificateResponse = await tx.certificate.create({
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
						certificateAuthorityId: certificateAuthority.id,
						expiresAt: expiresAt,
					},
				});

				for (const consent of consent_list) {
					await tx.consent.create({
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

				return { certificateResponse, userResponse };
			});

			const responseData = {
				rsp_code: getResponseMessage('SUCCESS').code,
				rsp_msg: 'Electronic signature request successful, cert_tx_id has been provided.',
				sign_ios_app_scheme_url: `mydataauth://auth?tx_id=${certTxId}`,
				sign_aos_app_scheme_url: `mydataauth://auth?tx_id=${certTxId}`,
				sign_web_url: `https://mydataauth.com/auth?tx_id=${certTxId}`,
				cert_tx_id: certTxId,
			};

			const response = getResponseContent({
				headers: {
					xApiTranId: xApiTranId || '',
					contentType: 'application/json;charset=UTF-8',
				},
				body: responseData,
			});

			await logger(JSON.stringify(request), JSON.stringify(response), 200);
			return NextResponse.json(response, { status: 200 });
		} catch (dbError) {
			console.error('Database operation error:', dbError);
			const response = getResponseContent({
				headers: {
					xApiTranId: xApiTranId || '',
					contentType: 'application/json;charset=UTF-8',
				},
				body: getResponseMessage('DATABASE_ERROR'),
			});
			await logger(JSON.stringify(request), JSON.stringify(response), 500);
			return NextResponse.json(response, { status: 500 });
		}
	} catch (error) {
		console.error('Error in processing request:', error);
		const response = getResponseContent({
			headers: {
				xApiTranId: xApiTranId || '',
				contentType: 'application/json;charset=UTF-8',
			},
			body: getResponseMessage('INTERNAL_SERVER_ERROR'),
		});
		await logger(JSON.stringify(request), JSON.stringify(response), 500);
		return NextResponse.json(response, { status: 500 });
	}
}

// Helper function to check if token has been revoked
// This would typically check against a database or Redis cache
async function checkTokenRevocation(jti: string): Promise<boolean> {
	try {
		// Example implementation - replace with actual check against DB or cache
		// Since revokedToken model doesn't exist yet, we'll simulate a check
		// In a real implementation, you would have a proper table/model for revoked tokens

		// If the Prisma schema doesn't include RevokedToken model yet,
		// you would need to add it to your schema.prisma file

		// For now, return false (not revoked) as a placeholder
		// In production, implement this with an actual database check
		return false;

		/*
		// Once you've added RevokedToken to your Prisma schema:
		const revokedToken = await prisma.revokedToken.findUnique({
			where: {
				jti: jti,
			},
		});
		return !!revokedToken;
		*/
	} catch (error) {
		console.error('Error checking token revocation:', error);
		// Fail closed for security - treat errors as if the token is revoked
		return true;
	}
}
