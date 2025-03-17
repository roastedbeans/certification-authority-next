import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET || 'your-secure-secret';
const TOKEN_EXPIRY = 3600; // 1 hour in seconds

/**
 * Generates an OAuth 2.0 access token using JWT
 * @param clientId The client ID
 * @param scope The requested scope
 * @returns A signed JWT token
 */
export function generateAccessToken(clientId: string, scope: string, issuer: string): string {
	const payload = {
		iss: issuer,
		client_id: clientId,
		scope: scope,
		exp: Math.floor(Date.now() / 1000) + TOKEN_EXPIRY,
		iat: Math.floor(Date.now() / 1000),
		jti: Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15),
	};

	return jwt.sign(payload, JWT_SECRET);
}
