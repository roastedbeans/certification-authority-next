/**
 * Utility functions for validation
 */

/**
 * Validates an Authorization header
 * @param header The Authorization header value
 * @returns true if the header is a valid Bearer token, false otherwise
 */
export const validateAuthorizationHeader = (header: string | null): boolean => {
	if (!header) return false;
	const [type, token] = header.split(' ');
	return type === 'Bearer' && !!token;
};
