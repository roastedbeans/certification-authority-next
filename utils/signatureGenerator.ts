// app/api/utils/signatureGenerator.ts
import { v4 as uuidv4 } from 'uuid';

interface SignatureInput {
	cert_tx_id: string;
	sign_tx_id: string;
	timestamp: string;
}

export function generateSignature(data: SignatureInput): string {
	// Create a basic signature payload
	const signaturePayload = {
		type: 'SignedConsent',
		version: '1.0',
		cert_tx_id: data.cert_tx_id,
		sign_tx_id: data.sign_tx_id,
		timestamp: data.timestamp,
	};

	// Convert to string and encode to base64
	const jsonString = JSON.stringify(signaturePayload);
	const base64Signature = Buffer.from(jsonString).toString('base64');

	// Make it URL-safe
	return base64Signature.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// Helper function to create the full signature response
export function createSignatureResponse(certTxId: string, signTxId: string) {
	const timestamp = new Date().toISOString();

	const signedConsent = generateSignature({
		cert_tx_id: certTxId,
		sign_tx_id: signTxId,
		timestamp,
	});

	return {
		signed_consent: signedConsent,
		signed_consent_len: signedConsent.length,
	};
}

export function generateCertTxId() {
	const timestamp = new Date()
		.toISOString()
		.replace(/[-:.TZ]/g, '')
		.slice(0, 14); // YYYYMMDDHHMMSS
	const randomPart = Math.random().toString(36).substring(2, 12).toUpperCase(); // 10-character alphanumeric string
	return `${timestamp}${randomPart}`.substring(0, 40); // Ensure it fits within 40 characters
}

export function generateTxId() {
	const length = 74;

	// Generate a base UUID (e.g., "550e8400-e29b-41d4-a716-446655440000")
	const uuid = uuidv4().replace(/-/g, ''); // Remove dashes to create a clean alphanumeric base

	// Add randomness to ensure we reach exactly 74 characters
	const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
	let additionalChars = '';
	while (additionalChars.length + uuid.length < length) {
		const randomIndex = Math.floor(Math.random() * chars.length);
		additionalChars += chars[randomIndex];
	}

	// Combine the UUID and additional random characters to ensure 74 characters
	const txId = (uuid + additionalChars).slice(0, length);

	return txId;
}
