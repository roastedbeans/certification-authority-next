// app/api/utils/signatureGenerator.ts
import { v4 as uuidv4 } from 'uuid';
import * as crypto from 'crypto';

interface SignatureInput {
	consent: string;
	privateKey: string;
	timestamp: string;
}

export function generateSignature(data: SignatureInput): string {
	// Create a basic signature payload
	const signaturePayload = {
		type: 'SignedConsent',
		version: '1.0',
		sign_tx_id: data.privateKey,
		timestamp: data.timestamp,
	};

	// Convert to string and encode to base64
	const jsonString = JSON.stringify(signaturePayload);
	const base64Signature = Buffer.from(jsonString).toString('base64');

	// Make it URL-safe
	return base64Signature.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

interface Consent {
	consentTitle: string;
	consent: string;
	txId: string;
}

// Helper function to create signed array of consent list
export function createSignedConsentList(consentList: Consent[], privateKey: string) {
	const signedConsentList = [];
	const timestamp = new Date().toISOString();

	for (const consent of consentList) {
		const signedConsent = generateSignature({
			consent: consent.consent,
			privateKey: privateKey,
			timestamp,
		});

		signedConsentList.push({
			signed_consent_len: signedConsent.length,
			signed_consent: signedConsent,
			tx_id: consent.txId,
		});
	}

	return signedConsentList;
}

export function generateCertTxId() {
	const timestamp = new Date()
		.toISOString()
		.replace(/[-:.TZ]/g, '')
		.slice(0, 14); // YYYYMMDDHHMMSS

	const id = uuidv4().replace(/-/g, ''); // Remove dashes from UUID

	return `${timestamp}${id}`.substring(0, 40); // Ensure it fits within 40 characters
}

// Function to sign transaction data (generate signature)
export function generateTxId(action: string, timestamp: string): string {
	// Generate 60 bytes of random data
	const randomBytes = crypto.randomBytes(60).toString('hex');

	return `${action}_${timestamp}_${randomBytes}`.substring(0, 74); // Ensure it fits within 74 characters
}
