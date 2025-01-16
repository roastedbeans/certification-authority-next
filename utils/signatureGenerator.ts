// app/api/utils/signatureGenerator.ts

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
