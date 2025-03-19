import { PrismaClient } from '@prisma/client';
import { faker } from '@faker-js/faker';
import dayjs from 'dayjs';

// Create PrismaClient singleton to prevent multiple instances during hot reloading
const globalForPrisma = globalThis as unknown as {
	prisma: PrismaClient | undefined;
};

export const prisma = globalForPrisma.prisma ?? new PrismaClient();

if (process.env.NODE_ENV !== 'production') globalForPrisma.prisma = prisma;

// Logger utility
const logger = {
	error: (message: string, error?: any) => {
		console.error(`[ERROR] ${message}`, error);
	},
	warn: (message: string) => {
		console.warn(`[WARN] ${message}`);
	},
	info: (message: string) => {
		console.info(`[INFO] ${message}`);
	},
};

// Custom error classes
class ValidationError extends Error {
	constructor(message: string) {
		super(message);
		this.name = 'ValidationError';
	}
}

class APIError extends Error {
	statusCode: number;
	errorCode: string;
	originalError: any;

	constructor(message: string, statusCode: number, errorCode: string, originalError?: any) {
		super(message);
		this.name = 'APIError';
		this.statusCode = statusCode;
		this.errorCode = errorCode;
		this.originalError = originalError;
	}
}

// Define types
export type BodyIA102 = {
	sign_tx_id: string;
	user_ci: string;
	real_name: string;
	phone_num: string;
	request_title: string;
	device_code: string;
	device_browser: string;
	return_app_scheme_url: string;
	consent_type: string;
	consent_cnt: number;
	consent_list: Consent[];
};

export type BodyIA103 = {
	cert_tx_id: string;
	sign_tx_id: string;
};

export type BodyIA002 = {
	tx_id: string;
	org_code: string;
	grant_type: string;
	client_id: string;
	client_secret: string;
	ca_code: string;
	username: string;
	request_type: string;
	password_len: string;
	password: string;
	auth_type: string;
	consent_type: string;
	consent_len: string;
	consent: string;
	signed_person_info_req_len: string;
	signed_person_info_req: string;
	consent_nonce: string;
	ucpid_nonce: string;
	cert_tx_id: string;
	service_id: string;
};

export type BodyIA104 = {
	tx_id: string;
	cert_tx_id: string;
	signed_consent_len: number;
	signed_consent: string;
	consent_type: string;
	consent_len: number;
	consent: string;
};

export type Consent = {
	tx_id: string;
	consent_title: string;
	consent: string;
	consent_len: number;
};

export type SignedConsent = {
	tx_id: string;
	signed_consent: string;
	signed_consent_len: number;
};

// Validation functions
const validateBodyIA102 = (body: BodyIA102): void => {
	if (!body.sign_tx_id) throw new ValidationError('sign_tx_id is required');
	if (!body.user_ci) throw new ValidationError('user_ci is required');
	if (!body.real_name) throw new ValidationError('real_name is required');
	if (!body.phone_num) throw new ValidationError('phone_num is required');
	if (!Array.isArray(body.consent_list)) throw new ValidationError('consent_list must be an array');
	if (body.consent_list.length === 0) throw new ValidationError('consent_list cannot be empty');
};

const validateBodyIA103 = (body: BodyIA103): void => {
	if (!body.cert_tx_id) throw new ValidationError('cert_tx_id is required');
	if (!body.sign_tx_id) throw new ValidationError('sign_tx_id is required');
};

const validateBodyIA002 = (body: BodyIA002): void => {
	if (!body.tx_id) throw new ValidationError('tx_id is required');
	if (!body.org_code) throw new ValidationError('org_code is required');
	if (!body.client_id) throw new ValidationError('client_id is required');
	if (!body.client_secret) throw new ValidationError('client_secret is required');
};

const validateBodyIA104 = (body: BodyIA104): void => {
	if (!body.tx_id) throw new ValidationError('tx_id is required');
	if (!body.cert_tx_id) throw new ValidationError('cert_tx_id is required');
	if (!body.signed_consent) throw new ValidationError('signed_consent is required');
	if (!body.consent) throw new ValidationError('consent is required');
};

// Attack configuration interface
interface AttackConfiguration {
	type: string;
	payload: string;
	location: string;
}

// Generate malicious content with error handling
const generateMaliciousContent = (attackLocation: string[]): AttackConfiguration | null => {
	//all attack location: x-api-tran-id, X-CSRF-Token, Cookie, Set-Cookie, User-Agent, search_timestamp, client_id, client_secret, grant_type, scope, username, password, org_code, account_num, next, return_app_scheme_url, device_code, device_browser, consent_type, consent_cnt, consent_list, signed_person_info_req_len, signed_person_info_req, consent_nonce, ucpid_nonce, cert_tx_id, service_id
	try {
		const attackConfigurations = [
			// XSS attacks
			...attackLocation
				.filter((location) => location !== 'Cookie')
				.map((location) => ({
					type: 'XSS',
					payload: faker.helpers.arrayElement([
						'<script>alert("XSS")</script>',
						'<img src="x" onerror="alert(\'XSS\')">',
						'<script>alert(document.cookie)</script>',
					]),
					location,
				})),

			// SQLi attacks
			...attackLocation
				.filter((location) => location === 'search_timestamp')
				.map((location) => ({
					type: 'SQLi',
					payload: faker.helpers.arrayElement([
						"' OR '1'='1",
						"'; DROP TABLE users--",
						"' UNION SELECT * FROM accounts--",
					]),
					location,
				})),

			// Cookie manipulation
			...['Cookie', 'Set-Cookie'].map((location) => ({
				type: 'CookieInjection',
				payload: faker.helpers.arrayElement(['session=admin123; Path=/', 'isAdmin=true; HttpOnly']),
				location,
			})),

			// Directory traversal
			...attackLocation.map((location) => ({
				type: 'DirectoryTraversal',
				payload: faker.helpers.arrayElement(['../../../etc/passwd', '../../../../etc/hosts']),
				location,
			})),

			// XML external entity injection
			...attackLocation.map((location) => ({
				type: 'XXE',
				payload: faker.helpers.arrayElement([
					'<!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>',
					'<!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "http://example.com/xxe" >]><foo>&xxe;</foo>',
					'<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>',
				]),
				location,
			})),

			// Payload Overflow attacks using repeat() of header
			...attackLocation.map((location) => ({
				type: 'PayloadOverflow',
				payload: faker.helpers.arrayElement([faker.number.bigInt().toString().repeat(10000)]),
				location,
			})),
		];

		const shouldAttack = faker.datatype.boolean(0.3); // 30% attack chance
		return shouldAttack ? faker.helpers.arrayElement(attackConfigurations) : null;
	} catch (error) {
		logger.error('Error generating malicious content', error);
		return null;
	}
};

// Process payload with error handling
const processPayload = (value: any, attack: AttackConfiguration | null, location: string): string => {
	try {
		if (attack && attack.location === location) {
			return attack.payload;
		}
		return value;
	} catch (error) {
		logger.error('Error processing payload', error);
		return value;
	}
};

// Generate transaction ID with error handling
export const generateTIN = (subject: string, orgCode: string): string => {
	//subject classification code
	try {
		const date = new Date();
		// grant code 10 uppercase letters + numbers
		const grantCode = faker.string.alphanumeric(14).toUpperCase();

		const xApiTranId = `${orgCode}${subject}${grantCode}`;

		return xApiTranId;
	} catch (error) {
		logger.error('Error generating TIN', error);
		return '00000000000000';
	}
};

// Generate timestamp with error handling
export function timestamp(date: Date): string {
	try {
		return date
			.toISOString()
			.replace(/[-:.TZ]/g, '')
			.slice(0, 14);
	} catch (error) {
		logger.error('Error generating timestamp', error);
		return Date.now().toString();
	}
}

// API Functions aligned with simulate.ts but keeping attack simulation
export const getIA101 = async (orgCode: string, clientId: string, clientSecret: string) => {
	try {
		const attackLocations = [
			'x-api-tran-id',
			'X-CSRF-Token',
			'Cookie',
			'Set-Cookie',
			'User-Agent',
			'client_id',
			'client_secret',
			'grant_type',
			'scope',
		];

		const attack = generateMaliciousContent(attackLocations);

		const options = {
			method: 'POST',
			headers: {
				'Content-Type': 'application/x-www-form-urlencoded',
				'x-api-tran-id': processPayload(generateTIN('S', orgCode), attack, 'x-api-tran-id'),
				'X-CSRF-Token': processPayload('', attack, 'X-CSRF-Token'),
				Cookie: processPayload('', attack, 'Cookie'),
				'Set-Cookie': processPayload('', attack, 'Set-Cookie'),
				'User-Agent': processPayload('Mozilla/5.0', attack, 'User-Agent'),
				'attack-type': attack?.type || '',
			},
			body: new URLSearchParams({
				grant_type: processPayload('client_credentials', attack, 'grant_type'),
				client_id: processPayload(clientId, attack, 'client_id'),
				client_secret: processPayload(clientSecret, attack, 'client_secret'),
				scope: processPayload('ca', attack, 'scope'),
			}),
		};

		logger.info('requesting token from certification authority');
		const response = await fetch('http://localhost:3000/api/oauth/2.0/token', options);

		if (!response.ok) {
			// Handle HTTP errors
			throw new Error(`HTTP error! Status: ${response.status}`);
		}

		const res = await response.json();
		return res;
	} catch (error) {
		logger.error('Error in getIA101:', error);
		throw error;
	}
};

// Normal simulation for IA102 with attack functionality
export const getIA102 = async (accessToken: string, body: BodyIA102, orgCode: string) => {
	try {
		if (!accessToken) throw new ValidationError('Access token is required');
		validateBodyIA102(body);

		const attackLocations = ['x-api-tran-id', 'X-CSRF-Token', 'Cookie', 'Set-Cookie', 'User-Agent'];
		const attack = generateMaliciousContent(attackLocations);

		const options = {
			method: 'POST',
			headers: {
				'Access-Control-Allow-Origin': '*',
				'Content-Type': 'application/json;charset=UTF-8',
				'x-api-tran-id': processPayload(generateTIN('S', orgCode), attack, 'x-api-tran-id'),
				'X-CSRF-Token': processPayload('', attack, 'X-CSRF-Token'),
				Cookie: processPayload('', attack, 'Cookie'),
				'Set-Cookie': processPayload('', attack, 'Set-Cookie'),
				'User-Agent': processPayload('Mozilla/5.0', attack, 'User-Agent'),
				'attack-type': attack?.type || '',
				Authorization: `Bearer ${accessToken}`,
			},
			body: JSON.stringify(body),
		};

		logger.info('requesting sign request from certification authority');
		const response = await fetch(`http://localhost:3000/api/ca/sign_request`, options);

		if (!response.ok) {
			// Handle HTTP errors
			throw new Error(`HTTP error on IA102! Status: ${response.status}`);
		}

		const res = await response.json();
		return res;
	} catch (error) {
		logger.error('Error in getIA102:', error);
		throw error;
	}
};

export const getIA103 = async (accessToken: string, body: BodyIA103, orgCode: string) => {
	try {
		if (!accessToken) throw new ValidationError('Access token is required');
		validateBodyIA103(body);

		const attackLocations = ['x-api-tran-id', 'X-CSRF-Token', 'Cookie', 'Set-Cookie', 'User-Agent'];
		const attack = generateMaliciousContent(attackLocations);

		const options = {
			method: 'POST',
			headers: {
				'Access-Control-Allow-Origin': '*',
				'Content-Type': 'application/json;charset=UTF-8',
				'x-api-tran-id': processPayload(generateTIN('S', orgCode), attack, 'x-api-tran-id'),
				'X-CSRF-Token': processPayload('', attack, 'X-CSRF-Token'),
				Cookie: processPayload('', attack, 'Cookie'),
				'Set-Cookie': processPayload('', attack, 'Set-Cookie'),
				'User-Agent': processPayload('Mozilla/5.0', attack, 'User-Agent'),
				'attack-type': attack?.type || '',
				Authorization: `Bearer ${accessToken}`,
			},
			body: JSON.stringify(body),
		};

		logger.info('requesting sign result from certification authority');
		const response = await fetch(`http://localhost:3000/api/ca/sign_result`, options);

		if (!response.ok) {
			// Handle HTTP errors
			throw new Error(`HTTP error on IA103! Status: ${response.status}`);
		}

		const res = await response.json();
		return res;
	} catch (error) {
		logger.error('Error in getIA103:', error);
		throw error;
	}
};

export const getIA002 = async (body: BodyIA002, otherBankAPI: string, orgCode: string) => {
	try {
		validateBodyIA002(body);

		const attackLocations = ['x-api-tran-id', 'X-CSRF-Token', 'Cookie', 'Set-Cookie', 'User-Agent'];
		const attack = generateMaliciousContent(attackLocations);

		const options = {
			method: 'POST',
			headers: {
				'Content-Type': 'application/x-www-form-urlencoded',
				'x-api-tran-id': processPayload(generateTIN('S', orgCode), attack, 'x-api-tran-id'),
				'X-CSRF-Token': processPayload('', attack, 'X-CSRF-Token'),
				Cookie: processPayload('', attack, 'Cookie'),
				'Set-Cookie': processPayload('', attack, 'Set-Cookie'),
				'User-Agent': processPayload('Mozilla/5.0', attack, 'User-Agent'),
				'attack-type': attack?.type || '',
			},
			body: new URLSearchParams(body),
		};

		const response = await fetch(`${otherBankAPI}/api/oauth/2.0/token`, options);

		if (!response.ok) {
			// Handle HTTP errors
			throw new Error(`HTTP error on IA002! Status: ${response.status}`);
		}

		const res = await response.json();
		return res;
	} catch (error) {
		logger.error('Error in getIA002:', error);
		throw error;
	}
};

export const getIA104 = async (accessToken: string, body: BodyIA104, orgCode: string) => {
	try {
		if (!accessToken) throw new ValidationError('Access token is required');
		validateBodyIA104(body);

		const attackLocations = ['x-api-tran-id', 'X-CSRF-Token', 'Cookie', 'Set-Cookie', 'User-Agent'];
		const attack = generateMaliciousContent(attackLocations);

		const options = {
			method: 'POST',
			headers: {
				'Access-Control-Allow-Origin': '*',
				'Content-Type': 'application/json;charset=UTF-8',
				'x-api-tran-id': processPayload(generateTIN('S', orgCode), attack, 'x-api-tran-id'),
				'X-CSRF-Token': processPayload('', attack, 'X-CSRF-Token'),
				Cookie: processPayload('', attack, 'Cookie'),
				'Set-Cookie': processPayload('', attack, 'Set-Cookie'),
				'User-Agent': processPayload('Mozilla/5.0', attack, 'User-Agent'),
				'attack-type': attack?.type || '',
				Authorization: `Bearer ${accessToken}`,
			},
			body: JSON.stringify(body),
		};

		const response = await fetch(`http://localhost:3000/api/ca/sign_verification`, options);

		if (!response.ok) {
			// Handle HTTP errors
			throw new Error(`HTTP error on IA104! Status: ${response.status}`);
		}

		const res = await response.json();
		return res;
	} catch (error) {
		logger.error('Error in getIA104:', error);
		throw error;
	}
};

export async function getSupport001(orgCode: string, clientId: string, clientSecret: string) {
	try {
		const attackLocations = [
			'x-api-tran-id',
			'X-CSRF-Token',
			'Cookie',
			'Set-Cookie',
			'User-Agent',
			'client_id',
			'client_secret',
			'grant_type',
			'scope',
		];

		const attack = generateMaliciousContent(attackLocations);

		const options = {
			method: 'POST',
			headers: {
				'Content-Type': 'application/x-www-form-urlencoded',
				'x-api-tran-id': processPayload(generateTIN('S', orgCode), attack, 'x-api-tran-id'),
				'X-CSRF-Token': processPayload('', attack, 'X-CSRF-Token'),
				Cookie: processPayload('', attack, 'Cookie'),
				'Set-Cookie': processPayload('', attack, 'Set-Cookie'),
				'User-Agent': processPayload('Mozilla/5.0', attack, 'User-Agent'),
				'attack-type': attack?.type || '',
				Authorization: '',
			},
			body: new URLSearchParams({
				grant_type: processPayload('client_credentials', attack, 'grant_type'),
				client_id: processPayload(clientId, attack, 'client_id'),
				client_secret: processPayload(clientSecret, attack, 'client_secret'),
				scope: processPayload('manage', attack, 'scope'),
			}),
		};

		const response = await fetch('http://localhost:3000/api/v2/mgmts/oauth/2.0/token', options);

		if (!response.ok) {
			// Handle HTTP errors
			throw new Error(`HTTP error! Status: ${response.status}`);
		}

		const data = await response.json();
		return data;
	} catch (error) {
		logger.error('Error in getSupport001:', error);
		throw error;
	}
}

export async function getSupport002(orgCode: string, clientId: string, clientSecret: string) {
	try {
		const support001Response = await getSupport001(orgCode, clientId, clientSecret);

		const { access_token } = support001Response?.body;
		if (!access_token) {
			throw new APIError('Failed to obtain management token', 401, 'UNAUTHORIZED');
		}

		const attackLocations = [
			'x-api-tran-id',
			'Cookie',
			'Set-Cookie',
			'User-Agent',
			'Authorization',
			'search_timestamp',
		];
		const attack = generateMaliciousContent(attackLocations);

		const options = {
			method: 'GET',
			headers: {
				'Access-Control-Allow-Origin': '*',
				'Content-Type': 'application/json;charset=UTF-8',
				'x-api-tran-id': processPayload(generateTIN('S', orgCode), attack, 'x-api-tran-id'),
				Cookie: processPayload('', attack, 'Cookie'),
				'Set-Cookie': processPayload('', attack, 'Set-Cookie'),
				'User-Agent': processPayload('Mozilla/5.0', attack, 'User-Agent'),
				'attack-type': attack?.type || '',
				Authorization: `Bearer ${processPayload(access_token, attack, 'Authorization')}`,
			},
		};

		const response = await fetch(
			`http://localhost:3000/api/v2/mgmts/orgs?search_timestamp=${processPayload(
				timestamp(new Date()),
				attack,
				'search_timestamp'
			)}`,
			options
		);

		if (!response.ok) {
			// Handle HTTP errors
			throw new Error(`HTTP error! Status: ${response.status}`);
		}

		const res = await response.json();
		return res;
	} catch (error) {
		logger.error('Error in getSupport002:', error);
		throw error;
	}
}

const getAccountsBasic = async (
	orgCode: string,
	accountNum: string,
	accessToken: string,
	otherOrgCode: string,
	otherBankAPI: string
) => {
	try {
		if (!orgCode) throw new ValidationError('Organization code is required');
		if (!accountNum) throw new ValidationError('Account number is required');
		if (!accessToken) throw new ValidationError('Access token is required');

		const attackLocations = ['x-api-tran-id', 'X-CSRF-Token', 'Cookie', 'Set-Cookie', 'User-Agent', 'x-api-type'];
		const attack = generateMaliciousContent(attackLocations);

		const options = {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json;charset=UTF-8',
				'x-api-tran-id': processPayload(generateTIN('S', orgCode), attack, 'x-api-tran-id'),
				'x-api-type': processPayload(faker.helpers.arrayElement(['regular', 'irregular']), attack, 'x-api-type'),
				'X-CSRF-Token': processPayload('', attack, 'X-CSRF-Token'),
				Cookie: processPayload('', attack, 'Cookie'),
				'Set-Cookie': processPayload('', attack, 'Set-Cookie'),
				'User-Agent': processPayload('Mozilla/5.0', attack, 'User-Agent'),
				'attack-type': attack?.type || '',
				Authorization: `Bearer ${accessToken}`,
			},
			body: JSON.stringify({
				org_code: otherOrgCode,
				account_num: accountNum,
				next: '0',
				search_timestamp: timestamp(new Date()),
			}),
		};

		logger.info('Getting basic account information');
		const response = await fetch(`${otherBankAPI}/api/v2/bank/accounts/deposit/basic`, options);

		if (!response.ok) {
			// Handle HTTP errors
			throw new Error(`HTTP error! Status: ${response.status}`);
		}

		const data = await response.json();
		return data;
	} catch (error) {
		logger.error('Error in getAccountsBasic:', error);
		throw error;
	}
};

const getAccountsDetail = async (
	orgCode: string,
	accountNum: string,
	accessToken: string,
	otherOrgCode: string,
	otherBankAPI: string
) => {
	try {
		if (!orgCode) throw new ValidationError('Organization code is required');
		if (!accountNum) throw new ValidationError('Account number is required');
		if (!accessToken) throw new ValidationError('Access token is required');

		const attackLocations = [
			'x-api-tran-id',
			'X-CSRF-Token',
			'Cookie',
			'Set-Cookie',
			'User-Agent',
			'x-api-type',
			'search_timestamp',
		];
		const attack = generateMaliciousContent(attackLocations);

		const options = {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json;charset=UTF-8',
				'x-api-tran-id': processPayload(generateTIN('S', orgCode), attack, 'x-api-tran-id'),
				'x-api-type': processPayload(faker.helpers.arrayElement(['regular', 'irregular']), attack, 'x-api-type'),
				'X-CSRF-Token': processPayload('', attack, 'X-CSRF-Token'),
				Cookie: processPayload('', attack, 'Cookie'),
				'Set-Cookie': processPayload('', attack, 'Set-Cookie'),
				'User-Agent': processPayload('Mozilla/5.0', attack, 'User-Agent'),
				'attack-type': attack?.type || '',
				Authorization: `Bearer ${accessToken}`,
			},
			body: JSON.stringify({
				org_code: otherOrgCode,
				account_num: accountNum,
				next: '0',
				search_timestamp: processPayload(timestamp(new Date()), attack, 'search_timestamp'),
			}),
		};

		logger.info('Getting detailed account information');
		const response = await fetch(`${otherBankAPI}/api/v2/bank/accounts/deposit/detail`, options);

		if (!response.ok) {
			// Handle HTTP errors
			throw new Error(`HTTP error! Status: ${response.status}`);
		}

		const data = await response.json();
		return data;
	} catch (error) {
		logger.error('Error in getAccountsDetail:', error);
		throw error;
	}
};

// Generate BodyIA102 with error handling (keeping from original simulateV2)
export const generateBodyIA102 = async (
	account: any,
	orgCode: string,
	otherOrgCode: string,
	otherBankAPI: string
): Promise<BodyIA102> => {
	try {
		if (!account) throw new ValidationError('Account is required');

		const caCode = faker.helpers.arrayElement(['certauth00']);
		const newTimestamp = timestamp(new Date());
		const serialNum = faker.helpers.arrayElement(['anyaserial00', 'bondserial00']);

		const signTxId = `${orgCode}_${caCode}_${newTimestamp}_${serialNum}`;
		const firstName = account.firstName;
		const lastName = account.lastName;

		if (!account.pinCode) throw new ValidationError('Account PIN code is required');
		const b64UserCI = Buffer.from(account.pinCode).toString('base64');

		const fullName = `${firstName} ${lastName}`;
		const phoneNum = account.phoneNumber;

		const requestTitle = faker.helpers.arrayElement([
			'Request for Consent to Use Personal Information',
			'Request for Consent to Use Personal Information for Marketing',
			'Request for Consent to Use Personal Information for Research',
		]);

		const deviceCode = faker.helpers.arrayElement(['PC', 'MO', 'TB']);
		const relayAgencyCode = faker.helpers.arrayElement(['ra20250001', 'ra20250002', 'ra20250003']);

		const consentTitles = [
			'Consent Request for Transmission',
			'Consent to Collection and Use of Personal Information',
			'Consent to Provide Personal Information',
		];

		const consentValues = ['consent-001', 'consent-002', 'consent-003'];
		const numConsents = faker.number.int({ min: 1, max: 3 });

		const consent_list = Array.from({ length: numConsents }, (_, index) => {
			const consent = faker.helpers.arrayElement(consentValues);
			const shaConsent = Buffer.from(consent).toString('base64');
			const txId = `MD_${orgCode}_${otherOrgCode}_${relayAgencyCode}_${caCode}_${newTimestamp}_${
				'XXAB0049000' + index
			}`;

			return {
				tx_id: txId,
				consent_title: consentTitles[index],
				consent: shaConsent,
				consent_len: shaConsent.length,
			};
		});

		const body: BodyIA102 = {
			sign_tx_id: signTxId,
			user_ci: b64UserCI,
			real_name: fullName,
			phone_num: phoneNum,
			request_title: requestTitle,
			device_code: deviceCode,
			device_browser: 'WB',
			return_app_scheme_url: 'https://anya-bank.com/return',
			consent_type: '1',
			consent_cnt: consent_list.length,
			consent_list: consent_list,
		};

		validateBodyIA102(body);
		return body;
	} catch (error) {
		logger.error('Error generating BodyIA102', error);
		throw error;
	}
};

// Generate BodyIA002 with error handling (keeping from original simulateV2)
export const generateBodyIA002 = async (
	certTxId: string,
	consent_list: Consent[],
	signed_consent_list: SignedConsent[]
): Promise<BodyIA002> => {
	try {
		if (!certTxId) throw new ValidationError('certTxId is required');
		if (!consent_list?.length) throw new ValidationError('consent_list is required');
		if (!signed_consent_list?.length) throw new ValidationError('signed_consent_list is required');

		const txId = signed_consent_list[0].tx_id;
		const parts = txId.split('_');
		const orgCode = parts[1]; // Updated to match simulate.ts pattern
		const ipCode = parts[2]; // Updated to match simulate.ts pattern
		const raCode = parts[3]; // Updated to match simulate.ts pattern
		const caCode = parts[4]; // Updated to match simulate.ts pattern

		const organization = await prisma.organization.findFirst({
			where: { orgCode: ipCode },
		});

		if (!organization) throw new ValidationError('Organization not found');

		const oAuthClient = await prisma.oAuthClient.findFirst({
			where: { organizationId: organization?.id },
		});

		if (!oAuthClient) throw new ValidationError('OAuth client not found');

		const certificate = await prisma.certificate.findFirst({
			where: { certTxId: certTxId },
		});

		if (!certificate) throw new ValidationError('Certificate not found');

		const account = await prisma.account.findFirst({
			where: { phoneNumber: certificate?.phoneNumber },
		});

		if (!account) throw new ValidationError('Account not found');

		const registrationDate = dayjs().format('DDMMYYYY');
		const serialNum = '0001';

		const generateNonce = () => {
			const letter = faker.string.alpha({ casing: 'upper', length: 1 });
			const year = dayjs().format('YYYY');
			const randomNumber = faker.number.int({ min: 100000000000000, max: 999999999999999 });
			return `${letter}${year}${randomNumber}`;
		};

		const b64PersonInfo = Buffer.from(account.firstName + account.lastName).toString('base64');
		const b64UserCI = Buffer.from(account.pinCode).toString('base64');
		const b64Password = Buffer.from('PASSWORD').toString('base64');

		const body: BodyIA002 = {
			tx_id: txId,
			org_code: orgCode,
			grant_type: 'password',
			client_id: oAuthClient.clientId,
			client_secret: oAuthClient.clientSecret,
			ca_code: caCode,
			username: b64UserCI,
			request_type: '1',
			password_len: b64Password.length.toString(),
			password: b64Password,
			auth_type: '1',
			consent_type: '1',
			consent_len: consent_list[0].consent_len.toString(),
			consent: consent_list[0].consent,
			signed_person_info_req_len: b64PersonInfo.length.toString(),
			signed_person_info_req: b64PersonInfo,
			consent_nonce: generateNonce(),
			ucpid_nonce: generateNonce(),
			cert_tx_id: certTxId,
			service_id: `${ipCode}${registrationDate}${serialNum}`,
		};

		validateBodyIA002(body);
		return body;
	} catch (error) {
		logger.error('Error generating BodyIA002', error);
		throw error;
	}
};

const generateBodyIA104 = async (certTxId: string, consent_list: any, signed_consent_list: any) => {
	try {
		if (!certTxId) throw new ValidationError('certTxId is required');
		if (!consent_list?.length) throw new ValidationError('consent_list is required');
		if (!signed_consent_list?.length) throw new ValidationError('signed_consent_list is required');

		const txId = signed_consent_list[0].tx_id;

		const bodyIA104 = {
			tx_id: txId,
			cert_tx_id: certTxId,
			signed_consent_len: signed_consent_list[0].signed_consent_len,
			signed_consent: signed_consent_list[0].signed_consent,
			consent_type: '1',
			consent_len: consent_list[0].consent_len,
			consent: consent_list[0].consent,
		};

		validateBodyIA104(bodyIA104);
		return bodyIA104;
	} catch (error) {
		logger.error('Error generating BodyIA104', error);
		throw error;
	}
};

// Main simulation function with comprehensive error handling
async function main(
	orgCode: string,
	clientId: string,
	clientSecret: string,
	otherOrgCode: string,
	otherBankAPI: string
) {
	try {
		// Interaction 1: User wants to sign up
		logger.info('Starting simulation: User sign-up');
		const response = await getSupport002(orgCode, clientId, clientSecret);

		if (!response) {
			throw new Error('Error fetching organization list');
		}

		// Interaction 2: User wants to connect their accounts to the selected banks
		logger.info('Starting simulation: Connect accounts to banks');
		const IA101Response = await getIA101(orgCode, clientId, clientSecret);

		const { access_token } = IA101Response?.body;

		if (!access_token) {
			throw new Error('Error fetching access token in IA101');
		}

		// add delay to simulate user interaction
		await new Promise((resolve) => setTimeout(resolve, 2000));

		// Get all the accounts that belong to the organization
		const accounts = await prisma.account.findMany({
			where: {
				orgCode: orgCode,
			},
		});

		if (!accounts || accounts.length === 0) {
			throw new Error('Error fetching accounts');
		}

		const account = faker.helpers.arrayElement(accounts);
		const accountNum = account.accountNum;

		const bodyIA102 = await generateBodyIA102(account, orgCode, otherOrgCode, otherBankAPI);

		const responseIA102 = await getIA102(access_token, bodyIA102, orgCode);
		if (!responseIA102) {
			throw new Error('Error sign request in IA102');
		}

		// add delay to simulate user interaction
		await new Promise((resolve) => setTimeout(resolve, 4000));

		const bodyIA103: BodyIA103 = {
			sign_tx_id: bodyIA102.sign_tx_id,
			cert_tx_id: responseIA102?.body?.cert_tx_id,
		};

		const responseIA103 = await getIA103(access_token, bodyIA103, orgCode);
		if (!responseIA103) {
			throw new Error('Error sign result in IA103');
		}

		// add delay to simulate user interaction
		await new Promise((resolve) => setTimeout(resolve, 4000));

		// Interaction 3: User wants to access their data from other banks
		logger.info('Starting simulation: Access data from other banks');

		const certTxId = responseIA102?.body?.cert_tx_id;
		const signedConsentList = responseIA103?.body?.signed_consent_list;
		const consentList = bodyIA102?.consent_list;

		const bodyIA002 = await generateBodyIA002(certTxId, consentList, signedConsentList);
		const responseIA002 = await getIA002(bodyIA002, otherBankAPI, orgCode);

		if (!responseIA002) {
			throw new Error('Error request for access token in IA002');
		}

		// add delay to simulate user interaction
		await new Promise((resolve) => setTimeout(resolve, 2000));

		// Interaction 4: Certification authority will provide a sign verification
		logger.info('Starting simulation: Sign verification');

		const bodyIA104 = await generateBodyIA104(certTxId, consentList, signedConsentList);
		const responseIA104 = await getIA104(responseIA002?.body?.access_token, bodyIA104, orgCode);

		if (!responseIA104) {
			throw new Error('Error sign verification in IA104');
		}

		const { result, user_ci } = responseIA104?.body;

		if (!result) {
			throw new Error('Sign verification result denied in IA104');
		}

		// Interaction 5: User wants to view their accounts from other banks
		logger.info('Starting simulation: View accounts from other banks');

		if (result) {
			const isGetBasic = faker.helpers.arrayElement([true, false]);
			const isGetDetail = faker.helpers.arrayElement([true, false]);

			console.log('responseIA104', result, user_ci);

			if (isGetBasic) {
				// Call for basic account information
				console.log('Getting basic account information');
				const accountsBasic = await getAccountsBasic(
					orgCode,
					accountNum,
					responseIA002.body.access_token,
					otherOrgCode,
					otherBankAPI
				);
				if (!accountsBasic) {
					throw new Error('Error fetching basic account information');
				}

				// add delay to simulate user interaction
				await new Promise((resolve) => setTimeout(resolve, 2000));
			}

			if (isGetDetail) {
				// Call for detailed account information
				console.log('Getting detailed account information');
				const accountsDetail = await getAccountsDetail(
					orgCode,
					accountNum,
					responseIA002.body.access_token,
					otherOrgCode,
					otherBankAPI
				);
				if (!accountsDetail) {
					throw new Error('Error fetching detailed account information');
				}

				// add delay to simulate user interaction
				await new Promise((resolve) => setTimeout(resolve, 2000));
			}
		}

		logger.info('Simulation completed successfully');
	} catch (error) {
		if (error instanceof APIError) {
			logger.error(`API Error: ${error.message}`, {
				statusCode: error.statusCode,
				errorCode: error.errorCode,
				originalError: error.originalError,
			});
		} else if (error instanceof ValidationError) {
			logger.error(`Validation Error: ${error.message}`);
		} else {
			logger.error('Unexpected error in main function', error);
		}
		throw error;
	}
}

// Run iterations with retry logic
export async function runAttackIterations(
	iterations: number = 100,
	orgCode: string,
	clientId: string,
	clientSecret: string,
	otherOrgCode: string,
	otherBankAPI: string
) {
	const delayBetweenIterations = 1000; // Delay between iterations in milliseconds (e.g., 1 second)

	for (let i = 0; i < iterations; i++) {
		try {
			await main(orgCode, clientId, clientSecret, otherOrgCode, otherBankAPI); // Run the main function
			console.log(`Attack iteration ${i + 1} completed.`);
		} catch (error) {
			console.error(`Error in attack iteration ${i + 1}:`, error);
		}

		// Add a delay between iterations to avoid overwhelming the system
		await new Promise((resolve) => setTimeout(resolve, delayBetweenIterations));
	}

	console.log('All attack iterations completed.');
}

// // Only run if this is the main module
// if (require.main === module) {
// 	// Run the iterations
// 	runIterations()
// 		.catch((e) => {
// 			console.error('Error during attack iterations:', e);
// 			process.exit(1);
// 		})
// 		.finally(async () => {
// 			await prisma.$disconnect();
// 		});
// }
