import { faker } from '@faker-js/faker';
import dayjs from 'dayjs';
import { PrismaClient } from '@prisma/client';

// Create PrismaClient singleton to prevent multiple instances during hot reloading
const globalForPrisma = globalThis as unknown as {
	prisma: PrismaClient | undefined;
};

export const prisma = globalForPrisma.prisma ?? new PrismaClient();

if (process.env.NODE_ENV !== 'production') globalForPrisma.prisma = prisma;

// Get URLs from environment or use default for local development
export const CA_API_URL = process.env.CA_API_URL || 'http://localhost:3000';
export const IP_API_URL = process.env.ANYA_BANK_API || 'http://localhost:4000';
export const MO_API_URL = process.env.BOND_BANK_API || 'http://localhost:4200';

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

export type BodyIA104 = {
	tx_id: string;
	cert_tx_id: string;
	signed_consent_len: number;
	signed_consent: string;
	consent_type: string;
	consent_len: number;
	consent: string;
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

export const generateTIN = (subject: string, orgCode: string): string => {
	try {
		const date = new Date();
		const grantCode = faker.string.alphanumeric(14).toUpperCase();
		const xApiTranId = `${orgCode}${subject}${grantCode}`;
		return xApiTranId;
	} catch (error) {
		console.error('Error generating TIN:', error);
		return '00000000000000';
	}
};

export function timestamp(date: Date): string {
	const timestamp = date
		.toISOString()
		.replace(/[-:.TZ]/g, '')
		.slice(0, 14);
	return timestamp;
}

export const getIA101 = async (orgCode: string, clientId: string, clientSecret: string, isAttack: boolean = false) => {
	try {
		const headers: any = {
			'Content-Type': 'application/x-www-form-urlencoded',
			'x-api-tran-id': generateTIN('S', orgCode),
		};

		if (isAttack) {
			headers['attack-type'] = 'invalid-business-flow';
		}

		const options = {
			method: 'POST',
			headers,
			body: new URLSearchParams({
				grant_type: 'client_credentials',
				client_id: clientId,
				client_secret: clientSecret,
				scope: 'ca',
			}),
		};
		console.log('requesting token from certification authority');
		const response = await fetch(`${CA_API_URL}/api/oauth/2.0/token`, options);

		if (!response.ok) {
			throw new Error(`HTTP error! Status: ${response.status}`);
		}

		const res = await response.json();
		return res;
	} catch (error) {
		console.error('Error:', error);
		throw error;
	}
};

export const getIA102 = async (accessToken: string, body: BodyIA102, orgCode: string, isAttack: boolean = false) => {
	const headers: any = {
		'Access-Control-Allow-Origin': '*',
		'Content-Type': 'application/json;charset=UTF-8',
		'x-api-tran-id': generateTIN('S', orgCode),
		Authorization: `Bearer ${accessToken}`,
	};

	if (isAttack) {
		headers['attack-type'] = 'invalid-business-flow';
	}

	const options = {
		method: 'POST',
		headers,
		body: JSON.stringify(body),
	};

	console.log('requesting sign request from certification authority');
	const response = await fetch(`${CA_API_URL}/api/ca/sign_request`, options);

	if (!response.ok) {
		throw new Error(`HTTP error on IA102! Status: ${response.status}`);
	}

	const res = await response.json();
	return res;
};

export const getIA103 = async (accessToken: string, body: BodyIA103, orgCode: string, isAttack: boolean = false) => {
	const headers: any = {
		'Access-Control-Allow-Origin': '*',
		'Content-Type': 'application/json;charset=UTF-8',
		'x-api-tran-id': generateTIN('S', orgCode),
		Authorization: `Bearer ${accessToken}`,
	};

	if (isAttack) {
		headers['attack-type'] = 'invalid-business-flow';
	}

	const options = {
		method: 'POST',
		headers,
		body: JSON.stringify(body),
	};
	console.log('requesting sign result from certification authority');
	const response = await fetch(`${CA_API_URL}/api/ca/sign_result`, options);

	if (!response.ok) {
		throw new Error(`HTTP error on IA103! Status: ${response.status}`);
	}
	const res = await response.json();
	return res;
};

export const getIA002 = async (body: BodyIA002, otherBankAPI: string, orgCode: string, isAttack: boolean = false) => {
	const headers: any = {
		'Content-Type': 'application/x-www-form-urlencoded',
		'x-api-tran-id': generateTIN('S', orgCode),
	};

	if (isAttack) {
		headers['attack-type'] = 'invalid-business-flow';
	}

	const options = {
		method: 'POST',
		headers,
		body: new URLSearchParams(body),
	};

	let apiUrl = otherBankAPI;
	if (otherBankAPI.includes('4000')) {
		apiUrl = IP_API_URL;
	} else if (otherBankAPI.includes('4200')) {
		apiUrl = MO_API_URL;
	}

	console.log(`Requesting token from ${apiUrl}/api/oauth/2.0/token`);
	const response = await fetch(`${apiUrl}/api/oauth/2.0/token`, options);

	if (!response.ok) {
		throw new Error(`HTTP error on IA002! Status: ${response.status}`);
	}
	const res = await response.json();
	return res;
};

export const getIA104 = async (accessToken: string, body: BodyIA104, orgCode: string, isAttack: boolean = false) => {
	const headers: any = {
		'Access-Control-Allow-Origin': '*',
		'Content-Type': 'application/json;charset=UTF-8',
		'x-api-tran-id': generateTIN('S', orgCode),
		Authorization: `Bearer ${accessToken}`,
	};

	if (isAttack) {
		headers['attack-type'] = 'invalid-business-flow';
	}

	const options = {
		method: 'POST',
		headers,
		body: JSON.stringify(body),
	};

	const response = await fetch(`${CA_API_URL}/api/ca/sign_verification`, options);
	const res = await response.json();
	return res;
};

export async function getSupport001(
	orgCode: string,
	clientId: string,
	clientSecret: string,
	isAttack: boolean = false
) {
	try {
		const headers: any = {
			'Content-Type': 'application/x-www-form-urlencoded',
			'x-api-tran-id': generateTIN('S', orgCode),
			Authorization: '',
		};

		if (isAttack) {
			headers['attack-type'] = 'invalid-business-flow';
		}

		const options = {
			method: 'POST',
			headers,
			body: new URLSearchParams({
				grant_type: 'client_credentials',
				client_id: clientId,
				client_secret: clientSecret,
				scope: 'manage',
			}),
		};

		const response = await fetch(`${CA_API_URL}/api/v2/mgmts/oauth/2.0/token`, options);

		if (!response.ok) {
			throw new Error(`HTTP error! Status: ${response.status}`);
		}

		const data = await response.json();
		return data;
	} catch (error) {
		console.error('Error:', error);
		throw error;
	}
}

export async function getSupport002(
	orgCode: string,
	clientId: string,
	clientSecret: string,
	isAttack: boolean = false
) {
	const support001Response = await getSupport001(orgCode, clientId, clientSecret, isAttack);

	const { access_token } = support001Response?.body;

	const headers: any = {
		'Access-Control-Allow-Origin': '*',
		'Content-Type': 'application/json;charset=UTF-8',
		'x-api-tran-id': generateTIN('S', orgCode),
		Authorization: `Bearer ${access_token}`,
	};

	if (isAttack) {
		headers['attack-type'] = 'invalid-business-flow';
	}

	const options = {
		method: 'GET',
		headers,
	};

	const response = await fetch(`${CA_API_URL}/api/v2/mgmts/orgs?search_timestamp=`, options);

	if (!response.ok) {
		throw new Error(`HTTP error! Status: ${response.status}`);
	}

	const res = await response.json();
	return res;
}

export const generateBodyIA102 = async (account: any, orgCode: string, otherOrgCode: string) => {
	const caCode = faker.helpers.arrayElement(['certauth00']);
	const newTimestamp = timestamp(new Date());
	const serialNum = faker.helpers.arrayElement(['anyaserial00', 'bondserial00']);

	const signTxId = `${orgCode}_${caCode}_${newTimestamp}_${serialNum}`;

	const firstName = account.firstName;
	const lastName = account.lastName;
	const b64UserCI = Buffer.from(account.pinCode).toString('base64');

	const fullName = `${firstName} ${lastName}`;
	const phoneNum = account.phoneNumber;

	const requestTitle = faker.helpers.arrayElement([
		'Request for Consent to Use Personal Information',
		'Request for Consent to Use Personal Information for Marketing',
		'Request for Consent to Use Personal Information for Research',
		'Request for Consent to Use Personal Information for Service Improvement',
		'Request for Consent to Use Personal Information for Service Development',
	]);

	const deviceCode = faker.helpers.arrayElement(['PC', 'MO', 'TB']);
	const relayAgencyCode = faker.helpers.arrayElement([
		'ra20250001',
		'ra20250002',
		'ra20250003',
		'ra20250004',
		'ra20250005',
	]);

	const consentTitles = [
		'Consent Request for Transmission',
		'Consent to Collection and Use of Personal Information',
		'Consent to Provide Personal Information',
	];

	const consentValues = ['consent-001', 'consent-002', 'consent-003', 'consent-004', 'consent-005'];
	const numConsents = faker.number.int({ min: 1, max: 3 });

	const consent_list = Array.from({ length: numConsents }, (_, index) => {
		const consent = faker.helpers.arrayElement(consentValues);
		const shaConsent = Buffer.from(consent).toString('base64');
		const txId = `MD_${orgCode}_${otherOrgCode}_${relayAgencyCode}_${caCode}_${newTimestamp}_${'XXAB0049000' + index}`;

		return {
			tx_id: txId,
			consent_title: consentTitles[index],
			consent: shaConsent,
			consent_len: shaConsent.length,
		};
	});

	const return_app_scheme_url = `https://anya-bank.com/return`;

	const body: BodyIA102 = {
		sign_tx_id: signTxId,
		user_ci: b64UserCI,
		real_name: fullName,
		phone_num: phoneNum,
		request_title: requestTitle,
		device_code: deviceCode,
		device_browser: 'WB',
		return_app_scheme_url: return_app_scheme_url,
		consent_type: '1',
		consent_cnt: consent_list.length,
		consent_list: consent_list,
	};

	return body;
};

export const generateBodyIA002 = async (certTxId: string, consent_list: any, signed_consent_list: any) => {
	const txId = signed_consent_list[0]?.tx_id;

	const orgCode = txId.split('_')[0];
	const ipCode = txId.split('_')[1];
	const raCode = txId.split('_')[2];
	const caCode = txId.split('_')[3];

	const organization = await prisma.organization.findFirst({
		where: {
			orgCode: ipCode,
		},
	});

	if (!organization) {
		throw new Error('Organization not found');
	}

	const oAuthClient = await prisma.oAuthClient.findFirst({
		where: {
			organizationId: organization?.id,
		},
	});

	if (!oAuthClient) {
		throw new Error('OAuth Client not found');
	}

	const certificate = await prisma.certificate.findFirst({
		where: {
			certTxId: certTxId,
		},
	});

	if (!certificate) {
		throw new Error('Certificate not found');
	}

	const account = await prisma.account.findFirst({
		where: {
			phoneNumber: certificate.phoneNumber,
		},
	});

	if (!account) {
		throw new Error('Account not found');
	}
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

	const bodyIA002: BodyIA002 = {
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

	return bodyIA002;
};

const generateBodyIA104 = async (certTxId: string, consent_list: any, signed_consent_list: any) => {
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

	return bodyIA104;
};

const getAccountsBasic = async (
	orgCode: string,
	accountNum: string,
	accessToken: string,
	otherOrgCode: string,
	otherBankAPI: string,
	isAttack: boolean = false
) => {
	const headers: any = {
		'Content-Type': 'application/json;charset=UTF-8',
		'x-api-tran-id': generateTIN('S', orgCode),
		'x-api-type': faker.helpers.arrayElement(['regular', 'irregular']),
		Authorization: `Bearer ${accessToken}`,
	};

	if (isAttack) {
		headers['attack-type'] = 'invalid-business-flow';
	}

	const options = {
		method: 'POST',
		headers,
		body: JSON.stringify({
			org_code: otherOrgCode,
			account_num: accountNum,
			next: '0',
			search_timestamp: timestamp(new Date()),
		}),
	};

	let apiUrl = otherBankAPI;
	if (otherBankAPI.includes('4000')) {
		apiUrl = IP_API_URL;
	} else if (otherBankAPI.includes('4200')) {
		apiUrl = MO_API_URL;
	}

	console.log(`Requesting account basic from ${apiUrl}/api/v2/bank/accounts/deposit/basic`);
	const response = await fetch(`${apiUrl}/api/v2/bank/accounts/deposit/basic`, options);
	if (!response.ok) {
		throw new Error(`HTTP error! Status: ${response.status}`);
	}
	const data = await response.json();
	return data;
};

const getAccountsDetail = async (
	orgCode: string,
	accountNum: string,
	accessToken: string,
	otherOrgCode: string,
	otherBankAPI: string,
	isAttack: boolean = false
) => {
	const headers: any = {
		'Content-Type': 'application/json;charset=UTF-8',
		'x-api-tran-id': generateTIN('S', orgCode),
		'x-api-type': faker.helpers.arrayElement(['regular', 'irregular']),
		Authorization: `Bearer ${accessToken}`,
	};

	if (isAttack) {
		headers['attack-type'] = 'invalid-business-flow';
	}

	const options = {
		method: 'POST',
		headers,
		body: JSON.stringify({
			org_code: otherOrgCode,
			account_num: accountNum,
			next: '0',
			search_timestamp: timestamp(new Date()),
		}),
	};

	let apiUrl = otherBankAPI;
	if (otherBankAPI.includes('4000')) {
		apiUrl = IP_API_URL;
	} else if (otherBankAPI.includes('4200')) {
		apiUrl = MO_API_URL;
	}

	console.log(`Requesting account detail from ${apiUrl}/api/v2/bank/accounts/deposit/detail`);
	const response = await fetch(`${apiUrl}/api/v2/bank/accounts/deposit/detail`, options);
	if (!response.ok) {
		throw new Error(`HTTP error! Status: ${response.status}`);
	}
	const data = await response.json();
	return data;
};

// Attack Scenario 1: Skip certification and directly access bank data
async function attackSkipCertification(
	orgCode: string,
	clientId: string,
	clientSecret: string,
	otherOrgCode: string,
	otherBankAPI: string
) {
	console.log('ATTACK: Attempting to skip certification process');

	try {
		// Get accounts without proper flow
		const accounts = await prisma.account.findMany({
			where: {
				orgCode: orgCode,
			},
		});

		const account = faker.helpers.arrayElement(accounts);

		// Create fake access token
		const fakeAccessToken = faker.string.alphanumeric(50);

		// Try to access accounts directly
		await getAccountsBasic(orgCode, account.accountNum, fakeAccessToken, otherOrgCode, otherBankAPI, true);
	} catch (error) {
		console.error('Attack failed:', error);
	}
}

// Attack Scenario 2: Use expired/old certification data
async function attackReplayOldCertification(
	orgCode: string,
	clientId: string,
	clientSecret: string,
	otherOrgCode: string,
	otherBankAPI: string
) {
	console.log('ATTACK: Attempting to replay old certification');

	try {
		// Generate fake old certification data
		const oldCertTxId = faker.string.alphanumeric(30);
		const fakeSignedConsent = [
			{
				tx_id: `MD_${orgCode}_${otherOrgCode}_ra20250001_certauth00_20240101000000_XXAB00490001`,
				signed_consent: Buffer.from('old-consent').toString('base64'),
				signed_consent_len: 11,
			},
		];
		const fakeConsent = [
			{
				tx_id: `MD_${orgCode}_${otherOrgCode}_ra20250001_certauth00_20240101000000_XXAB00490001`,
				consent_title: 'Old Consent',
				consent: Buffer.from('old-consent').toString('base64'),
				consent_len: 11,
			},
		];

		// Try to use old data for new request
		const bodyIA002 = await generateBodyIA002(oldCertTxId, fakeConsent, fakeSignedConsent);
		await getIA002(bodyIA002, otherBankAPI, orgCode, true);
	} catch (error) {
		console.error('Attack failed:', error);
	}
}

// Attack Scenario 3: Skip sign verification
async function attackSkipVerification(
	orgCode: string,
	clientId: string,
	clientSecret: string,
	otherOrgCode: string,
	otherBankAPI: string
) {
	console.log('ATTACK: Attempting to skip sign verification');

	try {
		// Get legitimate CA token
		const IA101Response = await getIA101(orgCode, clientId, clientSecret, true);
		const { access_token } = IA101Response?.body;

		// Get accounts
		const accounts = await prisma.account.findMany({
			where: {
				orgCode: orgCode,
			},
		});

		const account = faker.helpers.arrayElement(accounts);
		const bodyIA102 = await generateBodyIA102(account, orgCode, otherOrgCode);

		// Request signing
		const responseIA102 = await getIA102(access_token, bodyIA102, orgCode, true);

		// Skip IA103 and IA104, go directly to IA002
		const fakeSignedConsent = [
			{
				tx_id: bodyIA102.consent_list[0].tx_id,
				signed_consent: Buffer.from('fake-signed').toString('base64'),
				signed_consent_len: 11,
			},
		];

		const bodyIA002 = await generateBodyIA002(
			responseIA102?.body?.cert_tx_id,
			bodyIA102.consent_list,
			fakeSignedConsent
		);
		const responseIA002 = await getIA002(bodyIA002, otherBankAPI, orgCode, true);

		// Try to access data without verification
		await getAccountsBasic(
			orgCode,
			account.accountNum,
			responseIA002.body.access_token,
			otherOrgCode,
			otherBankAPI,
			true
		);
	} catch (error) {
		console.error('Attack failed:', error);
	}
}

// Attack Scenario 4: Out of order API calls
async function attackOutOfOrder(
	orgCode: string,
	clientId: string,
	clientSecret: string,
	otherOrgCode: string,
	otherBankAPI: string
) {
	console.log('ATTACK: Attempting out of order API calls');

	try {
		// Try IA103 before IA102
		const fakeBody103: BodyIA103 = {
			sign_tx_id: faker.string.alphanumeric(30),
			cert_tx_id: faker.string.alphanumeric(30),
		};

		const IA101Response = await getIA101(orgCode, clientId, clientSecret, true);
		await getIA103(IA101Response?.body?.access_token, fakeBody103, orgCode, true);

		// Try IA104 without proper flow
		const accounts = await prisma.account.findMany({
			where: {
				orgCode: orgCode,
			},
		});

		const account = faker.helpers.arrayElement(accounts);
		const bodyIA102 = await generateBodyIA102(account, orgCode, otherOrgCode);

		const fakeBody104 = {
			tx_id: bodyIA102.consent_list[0].tx_id,
			cert_tx_id: faker.string.alphanumeric(30),
			signed_consent_len: 10,
			signed_consent: Buffer.from('fake').toString('base64'),
			consent_type: '1',
			consent_len: 10,
			consent: Buffer.from('fake').toString('base64'),
		};

		await getIA104(IA101Response?.body?.access_token, fakeBody104, orgCode, true);
	} catch (error) {
		console.error('Attack failed:', error);
	}
}

// Attack Scenario 5: Skip Support APIs
async function attackSkipSupportAPIs(
	orgCode: string,
	clientId: string,
	clientSecret: string,
	otherOrgCode: string,
	otherBankAPI: string
) {
	console.log('ATTACK: Attempting to skip mandatory Support APIs');

	try {
		// Skip Support001 and Support002, go directly to IA101
		const IA101Response = await getIA101(orgCode, clientId, clientSecret, true);
		const { access_token } = IA101Response?.body;

		const accounts = await prisma.account.findMany({
			where: { orgCode: orgCode },
		});

		const account = faker.helpers.arrayElement(accounts);
		const bodyIA102 = await generateBodyIA102(account, orgCode, otherOrgCode);

		await getIA102(access_token, bodyIA102, orgCode, true);
	} catch (error) {
		console.error('Attack failed:', error);
	}
}

// Attack Scenario 6: Skip only Support002
async function attackSkipSupport002(
	orgCode: string,
	clientId: string,
	clientSecret: string,
	otherOrgCode: string,
	otherBankAPI: string
) {
	console.log('ATTACK: Attempting to skip Support002');

	try {
		// Call Support001 but skip Support002
		await getSupport001(orgCode, clientId, clientSecret, true);

		// Go directly to IA101 without Support002
		const IA101Response = await getIA101(orgCode, clientId, clientSecret, true);
		const { access_token } = IA101Response?.body;

		const accounts = await prisma.account.findMany({
			where: { orgCode: orgCode },
		});

		const account = faker.helpers.arrayElement(accounts);
		const bodyIA102 = await generateBodyIA102(account, orgCode, otherOrgCode);

		await getIA102(access_token, bodyIA102, orgCode, true);
	} catch (error) {
		console.error('Attack failed:', error);
	}
}

// Attack Scenario 7: Double Token Request (Resource exhaustion)
async function attackDoubleTokenRequest(
	orgCode: string,
	clientId: string,
	clientSecret: string,
	otherOrgCode: string,
	otherBankAPI: string
) {
	console.log('ATTACK: Attempting double token requests');

	try {
		// Skip Support APIs and request CA token multiple times
		await getIA101(orgCode, clientId, clientSecret, true);
		await getIA101(orgCode, clientId, clientSecret, true);
		const IA101Response = await getIA101(orgCode, clientId, clientSecret, true);

		const accounts = await prisma.account.findMany({
			where: { orgCode: orgCode },
		});

		const account = faker.helpers.arrayElement(accounts);
		const bodyIA102 = await generateBodyIA102(account, orgCode, otherOrgCode);

		await getIA102(IA101Response?.body?.access_token, bodyIA102, orgCode, true);

		const fakeSignedConsent = [
			{
				tx_id: bodyIA102.consent_list[0].tx_id,
				signed_consent: Buffer.from('fake-consent').toString('base64'),
				signed_consent_len: 12,
			},
		];

		const bodyIA002 = await generateBodyIA002('fake-cert-id', bodyIA102.consent_list, fakeSignedConsent);

		// Multiple bank token requests
		await getIA002(bodyIA002, otherBankAPI, orgCode, true);
		await getIA002(bodyIA002, otherBankAPI, orgCode, true);
		await getIA002(bodyIA002, otherBankAPI, orgCode, true);
	} catch (error) {
		console.error('Attack failed:', error);
	}
}

// Attack Scenario 8: Cross-Organization Mismatch
async function attackCrossOrgMismatch(
	orgCode: string,
	clientId: string,
	clientSecret: string,
	otherOrgCode: string,
	otherBankAPI: string
) {
	console.log('ATTACK: Attempting cross-organization data access');

	try {
		// Skip Support APIs
		const IA101Response = await getIA101(orgCode, clientId, clientSecret, true);
		const { access_token } = IA101Response?.body;

		const accounts = await prisma.account.findMany({
			where: { orgCode: orgCode },
		});

		const account = faker.helpers.arrayElement(accounts);
		const bodyIA102 = await generateBodyIA102(account, orgCode, otherOrgCode);

		// Modify consent list to use wrong org codes
		bodyIA102.consent_list[0].tx_id = bodyIA102.consent_list[0].tx_id.replace(orgCode, otherOrgCode);

		await getIA102(access_token, bodyIA102, orgCode, true);

		const fakeAccessToken = faker.string.alphanumeric(50);
		await getAccountsBasic(otherOrgCode, account.accountNum, fakeAccessToken, orgCode, otherBankAPI, true);
	} catch (error) {
		console.error('Attack failed:', error);
	}
}

// Attack Scenario 9: Incomplete Consent Flow
async function attackIncompleteConsent(
	orgCode: string,
	clientId: string,
	clientSecret: string,
	otherOrgCode: string,
	otherBankAPI: string
) {
	console.log('ATTACK: Attempting incomplete consent flow');

	try {
		// Skip Support APIs
		const IA101Response = await getIA101(orgCode, clientId, clientSecret, true);
		const { access_token } = IA101Response?.body;

		const accounts = await prisma.account.findMany({
			where: { orgCode: orgCode },
		});

		const account = faker.helpers.arrayElement(accounts);
		const bodyIA102 = await generateBodyIA102(account, orgCode, otherOrgCode);

		const responseIA102 = await getIA102(access_token, bodyIA102, orgCode, true);

		// Skip IA103 - don't get signed consent
		const bodyIA002 = await generateBodyIA002(
			responseIA102?.body?.cert_tx_id,
			bodyIA102.consent_list,
			bodyIA102.consent_list // Use unsigned consent instead of signed
		);

		const responseIA002 = await getIA002(bodyIA002, otherBankAPI, orgCode, true);

		await getAccountsBasic(
			orgCode,
			account.accountNum,
			responseIA002?.body?.access_token || 'fake-token',
			otherOrgCode,
			otherBankAPI,
			true
		);
	} catch (error) {
		console.error('Attack failed:', error);
	}
}

// Attack Scenario 10: Support API with Wrong Scope
async function attackWrongSupportScope(
	orgCode: string,
	clientId: string,
	clientSecret: string,
	otherOrgCode: string,
	otherBankAPI: string
) {
	console.log('ATTACK: Attempting Support API with wrong scope');

	try {
		// Try to use Support001 with CA scope instead of manage scope
		const headers: any = {
			'Content-Type': 'application/x-www-form-urlencoded',
			'x-api-tran-id': generateTIN('S', orgCode),
			'attack-type': 'invalid-business-flow',
			Authorization: '',
		};

		const options = {
			method: 'POST',
			headers,
			body: new URLSearchParams({
				grant_type: 'client_credentials',
				client_id: clientId,
				client_secret: clientSecret,
				scope: 'ca', // Wrong scope - should be 'manage'
			}),
		};

		const response = await fetch(`${CA_API_URL}/api/v2/mgmts/oauth/2.0/token`, options);

		if (response.ok) {
			const data = await response.json();
			// Try to use this token for Support002
			const support002Headers: any = {
				'Access-Control-Allow-Origin': '*',
				'Content-Type': 'application/json;charset=UTF-8',
				'x-api-tran-id': generateTIN('S', orgCode),
				'attack-type': 'invalid-business-flow',
				Authorization: `Bearer ${data?.body?.access_token}`,
			};

			await fetch(`${CA_API_URL}/api/v2/mgmts/orgs?search_timestamp=`, {
				method: 'GET',
				headers: support002Headers,
			});
		}
	} catch (error) {
		console.error('Attack failed:', error);
	}
}

// Normal flow function with mandatory Support APIs
async function main(
	orgCode: string,
	clientId: string,
	clientSecret: string,
	otherOrgCode: string,
	otherBankAPI: string
) {
	try {
		// MANDATORY: Support001 and Support002 must be called first
		console.log('Starting normal flow with Support APIs');

		// Step 1: Get management token via Support001
		const support001Response = await getSupport001(orgCode, clientId, clientSecret);
		if (!support001Response || !support001Response.body?.access_token) {
			throw new Error('Error fetching management token in Support001');
		}

		await new Promise((resolve) => setTimeout(resolve, 1000));

		// Step 2: Get organization list via Support002 (uses Support001 token internally)
		const support002Response = await getSupport002(orgCode, clientId, clientSecret);
		if (!support002Response) {
			throw new Error('Error fetching organization list in Support002');
		}

		await new Promise((resolve) => setTimeout(resolve, 1000));

		// Step 3: Continue with IA101
		const IA101Response = await getIA101(orgCode, clientId, clientSecret);

		const { access_token } = IA101Response?.body;

		if (!access_token) {
			throw new Error('Error fetching access token in IA101');
		}

		await new Promise((resolve) => setTimeout(resolve, 2000));

		const accounts = await prisma.account.findMany({
			where: {
				orgCode: orgCode,
			},
		});

		if (!accounts) {
			throw new Error('Error fetching accounts');
		}

		const account = faker.helpers.arrayElement(accounts);
		const accountNum = account.accountNum;

		const bodyIA102 = await generateBodyIA102(account, orgCode, otherOrgCode);

		const responseIA102 = await getIA102(access_token, bodyIA102, orgCode);
		if (!responseIA102) {
			throw new Error('Error sign request in IA102');
		}

		await new Promise((resolve) => setTimeout(resolve, 4000));

		const bodyIA103: BodyIA103 = {
			sign_tx_id: bodyIA102.sign_tx_id,
			cert_tx_id: responseIA102?.body?.cert_tx_id,
		};

		const responseIA103 = await getIA103(access_token, bodyIA103, orgCode);
		if (!responseIA103) {
			throw new Error('Error sign result in IA103');
		}

		await new Promise((resolve) => setTimeout(resolve, 4000));

		const certTxId = responseIA102?.body?.cert_tx_id;
		const signedConsentList = responseIA103?.body?.signed_consent_list;
		const consentList = bodyIA102?.consent_list;

		const bodyIA002 = await generateBodyIA002(certTxId, consentList, signedConsentList);
		const responseIA002 = await getIA002(bodyIA002, otherBankAPI, orgCode);

		if (!responseIA002) {
			throw new Error('Error request for access token in IA002');
		}

		await new Promise((resolve) => setTimeout(resolve, 2000));

		const bodyIA104 = await generateBodyIA104(certTxId, consentList, signedConsentList);
		const responseIA104 = await getIA104(responseIA002?.body?.access_token, bodyIA104, orgCode);

		if (!responseIA104) {
			throw new Error('Error sign verification in IA104');
		}

		const { result, user_ci } = responseIA104?.body;

		if (!result) {
			throw new Error('Sign verification result denied in IA104');
		} else if (result) {
			const isGetBasic = faker.helpers.arrayElement([true, false]);
			const isGetDetail = faker.helpers.arrayElement([true, false]);

			console.log('responseIA104', result, user_ci);

			if (isGetBasic) {
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

				await new Promise((resolve) => setTimeout(resolve, 2000));
			}

			if (isGetDetail) {
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

				await new Promise((resolve) => setTimeout(resolve, 2000));
			}
		}
	} catch (error) {
		console.error('Error within interaction', error);
		throw error;
	}
}

// Run iterations with 60% normal, 40% attack
export async function runIterations(
	iterations: number = 100,
	orgCode: string,
	clientId: string,
	clientSecret: string,
	otherOrgCode: string,
	otherBankAPI: string
) {
	const delayBetweenIterations = 1000;
	const attackScenarios = [
		attackSkipCertification,
		attackReplayOldCertification,
		attackSkipVerification,
		attackOutOfOrder,
		attackSkipSupportAPIs,
		attackSkipSupport002,
		// attackDoubleTokenRequest,
		// attackCrossOrgMismatch,
		// attackIncompleteConsent,
		// attackWrongSupportScope,
	];

	for (let i = 0; i < iterations; i++) {
		try {
			// 60% normal, 40% attack
			const isAttack = Math.random() < 0.4;

			if (isAttack) {
				const attackFn = faker.helpers.arrayElement(attackScenarios);
				await attackFn(orgCode, clientId, clientSecret, otherOrgCode, otherBankAPI);
				console.log(`Iteration ${i + 1} completed (ATTACK).`);
			} else {
				await main(orgCode, clientId, clientSecret, otherOrgCode, otherBankAPI);
				console.log(`Iteration ${i + 1} completed (NORMAL).`);
			}
		} catch (error) {
			console.error(`Error in iteration ${i + 1}:`, error);
		}

		await new Promise((resolve) => setTimeout(resolve, delayBetweenIterations));
	}

	console.log('All iterations completed.');
}

// If this script is run directly, execute with the following parameters
if (require.main === module) {
	const iterations = 1;
	const orgCode = process.env.BOND_ORG_CODE || 'bond123456';
	const clientId = process.env.BOND_CLIENT_ID || 'xv9gqz7mb4t2o5wcf8rjy6kphudsnea0l3ytkpdhqrvcxz1578';
	const clientSecret = process.env.BOND_CLIENT_SECRET || 'm4q7xv9zb2tgc8rjy6kphudsnea0l3ow5ytkpdhqrvcfz926bt';
	const otherOrgCode = process.env.ANYA_ORG_CODE || 'anya123456';
	const otherBankAPI = process.env.ANYA_BANK_API || 'http://information-provider:4000';

	console.log('Starting simulation with parameters:');
	console.log(`Iterations: ${iterations}`);
	console.log(`Org Code: ${orgCode}`);
	console.log(`Other Org Code: ${otherOrgCode}`);
	console.log(`Other Bank API: ${otherBankAPI}`);

	runIterations(iterations, orgCode, clientId, clientSecret, otherOrgCode, otherBankAPI)
		.then(() => console.log('Simulation complete.'))
		.catch((error) => console.error('Error running simulation:', error));
}
