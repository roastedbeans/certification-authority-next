import { PrismaClient } from '@prisma/client';
import { faker } from '@faker-js/faker';
import dayjs from 'dayjs';

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
	service_id: string; //institution code (10 digits) + registration date (8 digits) + serial number (4 digits)
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

// Initialize Prisma and constants
const prisma = new PrismaClient();
const otherBankAPI = process.env.BOND_BANK_API || '';
const otherOrgCode = process.env.BOND_ORG_CODE || '';
const orgCode = process.env.ANYA_ORG_CODE || '';
const caCode = process.env.CA_CODE || '';
const orgSerialCode = process.env.ANYA_ORG_SERIAL_CODE || '';
const clientId = process.env.ANYA_CLIENT_ID || '';
const clientSecret = process.env.ANYA_CLIENT_SECRET || '';

export const generateTIN = (subject: string): string => {
	//subject classification code
	try {
		const date = new Date();
		// grant code 10 uppercase letters + numbers
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
		.slice(0, 14); // YYYYMMDDHHMMSS

	return timestamp;
}

export const getIA101 = async () => {
	try {
		const options = {
			method: 'POST',
			headers: {
				'Content-Type': 'application/x-www-form-urlencoded',
				'x-api-tran-id': generateTIN('S'),
			},
			body: new URLSearchParams({
				grant_type: 'client_credentials',
				client_id: clientId,
				client_secret: clientSecret,
				scope: 'ca',
			}),
		};
		console.log('requesting token from certification authority');
		const response = await fetch('http://localhost:3000/api/oauth/2.0/token', options);

		if (!response.ok) {
			// Handle HTTP errors
			throw new Error(`HTTP error! Status: ${response.status}`);
		}

		const res = await response.json();
		return res;
	} catch (error) {
		console.error('Error:', error);
		throw error;
	}
};

// Normal simulation for IA102
export const getIA102 = async (accessToken: string, body: BodyIA102) => {
	const options = {
		method: 'POST',
		headers: {
			'Access-Control-Allow-Origin': '*',
			'Content-Type': 'application/json;charset=UTF-8',
			'x-api-tran-id': generateTIN('S'),
			Authorization: `Bearer ${accessToken}`,
		},
		body: JSON.stringify(body),
	};

	console.log('requesting sign request from certification authority');
	const response = await fetch(`http://localhost:3000/api/ca/sign_request`, options);

	if (!response.ok) {
		// Handle HTTP errors
		throw new Error(`HTTP error on IA102! Status: ${response.status}`);
	}

	const res = await response.json();

	return res;
};

export const getIA103 = async (accessToken: string, body: BodyIA103) => {
	const options = {
		method: 'POST',
		headers: {
			'Access-Control-Allow-Origin': '*',
			'Content-Type': 'application/json;charset=UTF-8',
			'x-api-tran-id': generateTIN('S'),
			Authorization: `Bearer ${accessToken}`,
		},
		body: JSON.stringify(body),
	};
	console.log('requesting sign result from certification authority');
	const response = await fetch(`http://localhost:3000/api/ca/sign_result`, options);

	if (!response.ok) {
		// Handle HTTP errors
		throw new Error(`HTTP error on IA103! Status: ${response.status}`);
	}
	const res = await response.json();
	return res;
};

export const getIA002 = async (body: BodyIA002) => {
	const options = {
		method: 'POST',
		headers: {
			'Content-Type': 'application/x-www-form-urlencoded',
			'x-api-tran-id': generateTIN('S'),
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
};

export const getIA104 = async (accessToken: string, body: BodyIA104) => {
	const options = {
		method: 'POST',
		headers: {
			'Access-Control-Allow-Origin': '*',
			'Content-Type': 'application/json;charset=UTF-8',
			'x-api-tran-id': generateTIN('S'),
			Authorization: `Bearer ${accessToken}`,
		},
		body: JSON.stringify(body),
	};

	const response = await fetch(`http://localhost:3000/api/ca/sign_verification`, options);
	const res = await response.json();
	return res;
};

export async function getSupport001() {
	try {
		const options = {
			method: 'POST',
			headers: {
				'Content-Type': 'application/x-www-form-urlencoded',
				'x-api-tran-id': generateTIN('S'),
				Authorization: '',
			},
			body: new URLSearchParams({
				grant_type: 'client_credentials',
				client_id: clientId,
				client_secret: clientSecret,
				scope: 'manage',
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
		console.error('Error:', error);
		throw error;
	}
}

export async function getSupport002() {
	const support001Response = await getSupport001();

	const { access_token } = support001Response?.body;

	const options = {
		method: 'GET',
		headers: {
			'Access-Control-Allow-Origin': '*',
			'Content-Type': 'application/json;charset=UTF-8',
			'x-api-tran-id': generateTIN('S'),
			Authorization: `Bearer ${access_token}`,
		},
	};

	const response = await fetch(`http://localhost:3000/api/v2/mgmts/orgs?search_timestamp=`, options);

	if (!response.ok) {
		// Handle HTTP errors
		throw new Error(`HTTP error! Status: ${response.status}`);
	}

	const res = await response.json();

	return res;
}

export const generateBodyIA102 = async (account: any) => {
	// Fetch accounts that belong to the organization

	const caCode = faker.helpers.arrayElement(['certauth00']);
	const newTimestamp = timestamp(new Date());
	const serialNum = faker.helpers.arrayElement(['anyaserial00', 'bondserial00']);

	const signTxId = `${orgCode}_${caCode}_${newTimestamp}_${serialNum}`;

	const firstName = account.firstName;
	const lastName = account.lastName;
	const b64UserCI = Buffer.from(account.pinCode).toString('base64');

	const fullName = `${firstName} ${lastName}`;
	const phoneNum = account.phoneNumber;

	// Generate request title based on bank request for consent
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
	// Randomly determine how many consents to generate (1 to 3)
	const numConsents = faker.number.int({ min: 1, max: 3 });

	// Generate consent_list dynamically
	const consent_list = Array.from({ length: numConsents }, (_, index) => {
		const consent = faker.helpers.arrayElement(consentValues);
		const shaConsent = Buffer.from(consent).toString('base64');
		const txId = `MD_${orgCode}_${otherOrgCode}_${relayAgencyCode}_${caCode}_${newTimestamp}_${'XXAB0049000' + index}`;

		return {
			tx_id: txId,
			consent_title: consentTitles[index], // Ensure unique title for each
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
	// Assumed that signed_consent is already decoded from base64

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
		const letter = faker.string.alpha({ casing: 'upper', length: 1 }); // Random uppercase letter (A-Z)
		const year = dayjs().format('YYYY'); // Current year (e.g., 2025)
		const randomNumber = faker.number.int({ min: 100000000000000, max: 999999999999999 }); // 15-digit number

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
		service_id: `${ipCode}${registrationDate}${serialNum}`, //institution code (10 digits) + registration date (8 digits) + serial number (4 digits)
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

const getAccountsBasic = async (orgCode: string, accountNum: string, accessToken: string) => {
	// Assumption: Mydata app is looking for api of the bank with orgCode to get the access token
	const options = {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json;charset=UTF-8',
			'x-api-tran-id': generateTIN('S'),
			'x-api-type': faker.helpers.arrayElement(['regular', 'irregular']),
			Authorization: `Bearer ${accessToken}`,
		},
		body: JSON.stringify({
			org_code: otherOrgCode,
			account_num: accountNum,
			next: '0',
			search_timestamp: timestamp(new Date()),
		}),
	};

	const response = await fetch(`${otherBankAPI}/api/v2/bank/accounts/deposit/basic`, options);
	if (!response.ok) {
		// Handle HTTP errors
		throw new Error(`HTTP error! Status: ${response.status}`);
	}
	const data = await response.json();
	return data;
};

const getAccountsDetail = async (orgCode: string, accountNum: string, accessToken: string) => {
	// Assumption: Mydata app is looking for api of the bank with orgCode to get the access token
	const options = {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json;charset=UTF-8',
			'x-api-tran-id': generateTIN('S'),
			'x-api-type': faker.helpers.arrayElement(['regular', 'irregular']),
			Authorization: `Bearer ${accessToken}`,
		},
		body: JSON.stringify({
			org_code: otherOrgCode,
			account_num: accountNum,
			next: '0',
			search_timestamp: timestamp(new Date()),
		}),
	};

	const response = await fetch(`${otherBankAPI}/api/v2/bank/accounts/deposit/detail`, options);
	if (!response.ok) {
		// Handle HTTP errors
		throw new Error(`HTTP error! Status: ${response.status}`);
	}
	const data = await response.json();
	return data;
};

async function main() {
	// Generate a simulation of a normal user flow and interactions between bank app and Mydata app
	// Interaction 1: User wants to to sign up
	// Assumptions:
	// Accounts in the Anya Bank and Bond Bank have been created
	// The user has already logged in to the bank app and is trying to connect their accounts through the Mydata app
	// User has to sign up to the Mydata Service and accept the terms and conditions
	//
	// Call for a token to access the Mydata API, /api/v2/mgmts/oauth/2.0/token
	// Call for a list of organizations, /api/v2/mgmts/orgs?search_timestamp=

	try {
		const response = await getSupport002();

		if (!response) {
			throw new Error('Error fetching organization list');
		}
	} catch (error) {
		console.error('Error on support002:', error);
		throw error;
	}

	// Interaction 2: User wants to connect their accounts to the selected banks
	// Assumptions: User has selected the bank except the one they are currently logged in to

	// Consent will be required from the user to connect their accounts
	// Consent List: "Consent Request for Transmission", "Consent to Collection and Use of Personal Information", "Consent to Provide Personal Information"

	try {
		const IA101Response = await getIA101();

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

		if (!accounts) {
			throw new Error('Error fetching accounts');
		}

		const account = faker.helpers.arrayElement(accounts);
		const accountNum = account.accountNum;

		const bodyIA102 = await generateBodyIA102(account);

		const responseIA102 = await getIA102(access_token, bodyIA102);
		if (!responseIA102) {
			throw new Error('Error sign request in IA102');
		}

		// add delay to simulate user interaction
		await new Promise((resolve) => setTimeout(resolve, 4000));

		const bodyIA103: BodyIA103 = {
			sign_tx_id: bodyIA102.sign_tx_id,
			cert_tx_id: responseIA102?.body?.cert_tx_id,
		};

		const responseIA103 = await getIA103(access_token, bodyIA103);
		if (!responseIA103) {
			throw new Error('Error sign result in IA103');
		}

		// add delay to simulate user interaction
		await new Promise((resolve) => setTimeout(resolve, 4000));

		// After the integrated certification has been completed from Certification Authority, the response will
		// be sent to the bank app (Information Provider) to complete the process
		// this will provide access_token to allow access to the user's data
		// Interaction 3: User wants to access their data from other banks

		const certTxId = responseIA102?.body?.cert_tx_id;
		const signedConsentList = responseIA103?.body?.signed_consent_list;
		const consentList = bodyIA102?.consent_list;

		const bodyIA002 = await generateBodyIA002(certTxId, consentList, signedConsentList);
		const responseIA002 = await getIA002(bodyIA002);

		if (!responseIA002) {
			throw new Error('Error request for access token in IA002');
		}
		// add delay to simulate user interaction
		await new Promise((resolve) => setTimeout(resolve, 2000));
		// Interaction 4: Certification authority will provide a sign verification to the bank, this will include boolean result in the response
		const bodyIA104 = await generateBodyIA104(certTxId, consentList, signedConsentList);
		const responseIA104 = await getIA104(responseIA002?.body?.access_token, bodyIA104);

		if (!responseIA104) {
			throw new Error('Error sign verification in IA104');
		}

		const { result, user_ci } = responseIA104?.body;

		if (!result) {
			throw new Error('Sign verification result denied in IA104');
		}

		// Interaction 5: User wants to view their accounts from other banks
		// Assumptions: User has already connected their accounts to the Mydata app
		// User can either view basic account information or detailed account information or both
		else if (result) {
			const isGetBasic = faker.helpers.arrayElement([true, false]);
			const isGetDetail = faker.helpers.arrayElement([true, false]);

			console.log('responseIA104', result, user_ci);

			if (isGetBasic) {
				// Call for basic account information
				console.log('Getting basic account information');
				const accountsBasic = await getAccountsBasic(orgCode, accountNum, responseIA002.body.access_token);
				if (!accountsBasic) {
					throw new Error('Error fetching basic account information');
				}

				// add delay to simulate user interaction
				await new Promise((resolve) => setTimeout(resolve, 2000));
			}

			if (isGetDetail) {
				// Call for detailed account information
				console.log('Getting detailed account information');
				const accountsDetail = await getAccountsDetail(orgCode, accountNum, responseIA002.body.access_token);
				if (!accountsDetail) {
					throw new Error('Error fetching detailed account information');
				}

				// add delay to simulate user interaction
				await new Promise((resolve) => setTimeout(resolve, 2000));
			}
		}
	} catch (error) {
		console.error('Error within interaction', error);
		throw error;
	}
}

async function runIterations() {
	const iterations = 100; // Number of iterations
	const delayBetweenIterations = 1000; // Delay between iterations in milliseconds (e.g., 1 second)

	for (let i = 0; i < iterations; i++) {
		try {
			await main(); // Run the main function
			console.log(`Iteration ${i + 1} completed.`);
		} catch (error) {
			console.error(`Error in iteration ${i + 1}:`, error);
		}

		// Add a delay between iterations to avoid overwhelming the system
		await new Promise((resolve) => setTimeout(resolve, delayBetweenIterations));
	}

	console.log('All iterations completed.');
}

// Run the iterations
runIterations()
	.catch((e) => {
		console.error('Error during iterations:', e);
		process.exit(1);
	})
	.finally(async () => {
		await prisma.$disconnect();
	});
