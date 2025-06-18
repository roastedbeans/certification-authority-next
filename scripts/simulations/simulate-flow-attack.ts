import { faker } from '@faker-js/faker';
import {
	generateTIN,
	timestamp,
	getIA101,
	getIA102,
	getIA103,
	getIA002,
	getIA104,
	generateBodyIA102,
	generateBodyIA002,
	getSupport002,
	CA_API_URL,
	IP_API_URL,
	MO_API_URL,
	prisma,
} from './simulate'; // Changed from './normalSimulation' to match your import

// Helper to ensure all requests include attack-type header
function createAttackOptions(method: string, headers: any, body: any, attackType: string) {
	return {
		method,
		headers: {
			...headers,
			'attack-type': attackType,
		},
		body,
	};
}

// Normal flow execution (no attack-type header)
async function executeNormalFlow(
	orgCode: string,
	clientId: string,
	clientSecret: string,
	otherOrgCode: string,
	otherBankAPI: string
) {
	console.log('Executing NORMAL flow...');

	try {
		// Optional: Support APIs
		if (faker.datatype.boolean({ probability: 0.3 })) {
			await getSupport002(orgCode, clientId, clientSecret);
		}

		// Step 1: Get CA token (IA101)
		const IA101Response = await getIA101(orgCode, clientId, clientSecret);
		const { access_token } = IA101Response?.body;

		if (!access_token) throw new Error('No access token from IA101');

		await new Promise((resolve) => setTimeout(resolve, faker.number.int({ min: 1000, max: 3000 })));

		// Step 2: Get account and prepare consent (IA102)
		const accounts = await prisma.account.findMany({ where: { orgCode } });
		if (!accounts || accounts.length === 0) throw new Error('No accounts found');

		const account = faker.helpers.arrayElement(accounts);
		const bodyIA102 = await generateBodyIA102(account, orgCode, otherOrgCode);

		const responseIA102 = await getIA102(access_token, bodyIA102, orgCode);
		if (!responseIA102?.body?.cert_tx_id) throw new Error('No cert_tx_id from IA102');

		await new Promise((resolve) => setTimeout(resolve, faker.number.int({ min: 2000, max: 4000 })));

		// Step 3: Get signature result (IA103)
		const bodyIA103 = {
			sign_tx_id: bodyIA102.sign_tx_id,
			cert_tx_id: responseIA102.body.cert_tx_id,
		};

		const responseIA103 = await getIA103(access_token, bodyIA103, orgCode);
		if (!responseIA103?.body?.signed_consent_list) throw new Error('No signed consent from IA103');

		await new Promise((resolve) => setTimeout(resolve, faker.number.int({ min: 2000, max: 4000 })));

		// Step 4: Get bank token (IA002)
		const bodyIA002 = await generateBodyIA002(
			responseIA102.body.cert_tx_id,
			bodyIA102.consent_list,
			responseIA103.body.signed_consent_list
		);

		const responseIA002 = await getIA002(bodyIA002, otherBankAPI, orgCode);
		if (!responseIA002?.body?.access_token) throw new Error('No access token from IA002');

		await new Promise((resolve) => setTimeout(resolve, faker.number.int({ min: 1000, max: 2000 })));

		// Step 5: Verify consent (IA104)
		const bodyIA104 = {
			tx_id: responseIA103.body.signed_consent_list[0].tx_id,
			cert_tx_id: responseIA102.body.cert_tx_id,
			signed_consent_len: responseIA103.body.signed_consent_list[0].signed_consent_len,
			signed_consent: responseIA103.body.signed_consent_list[0].signed_consent,
			consent_type: '1',
			consent_len: bodyIA102.consent_list[0].consent_len,
			consent: bodyIA102.consent_list[0].consent,
		};

		const responseIA104 = await getIA104(responseIA002.body.access_token, bodyIA104, orgCode);
		if (!responseIA104?.body?.result) throw new Error('Verification failed in IA104');

		// Step 6: Access account data
		const accessChoice = faker.number.int({ min: 1, max: 3 });

		if (accessChoice === 1 || accessChoice === 3) {
			await getAccountsBasic(orgCode, account.accountNum, responseIA002.body.access_token, otherOrgCode, otherBankAPI);
		}

		if (accessChoice === 2 || accessChoice === 3) {
			await getAccountsDetail(orgCode, account.accountNum, responseIA002.body.access_token, otherOrgCode, otherBankAPI);
		}

		console.log('Normal flow completed successfully');
	} catch (error) {
		console.log('Normal flow error:', error);
	}
}

// Get account basic info
async function getAccountsBasic(
	orgCode: string,
	accountNum: string,
	accessToken: string,
	otherOrgCode: string,
	otherBankAPI: string
) {
	const options = {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json;charset=UTF-8',
			'x-api-tran-id': generateTIN('S', orgCode),
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

	let apiUrl = otherBankAPI;
	if (otherBankAPI.includes('4000')) apiUrl = IP_API_URL;
	else if (otherBankAPI.includes('4200')) apiUrl = MO_API_URL;

	const response = await fetch(`${apiUrl}/api/v2/bank/accounts/deposit/basic`, options);
	return response.json();
}

// Get account detail info
async function getAccountsDetail(
	orgCode: string,
	accountNum: string,
	accessToken: string,
	otherOrgCode: string,
	otherBankAPI: string
) {
	const options = {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json;charset=UTF-8',
			'x-api-tran-id': generateTIN('S', orgCode),
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

	let apiUrl = otherBankAPI;
	if (otherBankAPI.includes('4000')) apiUrl = IP_API_URL;
	else if (otherBankAPI.includes('4200')) apiUrl = MO_API_URL;

	const response = await fetch(`${apiUrl}/api/v2/bank/accounts/deposit/detail`, options);
	return response.json();
}

// SEQUENCE_BYPASS Attack - Skip authentication and directly access data
export async function sequenceBypassAttack(
	orgCode: string,
	clientId: string,
	clientSecret: string,
	otherOrgCode: string,
	otherBankAPI: string
) {
	console.log('Starting SEQUENCE_BYPASS attack...');
	const attackType = 'invalid-business-flow';

	try {
		// Get legitimate access token first for all attacks
		const IA101Response = await getIA101(orgCode, clientId, clientSecret);
		const { access_token } = IA101Response?.body;

		if (!access_token) {
			console.log('Failed to get legitimate access token, aborting sequence bypass attacks');
			return;
		}

		// Get realistic account data for testing
		const accounts = await prisma.account.findMany({ where: { orgCode } });
		if (!accounts || accounts.length === 0) {
			console.log('No accounts found for realistic testing');
			return;
		}
		const account = faker.helpers.arrayElement(accounts);

		// === CA API Sequence Bypass Attacks ===
		console.log('Attempting CA API sequence bypasses...');

		// Generate realistic values following simulate.ts patterns
		const caCode = 'certauth00';
		const newTimestamp = timestamp(new Date());
		const serialNum = faker.helpers.arrayElement(['anyaserial00', 'bondserial00']);
		const relayAgencyCode = faker.helpers.arrayElement(['ra20250001', 'ra20250002', 'ra20250003']);

		// Attack 1: Skip Support API, use valid token but skip to IA102 without proper sequence
		console.log('[Attack 1] Bypassing Support API + proper IA101 sequence → Direct IA102');
		const realisticSignTxId = `${orgCode}_${caCode}_${newTimestamp}_${serialNum}`;
		const realisticConsentTxId = `MD_${orgCode}_${otherOrgCode}_${relayAgencyCode}_${caCode}_${newTimestamp}_XXAB0049001`;

		const fakeIA102Body = {
			sign_tx_id: realisticSignTxId,
			user_ci: Buffer.from(account.pinCode).toString('base64'), // Realistic user CI
			real_name: `${account.firstName} ${account.lastName}`, // Realistic name
			phone_num: account.phoneNumber, // Realistic phone
			request_title: 'Request for Consent to Use Personal Information',
			device_code: faker.helpers.arrayElement(['PC', 'MO', 'TB']),
			device_browser: 'WB',
			return_app_scheme_url: 'https://anya-bank.com/return',
			consent_type: '1',
			consent_cnt: 1,
			consent_list: [
				{
					tx_id: realisticConsentTxId,
					consent_title: 'Consent Request for Transmission',
					consent: Buffer.from('consent-001').toString('base64'),
					consent_len: Buffer.from('consent-001').toString('base64').length,
				},
			],
		};

		const ia102BypassOptions = createAttackOptions(
			'POST',
			{
				'Content-Type': 'application/json;charset=UTF-8',
				'x-api-tran-id': generateTIN('S', orgCode),
				Authorization: `Bearer ${access_token}`, // Using legitimate token
			},
			JSON.stringify(fakeIA102Body),
			attackType
		);

		const ia102Response = await fetch(`${CA_API_URL}/api/ca/sign_request`, ia102BypassOptions);
		console.log('  Status:', ia102Response.status, 'IA102 with valid token but improper sequence');

		// Attack 2: Skip IA102, go directly to IA103 with valid token
		console.log('[Attack 2] Bypassing IA102 → Direct IA103 with valid token');
		const unrealCertTxId = `CERT_${orgCode}_${newTimestamp}_BYPASS`; // This cert_tx_id wasn't generated by IA102
		const fakeIA103Body = {
			sign_tx_id: realisticSignTxId,
			cert_tx_id: unrealCertTxId,
		};

		const ia103BypassOptions = createAttackOptions(
			'POST',
			{
				'Content-Type': 'application/json;charset=UTF-8',
				'x-api-tran-id': generateTIN('S', orgCode),
				Authorization: `Bearer ${access_token}`, // Using legitimate token
			},
			JSON.stringify(fakeIA103Body),
			attackType
		);

		const ia103Response = await fetch(`${CA_API_URL}/api/ca/sign_result`, ia103BypassOptions);
		console.log('  Status:', ia103Response.status, 'IA103 with valid token but no IA102');

		// Attack 3: Skip all intermediate steps, go directly to IA104
		console.log('[Attack 3] Bypassing IA102+IA103 → Direct IA104 with valid token');
		const fakeIA104Body = {
			tx_id: realisticConsentTxId,
			cert_tx_id: unrealCertTxId,
			signed_consent_len: 50,
			signed_consent: Buffer.from('fake-signed-consent').toString('base64'),
			consent_type: '1',
			consent_len: Buffer.from('consent-001').toString('base64').length,
			consent: Buffer.from('consent-001').toString('base64'),
		};

		const ia104BypassOptions = createAttackOptions(
			'POST',
			{
				'Content-Type': 'application/json;charset=UTF-8',
				'x-api-tran-id': generateTIN('S', orgCode),
				Authorization: `Bearer ${access_token}`, // Using legitimate token
			},
			JSON.stringify(fakeIA104Body),
			attackType
		);

		const ia104Response = await fetch(`${CA_API_URL}/api/ca/sign_verification`, ia104BypassOptions);
		console.log('  Status:', ia104Response.status, 'IA104 with valid token but no prior steps');

		// Attack 4: Wrong order - IA103 before IA102 (both with valid tokens)
		console.log('[Attack 4] Wrong sequence order → IA103 before IA102 with valid token');
		const wrongOrderSignTxId = `${orgCode}_${caCode}_${timestamp(new Date())}_wrongorder00`;
		const wrongOrderCertTxId = `CERT_${orgCode}_${timestamp(new Date())}_PREMATURE`;

		const wrongOrderOptions = createAttackOptions(
			'POST',
			{
				'Content-Type': 'application/json;charset=UTF-8',
				'x-api-tran-id': generateTIN('S', orgCode),
				Authorization: `Bearer ${access_token}`, // Using legitimate token
			},
			JSON.stringify({
				sign_tx_id: wrongOrderSignTxId,
				cert_tx_id: wrongOrderCertTxId,
			}),
			attackType
		);

		const wrongOrderResponse = await fetch(`${CA_API_URL}/api/ca/sign_result`, wrongOrderOptions);
		console.log('  Status:', wrongOrderResponse.status, 'IA103 with valid token but wrong order');

		// === Bank API Sequence Bypass Attacks ===
		console.log('\nAttempting Bank API sequence bypasses...');

		let apiUrl = otherBankAPI;
		if (otherBankAPI.includes('4000')) apiUrl = IP_API_URL;
		else if (otherBankAPI.includes('4200')) apiUrl = MO_API_URL;

		// Attack 5: Skip entire CA flow, go directly to IA002 with realistic format
		console.log('[Attack 5] Bypassing entire CA consent flow → Direct IA002');
		const registrationDate = timestamp(new Date()).slice(0, 8); // YYYYMMDD
		const serviceSerial = '0001';
		const realisticServiceId = `${otherOrgCode}${registrationDate}${serviceSerial}`;

		// Generate realistic nonce following simulate.ts pattern
		const generateNonce = () => {
			const letter = faker.string.alpha({ casing: 'upper', length: 1 });
			const year = new Date().getFullYear();
			const randomNumber = faker.number.int({ min: 100000000000000, max: 999999999999999 });
			return `${letter}${year}${randomNumber}`;
		};

		const fakeBodyIA002 = {
			tx_id: realisticConsentTxId, // Using realistic consent tx_id format
			org_code: orgCode,
			grant_type: 'password',
			client_id: clientId, // Using legitimate client credentials
			client_secret: clientSecret, // Using legitimate client secret
			ca_code: caCode,
			username: Buffer.from(account.pinCode).toString('base64'), // Realistic user CI
			request_type: '1',
			password_len: Buffer.from('PASSWORD').toString('base64').length.toString(),
			password: Buffer.from('PASSWORD').toString('base64'),
			auth_type: '1',
			consent_type: '1',
			consent_len: Buffer.from('consent-001').toString('base64').length.toString(),
			consent: Buffer.from('consent-001').toString('base64'),
			signed_person_info_req_len: Buffer.from(account.firstName + account.lastName)
				.toString('base64')
				.length.toString(),
			signed_person_info_req: Buffer.from(account.firstName + account.lastName).toString('base64'),
			consent_nonce: generateNonce(),
			ucpid_nonce: generateNonce(),
			cert_tx_id: unrealCertTxId, // Using the fake cert_tx_id
			service_id: realisticServiceId,
		};

		const ia002Options = createAttackOptions(
			'POST',
			{
				'Content-Type': 'application/x-www-form-urlencoded',
				'x-api-tran-id': generateTIN('S', orgCode),
			},
			new URLSearchParams(fakeBodyIA002),
			attackType
		);

		const ia002Response = await fetch(`${apiUrl}/api/oauth/2.0/token`, ia002Options);
		console.log('  Status:', ia002Response.status, 'IA002 with valid credentials but no CA consent flow');

		// For the remaining attacks, try to use the bank token from IA002 if we got one
		let bankAccessToken = null;
		if (ia002Response.ok) {
			try {
				const ia002Data = await ia002Response.json();
				bankAccessToken = ia002Data.access_token;
			} catch (e) {
				console.log('  Could not extract bank access token from IA002 response');
			}
		}

		// Attack 6: Skip all authentication, go directly to account access
		console.log('[Attack 6] Testing account access with bypassed authentication');
		const testToken = bankAccessToken || access_token; // Use bank token if available, otherwise CA token
		const accountOptions = createAttackOptions(
			'POST',
			{
				'Content-Type': 'application/json;charset=UTF-8',
				'x-api-tran-id': generateTIN('S', orgCode),
				'x-api-type': faker.helpers.arrayElement(['regular', 'irregular']), // Following simulate.ts pattern
				Authorization: `Bearer ${testToken}`,
			},
			JSON.stringify({
				org_code: otherOrgCode,
				account_num: account.accountNum, // Using realistic account number
				next: '0',
				search_timestamp: timestamp(new Date()),
			}),
			attackType
		);

		const accountResponse = await fetch(`${apiUrl}/api/v2/bank/accounts/deposit/basic`, accountOptions);
		console.log('  Status:', accountResponse.status, 'Account basic access with token from bypassed flow');

		// Attack 7: Test detail endpoint with bypassed authentication
		console.log('[Attack 7] Testing account detail access with bypassed authentication');
		const detailOptions = createAttackOptions(
			'POST',
			{
				'Content-Type': 'application/json;charset=UTF-8',
				'x-api-tran-id': generateTIN('S', orgCode),
				'x-api-type': faker.helpers.arrayElement(['regular', 'irregular']), // Following simulate.ts pattern
				Authorization: `Bearer ${testToken}`,
			},
			JSON.stringify({
				org_code: otherOrgCode,
				account_num: account.accountNum, // Using realistic account number
				next: '0',
				search_timestamp: timestamp(new Date()),
			}),
			attackType
		);

		const detailResponse = await fetch(`${apiUrl}/api/v2/bank/accounts/deposit/detail`, detailOptions);
		console.log('  Status:', detailResponse.status, 'Account detail access with token from bypassed flow');

		// Attack 8: Support API called at wrong time with legitimate credentials
		console.log('[Attack 8] Support API called out of sequence with valid credentials');
		try {
			await getSupport002(orgCode, clientId, clientSecret);
			console.log('  Status: Support API called out of sequence with valid credentials');
		} catch (error) {
			console.log('  Status: Support API sequence error with valid credentials');
		}
	} catch (error) {
		console.log('SEQUENCE_BYPASS attack completed with error:', error);
	}
}

// Main sequence bypass attack runner
export async function runSequenceBypassSimulation(
	orgCode: string,
	clientId: string,
	clientSecret: string,
	otherOrgCode: string,
	otherBankAPI: string,
	iterations: number = 1
) {
	console.log(`\n=== SEQUENCE BYPASS Attack Simulation ===`);
	console.log(`Target: Invalid sequence flows from Support API → CA → Bank API`);
	console.log(`Iterations: ${iterations}\n`);

	for (let i = 0; i < iterations; i++) {
		console.log(`\n========== Sequence Bypass Iteration ${i + 1}/${iterations} ==========`);

		try {
			await sequenceBypassAttack(orgCode, clientId, clientSecret, otherOrgCode, otherBankAPI);
			console.log('---');
			await new Promise((resolve) => setTimeout(resolve, faker.number.int({ min: 2000, max: 5000 })));
		} catch (error) {
			console.error('Sequence bypass simulation error:', error);
		}
	}

	console.log('\nSequence bypass attack simulations completed.');
}

// Mixed dataset runner - 70% normal, 30% sequence bypass attacks
export async function runMixedSequenceBypassDataset(
	orgCode: string,
	clientId: string,
	clientSecret: string,
	otherOrgCode: string,
	otherBankAPI: string,
	totalIterations: number = 100
) {
	console.log(`\n=== Mixed Dataset: Normal Flow vs Sequence Bypass ===`);
	console.log(`Total iterations: ${totalIterations}`);
	console.log(
		`Expected: ~${Math.round(totalIterations * 0.7)} normal, ~${Math.round(
			totalIterations * 0.3
		)} sequence bypass attacks\n`
	);

	let normalCount = 0;
	let attackCount = 0;

	for (let i = 0; i < totalIterations; i++) {
		console.log(`\n========== Iteration ${i + 1}/${totalIterations} ==========`);

		// 70% chance of normal flow, 30% chance of sequence bypass attack
		const isNormal = faker.datatype.boolean({ probability: 0.7 });

		try {
			if (isNormal) {
				await executeNormalFlow(orgCode, clientId, clientSecret, otherOrgCode, otherBankAPI);
				normalCount++;
			} else {
				await sequenceBypassAttack(orgCode, clientId, clientSecret, otherOrgCode, otherBankAPI);
				attackCount++;
			}
		} catch (error) {
			console.error('Simulation error:', error);
		}

		// Add random delay between iterations
		await new Promise((resolve) => setTimeout(resolve, faker.number.int({ min: 1000, max: 3000 })));
	}

	console.log(`\n=== Mixed Dataset Simulation Complete ===`);
	console.log(`Normal flows: ${normalCount} (${((normalCount / totalIterations) * 100).toFixed(1)}%)`);
	console.log(`Sequence bypass attacks: ${attackCount} (${((attackCount / totalIterations) * 100).toFixed(1)}%)`);
	console.log('=====================================\n');
}

// Run if executed directly
if (require.main === module) {
	const orgCode = process.env.BOND_ORG_CODE || 'bond123456';
	const clientId = process.env.BOND_CLIENT_ID || 'xv9gqz7mb4t2o5wcf8rjy6kphudsnea0l3ytkpdhqrvcxz1578';
	const clientSecret = process.env.BOND_CLIENT_SECRET || 'm4q7xv9zb2tgc8rjy6kphudsnea0l3ow5ytkpdhqrvcfz926bt';
	const otherOrgCode = process.env.ANYA_ORG_CODE || 'anya123456';
	const otherBankAPI = process.env.ANYA_BANK_API || 'http://information-provider:4000';

	// Choose simulation mode based on environment variable or default to mixed
	const simulationMode = process.env.SIMULATION_MODE || 'mixed'; // 'mixed', 'sequence-bypass-only'

	if (simulationMode === 'mixed') {
		// Run mixed dataset (70% normal, 30% sequence bypass)
		const totalIterations = parseInt(process.env.TOTAL_ITERATIONS || '100');
		runMixedSequenceBypassDataset(orgCode, clientId, clientSecret, otherOrgCode, otherBankAPI, totalIterations)
			.then(() => console.log('Mixed sequence bypass dataset simulation complete.'))
			.catch((error) => console.error('Error running mixed simulation:', error));
	} else {
		// Run sequence bypass attacks only
		const iterations = parseInt(process.env.ITERATIONS || '5');
		runSequenceBypassSimulation(orgCode, clientId, clientSecret, otherOrgCode, otherBankAPI, iterations)
			.then(() => console.log('Sequence bypass attack simulation complete.'))
			.catch((error) => console.error('Error running sequence bypass simulation:', error));
	}
}
