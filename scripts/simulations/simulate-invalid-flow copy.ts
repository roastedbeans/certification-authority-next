import { faker } from '@faker-js/faker';
import { generateTIN, timestamp, getIA101, CA_API_URL, IP_API_URL, MO_API_URL, prisma } from './simulate';

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

// Attack Type 1: SEQUENCE_BYPASS - Skip authentication and directly access data
export async function sequenceBypassAttack(orgCode: string, otherOrgCode: string, otherBankAPI: string) {
	console.log('Starting SEQUENCE_BYPASS attack...');
	const attackType = 'sequence-bypass';

	try {
		// CA API Sequence Bypass Attacks
		console.log('Attempting CA API sequence bypasses...');

		// Attack 1: Skip IA101, go directly to IA102
		const fakeIA102Body = {
			sign_tx_id: `BYPASS_${orgCode}_certauth00_${timestamp(new Date())}_001`,
			user_ci: Buffer.from('BYPASS_USER').toString('base64'),
			real_name: faker.person.fullName(),
			phone_num: faker.phone.number(),
			request_title: 'Bypass Consent Request',
			device_code: 'PC',
			device_browser: 'WB',
			return_app_scheme_url: 'https://bypass.com/return',
			consent_type: '1',
			consent_cnt: 1,
			consent_list: [
				{
					tx_id: `MD_${orgCode}_${otherOrgCode}_BYPASS_${timestamp(new Date())}_001`,
					consent_title: 'Bypass Consent',
					consent: Buffer.from('bypass-consent').toString('base64'),
					consent_len: 14,
				},
			],
		};

		const ia102BypassOptions = createAttackOptions(
			'POST',
			{
				'Content-Type': 'application/json;charset=UTF-8',
				'x-api-tran-id': generateTIN('S', orgCode),
				Authorization: 'Bearer FAKE_TOKEN_NO_IA101', // No valid IA101 token
			},
			JSON.stringify(fakeIA102Body),
			attackType
		);

		const ia102Response = await fetch(`${CA_API_URL}/api/ca/sign_request`, ia102BypassOptions);
		console.log('CA Bypass: IA102 without IA101:', ia102Response.status);

		// Attack 2: Skip IA101+IA102, go directly to IA103
		const fakeIA103Body = {
			sign_tx_id: `BYPASS_${orgCode}_certauth00_${timestamp(new Date())}_002`,
			cert_tx_id: 'FAKE_CERT_TX_' + timestamp(new Date()),
		};

		const ia103BypassOptions = createAttackOptions(
			'POST',
			{
				'Content-Type': 'application/json;charset=UTF-8',
				'x-api-tran-id': generateTIN('S', orgCode),
				Authorization: 'Bearer FAKE_TOKEN_NO_IA102',
			},
			JSON.stringify(fakeIA103Body),
			attackType
		);

		const ia103Response = await fetch(`${CA_API_URL}/api/ca/sign_result`, ia103BypassOptions);
		console.log('CA Bypass: IA103 without IA102:', ia103Response.status);

		// Attack 3: Skip all, go directly to IA104
		const fakeIA104Body = {
			tx_id: `MD_${orgCode}_${otherOrgCode}_BYPASS_${timestamp(new Date())}_003`,
			cert_tx_id: 'FAKE_CERT_TX_DIRECT_' + timestamp(new Date()),
			signed_consent_len: 50,
			signed_consent: Buffer.from('FAKE_SIGNED_CONSENT').toString('base64'),
			consent_type: '1',
			consent_len: 20,
			consent: Buffer.from('FAKE_CONSENT').toString('base64'),
		};

		const ia104BypassOptions = createAttackOptions(
			'POST',
			{
				'Content-Type': 'application/json;charset=UTF-8',
				'x-api-tran-id': generateTIN('S', orgCode),
				Authorization: 'Bearer FAKE_TOKEN_DIRECT_IA104',
			},
			JSON.stringify(fakeIA104Body),
			attackType
		);

		const ia104Response = await fetch(`${CA_API_URL}/api/ca/sign_verification`, ia104BypassOptions);
		console.log('CA Bypass: IA104 without prior steps:', ia104Response.status);

		// Attack 4: Wrong order - IA103 before IA102
		const wrongOrderOptions = createAttackOptions(
			'POST',
			{
				'Content-Type': 'application/json;charset=UTF-8',
				'x-api-tran-id': generateTIN('S', orgCode),
				Authorization: 'Bearer FAKE_TOKEN_WRONG_ORDER',
			},
			JSON.stringify({
				sign_tx_id: 'NONEXISTENT_TX_ID',
				cert_tx_id: 'PREMATURE_CERT_TX_ID',
			}),
			attackType
		);

		const wrongOrderResponse = await fetch(`${CA_API_URL}/api/ca/sign_result`, wrongOrderOptions);
		console.log('CA Bypass: Wrong order (IA103 first):', wrongOrderResponse.status);

		// Original bank API bypass attacks
		// Skip IA101, IA102, IA103 - directly attempt IA002 without proper authentication
		const fakeBodyIA002 = {
			tx_id: `FAKE_${orgCode}_${otherOrgCode}_XXXX_${timestamp(new Date())}_0001`,
			org_code: orgCode,
			grant_type: 'password',
			client_id: faker.string.alphanumeric(50),
			client_secret: faker.string.alphanumeric(50),
			ca_code: 'certauth00',
			username: Buffer.from('FAKEUSER').toString('base64'),
			request_type: '1',
			password_len: '8',
			password: Buffer.from('FAKEPASS').toString('base64'),
			auth_type: '1',
			consent_type: '1',
			consent_len: '100',
			consent: Buffer.from('fake-consent').toString('base64'),
			signed_person_info_req_len: '50',
			signed_person_info_req: Buffer.from('fake-person-info').toString('base64'),
			consent_nonce: faker.string.alphanumeric(20),
			ucpid_nonce: faker.string.alphanumeric(20),
			cert_tx_id: `FAKE_CERT_${timestamp(new Date())}`,
			service_id: `${otherOrgCode}${timestamp(new Date()).slice(0, 8)}0001`,
		};

		let apiUrl = otherBankAPI;
		if (otherBankAPI.includes('4000')) apiUrl = IP_API_URL;
		else if (otherBankAPI.includes('4200')) apiUrl = MO_API_URL;

		// Attack 5: Direct IA002 without consent flow
		const ia002Options = createAttackOptions(
			'POST',
			{
				'Content-Type': 'application/x-www-form-urlencoded',
				'x-api-tran-id': generateTIN('S', orgCode),
			},
			new URLSearchParams(fakeBodyIA002),
			attackType
		);

		const response = await fetch(`${apiUrl}/api/oauth/2.0/token`, ia002Options);
		console.log('Bank Bypass: IA002 without CA flow:', response.status);

		// Attack 6: Try to access accounts with fake token
		const fakeAccessToken = faker.string.alphanumeric(100);
		const accountOptions = createAttackOptions(
			'POST',
			{
				'Content-Type': 'application/json;charset=UTF-8',
				'x-api-tran-id': generateTIN('S', orgCode),
				Authorization: `Bearer ${fakeAccessToken}`,
			},
			JSON.stringify({
				org_code: otherOrgCode,
				account_num: faker.finance.accountNumber(),
				next: '0',
				search_timestamp: timestamp(new Date()),
			}),
			attackType
		);

		const accountResponse = await fetch(`${apiUrl}/api/v2/bank/accounts/deposit/basic`, accountOptions);
		console.log('Bank Bypass: Direct account access:', accountResponse.status);

		// Attack 7: Try detail endpoint too
		const detailOptions = createAttackOptions(
			'POST',
			{
				'Content-Type': 'application/json;charset=UTF-8',
				'x-api-tran-id': generateTIN('S', orgCode),
				Authorization: `Bearer ${fakeAccessToken}`,
			},
			JSON.stringify({
				org_code: otherOrgCode,
				account_num: faker.finance.accountNumber(),
				next: '0',
				search_timestamp: timestamp(new Date()),
			}),
			attackType
		);
		const detailResponse = await fetch(`${apiUrl}/api/v2/bank/accounts/deposit/detail`, detailOptions);
		console.log('Bank Bypass: Detail access:', detailResponse.status);
	} catch (error) {
		console.log('SEQUENCE_BYPASS attack completed with error:', error);
	}
}

// Attack Type 2: TRANSACTION_ID_DUPLICATE - Reuse transaction IDs across different contexts
export async function transactionIdDuplicateAttack(
	orgCode: string,
	clientId: string,
	clientSecret: string,
	otherOrgCode: string,
	otherBankAPI: string
) {
	console.log('Starting TRANSACTION_ID_DUPLICATE attack...');
	const attackType = 'transaction-id-duplicate';

	try {
		// Get legitimate access token
		const IA101Response = await getIA101(orgCode, clientId, clientSecret);
		const { access_token } = IA101Response?.body;

		// Attack 1: Same sign_tx_id for different users
		const duplicatedSignTxId = `${orgCode}_certauth00_${timestamp(new Date())}_DUP001`;
		console.log('\n[Attack 1] Duplicating sign_tx_id across different users...');

		for (let i = 0; i < 3; i++) {
			const bodyIA102 = {
				sign_tx_id: duplicatedSignTxId, // Same ID for all users
				user_ci: Buffer.from(`DIFFERENT_USER_${i}`).toString('base64'), // Different users
				real_name: faker.person.fullName(),
				phone_num: faker.phone.number(),
				request_title: 'Consent Request',
				device_code: faker.helpers.arrayElement(['PC', 'MO', 'TB']),
				device_browser: 'WB',
				return_app_scheme_url: 'https://duplicate.com/return',
				consent_type: '1',
				consent_cnt: 1,
				consent_list: [
					{
						tx_id: `MD_${orgCode}_${otherOrgCode}_USER${i}_${timestamp(new Date())}_001`,
						consent_title: 'User Consent',
						consent: Buffer.from(`consent-for-user-${i}`).toString('base64'),
						consent_len: 20,
					},
				],
			};

			const options = createAttackOptions(
				'POST',
				{
					'Content-Type': 'application/json;charset=UTF-8',
					'x-api-tran-id': generateTIN('S', orgCode),
					Authorization: `Bearer ${access_token}`,
				},
				JSON.stringify(bodyIA102),
				attackType
			);

			const response = await fetch(`${CA_API_URL}/api/ca/sign_request`, options);
			console.log(`  User ${i + 1} with duplicated sign_tx_id:`, response.status);
			await new Promise((resolve) => setTimeout(resolve, 1000));
		}

		// Attack 2: Reuse cert_tx_id from previous transaction
		console.log('\n[Attack 2] Reusing cert_tx_id from different transaction...');
		const stolenCertTxId = 'CERT_TX_STOLEN_FROM_ANOTHER_USER';

		const bodyIA103 = {
			sign_tx_id: `${orgCode}_certauth00_${timestamp(new Date())}_NEW`,
			cert_tx_id: stolenCertTxId, // Reusing cert_tx_id from another transaction
		};

		const stolenCertOptions = createAttackOptions(
			'POST',
			{
				'Content-Type': 'application/json;charset=UTF-8',
				'x-api-tran-id': generateTIN('S', orgCode),
				Authorization: `Bearer ${access_token}`,
			},
			JSON.stringify(bodyIA103),
			attackType
		);

		const stolenCertResponse = await fetch(`${CA_API_URL}/api/ca/sign_result`, stolenCertOptions);
		console.log('  Reused cert_tx_id response:', stolenCertResponse.status);

		// Attack 3: Duplicate transaction across different banks
		console.log('\n[Attack 3] Duplicating transaction across banks...');
		const duplicatedBankTxId = `MD_${orgCode}_ANYBANK_DUP_${timestamp(new Date())}_001`;

		let apiUrl = otherBankAPI;
		if (otherBankAPI.includes('4000')) apiUrl = IP_API_URL;
		else if (otherBankAPI.includes('4200')) apiUrl = MO_API_URL;

		const duplicatedIA002 = {
			tx_id: duplicatedBankTxId, // Same transaction ID
			org_code: orgCode,
			grant_type: 'password',
			client_id: clientId,
			client_secret: clientSecret,
			ca_code: 'certauth00',
			username: Buffer.from('DUP_BANK_USER').toString('base64'),
			request_type: '1',
			password_len: '10',
			password: Buffer.from('DUPPASS123').toString('base64'),
			auth_type: '1',
			consent_type: '1',
			consent_len: '30',
			consent: Buffer.from('duplicate-bank-consent').toString('base64'),
			signed_person_info_req_len: '25',
			signed_person_info_req: Buffer.from('dup-person-info').toString('base64'),
			consent_nonce: faker.string.alphanumeric(20),
			ucpid_nonce: faker.string.alphanumeric(20),
			cert_tx_id: 'DUP_CERT_TX_' + timestamp(new Date()),
			service_id: `${otherOrgCode}${timestamp(new Date()).slice(0, 8)}0001`,
		};

		const bankOptions = createAttackOptions(
			'POST',
			{
				'Content-Type': 'application/x-www-form-urlencoded',
				'x-api-tran-id': generateTIN('S', orgCode),
			},
			new URLSearchParams(duplicatedIA002),
			attackType
		);

		const response = await fetch(`${apiUrl}/api/oauth/2.0/token`, bankOptions);
		console.log('  Bank duplicate tx response:', response.status);
	} catch (error) {
		console.log('TRANSACTION_ID_DUPLICATE attack completed with error:', error);
	}
}

// Attack Type 3: TRANSACTION_ID_MANIPULATION - Manipulate transaction ID formats and values
export async function transactionManipulationAttack(
	orgCode: string,
	clientId: string,
	clientSecret: string,
	otherOrgCode: string
) {
	console.log('Starting TRANSACTION_ID_MANIPULATION attack...');
	const attackType = 'transaction-id-manipulation';

	try {
		// Get legitimate access token
		const IA101Response = await getIA101(orgCode, clientId, clientSecret);
		const { access_token } = IA101Response?.body;

		// Attack 1: Malformed transaction ID formats
		console.log('\n[Attack 1] Using malformed transaction ID formats...');
		const malformedIds = [
			'', // Empty ID
			'INVALID FORMAT WITH SPACES',
			'<script>alert(1)</script>', // XSS attempt
			'A'.repeat(200), // Very long ID
			'😀🎉🔥', // Unicode/emoji
		];

		for (let i = 0; i < malformedIds.length; i++) {
			const bodyIA102 = {
				sign_tx_id: malformedIds[i],
				user_ci: Buffer.from('MALFORMED_USER').toString('base64'),
				real_name: faker.person.fullName(),
				phone_num: faker.phone.number(),
				request_title: 'Malformed ID Test',
				device_code: 'PC',
				device_browser: 'WB',
				return_app_scheme_url: 'https://malformed.com/return',
				consent_type: '1',
				consent_cnt: 1,
				consent_list: [
					{
						tx_id: `MD_${orgCode}_${otherOrgCode}_MAL_${i}`,
						consent_title: 'Malformed Consent',
						consent: Buffer.from('malformed-consent').toString('base64'),
						consent_len: 17,
					},
				],
			};

			const options = createAttackOptions(
				'POST',
				{
					'Content-Type': 'application/json;charset=UTF-8',
					'x-api-tran-id': generateTIN('S', orgCode),
					Authorization: `Bearer ${access_token}`,
				},
				JSON.stringify(bodyIA102),
				attackType
			);

			const response = await fetch(`${CA_API_URL}/api/ca/sign_request`, options);
			console.log(`  Malformed ID "${malformedIds[i].substring(0, 20)}...":`, response.status);
			await new Promise((resolve) => setTimeout(resolve, 500));
		}

		// Attack 2: Manipulate cert_tx_id relationships
		console.log('\n[Attack 2] Manipulating cert_tx_id relationships...');

		// Use cert_tx_id that doesn't match any sign_tx_id
		const orphanedIA103 = {
			sign_tx_id: 'LEGITIMATE_SIGN_TX_12345',
			cert_tx_id: 'ORPHANED_CERT_TX_' + faker.string.alphanumeric(10),
		};

		const orphanedOptions = createAttackOptions(
			'POST',
			{
				'Content-Type': 'application/json;charset=UTF-8',
				'x-api-tran-id': generateTIN('S', orgCode),
				Authorization: `Bearer ${access_token}`,
			},
			JSON.stringify(orphanedIA103),
			attackType
		);

		const orphanedResponse = await fetch(`${CA_API_URL}/api/ca/sign_result`, orphanedOptions);
		console.log('  Orphaned cert_tx_id response:', orphanedResponse.status);

		// Attack 3: Swap transaction IDs between requests
		console.log('\n[Attack 3] Swapping transaction IDs between requests...');

		const txId1 = `${orgCode}_certauth00_${timestamp(new Date())}_SWAP1`;
		const txId2 = `${orgCode}_certauth00_${timestamp(new Date())}_SWAP2`;

		// First request with txId1 but cert for txId2
		const swap1Options = createAttackOptions(
			'POST',
			{
				'Content-Type': 'application/json;charset=UTF-8',
				'x-api-tran-id': generateTIN('S', orgCode),
				Authorization: `Bearer ${access_token}`,
			},
			JSON.stringify({
				sign_tx_id: txId1,
				cert_tx_id: 'CERT_FOR_TX2', // Wrong cert_tx_id
			}),
			attackType
		);

		const swap1Response = await fetch(`${CA_API_URL}/api/ca/sign_result`, swap1Options);
		console.log('  Swapped TX response:', swap1Response.status);
	} catch (error) {
		console.log('TRANSACTION_ID_MANIPULATION attack completed with error:', error);
	}
}

// Attack Type 4: CONSENT_FORGERY - Skip or forge consent verification
export async function consentForgeryAttack(
	orgCode: string,
	clientId: string,
	clientSecret: string,
	otherOrgCode: string,
	otherBankAPI: string
) {
	console.log('Starting CONSENT_FORGERY attack...');
	const attackType = 'consent-forgery';

	try {
		const IA101Response = await getIA101(orgCode, clientId, clientSecret);
		const { access_token } = IA101Response?.body;

		let apiUrl = otherBankAPI;
		if (otherBankAPI.includes('4000')) apiUrl = IP_API_URL;
		else if (otherBankAPI.includes('4200')) apiUrl = MO_API_URL;

		// Attack 1: Skip IA102/IA103 with forged consent
		const forgedBodyIA002 = {
			tx_id: `MD_${orgCode}_${otherOrgCode}_FORGED_${timestamp(new Date())}_0001`,
			org_code: orgCode,
			grant_type: 'password',
			client_id: faker.string.alphanumeric(50),
			client_secret: faker.string.alphanumeric(50),
			ca_code: 'certauth00',
			username: Buffer.from('FORGEDUSER').toString('base64'),
			request_type: '1',
			password_len: '12',
			password: Buffer.from('FORGEDPASS').toString('base64'),
			auth_type: '1',
			consent_type: '1',
			consent_len: '50',
			consent: Buffer.from('FORGED_CONSENT').toString('base64'),
			signed_person_info_req_len: '30',
			signed_person_info_req: Buffer.from('FORGED_PERSON_INFO').toString('base64'),
			consent_nonce: faker.string.alphanumeric(20),
			ucpid_nonce: faker.string.alphanumeric(20),
			cert_tx_id: 'FORGED_CERT_TX_' + timestamp(new Date()),
			service_id: `${otherOrgCode}${timestamp(new Date()).slice(0, 8)}0001`,
		};

		const forgedOptions = createAttackOptions(
			'POST',
			{
				'Content-Type': 'application/x-www-form-urlencoded',
				'x-api-tran-id': generateTIN('S', orgCode),
			},
			new URLSearchParams(forgedBodyIA002),
			attackType
		);

		const response = await fetch(`${apiUrl}/api/oauth/2.0/token`, forgedOptions);
		console.log('CONSENT_FORGERY forged consent response:', response.status);

		// Attack 2: Skip IA104 verification
		const fakeAccessToken = faker.string.alphanumeric(100);
		const skipVerificationOptions = createAttackOptions(
			'POST',
			{
				'Content-Type': 'application/json;charset=UTF-8',
				'x-api-tran-id': generateTIN('S', orgCode),
				Authorization: `Bearer ${fakeAccessToken}`,
			},
			JSON.stringify({
				org_code: otherOrgCode,
				account_num: faker.finance.accountNumber(),
				next: '0',
				search_timestamp: timestamp(new Date()),
			}),
			attackType
		);

		const accountAccess = await fetch(`${apiUrl}/api/v2/bank/accounts/deposit/basic`, skipVerificationOptions);
		console.log('CONSENT_FORGERY access without verification:', accountAccess.status);

		// Attack 3: Forge IA104 verification request
		const forgedIA104 = {
			tx_id: `MD_${orgCode}_${otherOrgCode}_FORGED_${timestamp(new Date())}_0001`,
			cert_tx_id: 'FORGED_CERT_TX_' + timestamp(new Date()),
			signed_consent_len: 50,
			signed_consent: Buffer.from('FORGED_SIGNED_CONSENT').toString('base64'),
			consent_type: '1',
			consent_len: 30,
			consent: Buffer.from('FORGED_CONSENT').toString('base64'),
		};

		const forgedVerifyOptions = createAttackOptions(
			'POST',
			{
				'Content-Type': 'application/json;charset=UTF-8',
				'x-api-tran-id': generateTIN('S', orgCode),
				Authorization: `Bearer ${access_token}`,
			},
			JSON.stringify(forgedIA104),
			attackType
		);

		const verifyResponse = await fetch(`${CA_API_URL}/api/ca/sign_verification`, forgedVerifyOptions);
		console.log('CONSENT_FORGERY forged verification:', verifyResponse.status);
	} catch (error) {
		console.log('CONSENT_FORGERY attack completed with error:', error);
	}
}

// Attack Type 5: TOKEN_REPLAY - Reuse expired or stolen tokens
export async function tokenReplayAttack(
	orgCode: string,
	clientId: string,
	clientSecret: string,
	otherOrgCode: string,
	otherBankAPI: string
) {
	console.log('Starting TOKEN_REPLAY attack...');
	const attackType = 'token-replay';

	try {
		// Get legitimate tokens
		const IA101Response = await getIA101(orgCode, clientId, clientSecret);
		const { access_token: caToken } = IA101Response?.body;

		let apiUrl = otherBankAPI;
		if (otherBankAPI.includes('4000')) apiUrl = IP_API_URL;
		else if (otherBankAPI.includes('4200')) apiUrl = MO_API_URL;

		// Simulate getting a bank token (using fake data)
		const fakeBankToken = 'STOLEN_BANK_TOKEN_' + faker.string.alphanumeric(50);

		// Attack 1: Replay expired CA token
		console.log('Simulating token expiry period...');
		await new Promise((resolve) => setTimeout(resolve, 2000));

		const expiredTokenOptions = createAttackOptions(
			'POST',
			{
				'Content-Type': 'application/json;charset=UTF-8',
				'x-api-tran-id': generateTIN('S', orgCode),
				Authorization: `Bearer ${caToken}`, // Potentially expired
			},
			JSON.stringify({
				sign_tx_id: `${orgCode}_certauth00_${timestamp(new Date())}_REPLAY001`,
				user_ci: Buffer.from('REPLAYUSER').toString('base64'),
				real_name: faker.person.fullName(),
				phone_num: faker.phone.number(),
				request_title: 'Replay Request',
				device_code: 'PC',
				device_browser: 'WB',
				return_app_scheme_url: 'https://replay.com/return',
				consent_type: '1',
				consent_cnt: 1,
				consent_list: [
					{
						tx_id: `MD_${orgCode}_${otherOrgCode}_REPLAY_${timestamp(new Date())}_0001`,
						consent_title: 'Replay Consent',
						consent: Buffer.from('replay-consent').toString('base64'),
						consent_len: 14,
					},
				],
			}),
			attackType
		);

		const expiredResponse = await fetch(`${CA_API_URL}/api/ca/sign_request`, expiredTokenOptions);
		console.log('TOKEN_REPLAY expired CA token reuse:', expiredResponse.status);

		// Attack 2: Replay bank token multiple times
		for (let i = 0; i < 5; i++) {
			const replayOptions = createAttackOptions(
				'POST',
				{
					'Content-Type': 'application/json;charset=UTF-8',
					'x-api-tran-id': generateTIN('S', orgCode),
					Authorization: `Bearer ${fakeBankToken}`,
				},
				JSON.stringify({
					org_code: otherOrgCode,
					account_num: faker.finance.accountNumber(),
					next: '0',
					search_timestamp: timestamp(new Date()),
				}),
				attackType
			);

			const basicResponse = await fetch(`${apiUrl}/api/v2/bank/accounts/deposit/basic`, replayOptions);
			console.log(`TOKEN_REPLAY bank token replay ${i + 1} (basic):`, basicResponse.status);

			const detailResponse = await fetch(`${apiUrl}/api/v2/bank/accounts/deposit/detail`, replayOptions);
			console.log(`TOKEN_REPLAY bank token replay ${i + 1} (detail):`, detailResponse.status);

			await new Promise((resolve) => setTimeout(resolve, 500));
		}
	} catch (error) {
		console.log('TOKEN_REPLAY attack completed with error:', error);
	}
}

// Attack Type 6: CROSS_ORGANIZATION_ACCESS - Try to access data from wrong organization
export async function crossOrganizationAttack(
	orgCode: string,
	clientId: string,
	clientSecret: string,
	otherOrgCode: string,
	thirdOrgCode: string,
	otherBankAPI: string
) {
	console.log('Starting CROSS_ORGANIZATION_ACCESS attack...');
	const attackType = 'cross-organization-access';

	try {
		// Get legitimate token for orgCode
		const IA101Response = await getIA101(orgCode, clientId, clientSecret);
		const { access_token } = IA101Response?.body;

		let apiUrl = otherBankAPI;
		if (otherBankAPI.includes('4000')) apiUrl = IP_API_URL;
		else if (otherBankAPI.includes('4200')) apiUrl = MO_API_URL;

		// Attack 1: Use orgCode credentials to access thirdOrgCode data
		const crossOrgIA002 = {
			tx_id: `MD_${thirdOrgCode}_${otherOrgCode}_CROSS_${timestamp(new Date())}_0001`,
			org_code: thirdOrgCode, // Wrong org!
			grant_type: 'password',
			client_id: clientId, // Using orgCode's credentials
			client_secret: clientSecret,
			ca_code: 'certauth00',
			username: Buffer.from('CROSSUSER').toString('base64'),
			request_type: '1',
			password_len: '10',
			password: Buffer.from('CROSSPASS').toString('base64'),
			auth_type: '1',
			consent_type: '1',
			consent_len: '20',
			consent: Buffer.from('cross-consent').toString('base64'),
			signed_person_info_req_len: '25',
			signed_person_info_req: Buffer.from('cross-person-info').toString('base64'),
			consent_nonce: faker.string.alphanumeric(20),
			ucpid_nonce: faker.string.alphanumeric(20),
			cert_tx_id: 'CROSS_CERT_TX_' + timestamp(new Date()),
			service_id: `${thirdOrgCode}${timestamp(new Date()).slice(0, 8)}0001`,
		};

		const crossOrgOptions = createAttackOptions(
			'POST',
			{
				'Content-Type': 'application/x-www-form-urlencoded',
				'x-api-tran-id': generateTIN('S', thirdOrgCode),
			},
			new URLSearchParams(crossOrgIA002),
			attackType
		);

		const crossOrgResponse = await fetch(`${apiUrl}/api/oauth/2.0/token`, crossOrgOptions);
		console.log('CROSS_ORGANIZATION_ACCESS unauthorized org token request:', crossOrgResponse.status);

		// Attack 2: Use valid token but wrong org_code in data request
		const wrongOrgDataOptions = createAttackOptions(
			'POST',
			{
				'Content-Type': 'application/json;charset=UTF-8',
				'x-api-tran-id': generateTIN('S', thirdOrgCode),
				Authorization: `Bearer ${access_token}`, // Valid token from orgCode
			},
			JSON.stringify({
				org_code: thirdOrgCode, // Requesting data from wrong org
				account_num: faker.finance.accountNumber(),
				next: '0',
				search_timestamp: timestamp(new Date()),
			}),
			attackType
		);

		const unauthorizedBasic = await fetch(`${apiUrl}/api/v2/bank/accounts/deposit/basic`, wrongOrgDataOptions);
		console.log('CROSS_ORGANIZATION_ACCESS wrong org basic access:', unauthorizedBasic.status);

		const unauthorizedDetail = await fetch(`${apiUrl}/api/v2/bank/accounts/deposit/detail`, wrongOrgDataOptions);
		console.log('CROSS_ORGANIZATION_ACCESS wrong org detail access:', unauthorizedDetail.status);

		// Attack 3: Manipulate consent to include wrong org
		const manipulatedConsentOptions = createAttackOptions(
			'POST',
			{
				'Content-Type': 'application/json;charset=UTF-8',
				'x-api-tran-id': generateTIN('S', orgCode),
				Authorization: `Bearer ${access_token}`,
			},
			JSON.stringify({
				sign_tx_id: `${orgCode}_certauth00_${timestamp(new Date())}_CROSS001`,
				user_ci: Buffer.from('CROSSUSER').toString('base64'),
				real_name: faker.person.fullName(),
				phone_num: faker.phone.number(),
				request_title: 'Cross Org Request',
				device_code: 'PC',
				device_browser: 'WB',
				return_app_scheme_url: 'https://cross.com/return',
				consent_type: '1',
				consent_cnt: 1,
				consent_list: [
					{
						tx_id: `MD_${thirdOrgCode}_${otherOrgCode}_CROSS_${timestamp(new Date())}_0001`,
						consent_title: 'Cross Org Consent',
						consent: Buffer.from('cross-org-consent').toString('base64'),
						consent_len: 17,
					},
				],
			}),
			attackType
		);

		const crossConsentResponse = await fetch(`${CA_API_URL}/api/ca/sign_request`, manipulatedConsentOptions);
		console.log('CROSS_ORGANIZATION_ACCESS manipulated consent:', crossConsentResponse.status);
	} catch (error) {
		console.log('CROSS_ORGANIZATION_ACCESS attack completed with error:', error);
	}
}

// Main attack runner
export async function runAttackSimulations(
	orgCode: string,
	clientId: string,
	clientSecret: string,
	otherOrgCode: string,
	otherBankAPI: string,
	iterations: number = 1
) {
	const thirdOrgCode = 'third12345'; // Additional org for cross-org attacks

	const attacks = [
		() => sequenceBypassAttack(orgCode, otherOrgCode, otherBankAPI),
		() => transactionIdDuplicateAttack(orgCode, clientId, clientSecret, otherOrgCode, otherBankAPI),
		() => transactionManipulationAttack(orgCode, clientId, clientSecret, otherOrgCode),
		() => consentForgeryAttack(orgCode, clientId, clientSecret, otherOrgCode, otherBankAPI),
		() => tokenReplayAttack(orgCode, clientId, clientSecret, otherOrgCode, otherBankAPI),
		() => crossOrganizationAttack(orgCode, clientId, clientSecret, otherOrgCode, thirdOrgCode, otherBankAPI),
	];

	for (let i = 0; i < iterations; i++) {
		console.log(`\n=== Attack Simulation Iteration ${i + 1} ===\n`);

		for (const attack of attacks) {
			try {
				await attack();
				console.log('---');
				await new Promise((resolve) => setTimeout(resolve, 2000));
			} catch (error) {
				console.error('Attack simulation error:', error);
			}
		}
	}

	console.log('\nAll attack simulations completed.');
}

// Run if executed directly
if (require.main === module) {
	const orgCode = process.env.BOND_ORG_CODE || 'bond123456';
	const clientId = process.env.BOND_CLIENT_ID || 'xv9gqz7mb4t2o5wcf8rjy6kphudsnea0l3ytkpdhqrvcxz1578';
	const clientSecret = process.env.BOND_CLIENT_SECRET || 'm4q7xv9zb2tgc8rjy6kphudsnea0l3ow5ytkpdhqrvcfz926bt';
	const otherOrgCode = process.env.ANYA_ORG_CODE || 'anya123456';
	const otherBankAPI = process.env.ANYA_BANK_API || 'http://information-provider:4000';

	runAttackSimulations(orgCode, clientId, clientSecret, otherOrgCode, otherBankAPI)
		.then(() => console.log('Attack simulation complete.'))
		.catch((error) => console.error('Error running attack simulation:', error));
}
