import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

async function main() {
	const bankAnya = await prisma.organization.create({
		data: {
			name: 'Anya Bank',
			opType: 'I',
			orgCode: 'anya123456',
			orgType: '01',
			authType: '01',
			industry: 'bank',
			serialNum: 'aynaserial00', // Add serialNum as required by the schema
		},
	});

	console.log('Anya Bank created:', bankAnya);

	const bodyOauthAnyaClient = {
		orgCode: 'anya123456',
		clientId: 'anya123456clientid',
		clientSecret: 'anya123456clientsecret',
	};

	const optionOauthAnyaClient = {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
		},
		body: JSON.stringify(bodyOauthAnyaClient),
	};

	const oAuthAnyaBank = await fetch('http://localhost:3000/api/generate_oauth_client', optionOauthAnyaClient);
	console.log('Generate OAuth Client for Anya Bank:', oAuthAnyaBank);

	const bankBond = await prisma.organization.create({
		data: {
			name: 'Bond Bank',
			opType: 'I',
			orgCode: 'bond123456',
			orgType: '01',
			authType: '01',
			industry: 'bank',
			serialNum: 'bondserial00', // Add serialNum as required by the schema
		},
	});

	console.log('Bond Bank created:', bankBond);

	const bodyOauthBondClient = {
		orgCode: 'bond123456',
		clientId: 'bond123456clientid',
		clientSecret: 'bond123456clientsecret',
	};

	const optionOauthBondClient = {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
		},
		body: JSON.stringify(bodyOauthBondClient),
	};

	const oAuthBondBank = await fetch('http://localhost:3000/api/generate_oauth_client', optionOauthBondClient);
	console.log('Generate OAuth Client for Bond Bank:', oAuthBondBank);
}

main()
	.catch((e) => {
		throw e;
	})
	.finally(async () => {
		await prisma.$disconnect();
	});
