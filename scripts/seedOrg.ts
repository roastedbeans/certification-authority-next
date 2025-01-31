import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

async function main() {
	const bankAnya = await prisma.organization.create({
		data: {
			name: 'Anya Bank',
			opType: 'I',
			orgCode: 'ORG2025001',
			orgType: '01',
			authType: '01',
			industry: 'bank',
			serialNum: 'BOAB20240201', // Add serialNum as required by the schema
		},
	});

	console.log('Anya Bank created:', bankAnya);

	const bodyOauthAnyaClient = {
		orgCode: 'ORG2025001',
		clientId: 'ORG2025001-CLIENT-ID',
		clientSecret: 'ORG2025001-CLIENT-SECRET',
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
			orgCode: 'ORG2025002',
			orgType: '01',
			authType: '01',
			industry: 'bank',
			serialNum: 'BOBB20240202', // Add serialNum as required by the schema
		},
	});

	console.log('Bond Bank created:', bankBond);

	const bodyOauthBondClient = {
		orgCode: 'ORG2025002',
		clientId: 'ORG2025002-CLIENT-ID',
		clientSecret: 'ORG2025002-CLIENT-SECRET',
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
