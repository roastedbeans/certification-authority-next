import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

async function main() {
	const caCode = process.env.CA_CODE;
	// find CertificateAuthority
	const ca = await prisma.certificateAuthority.findUnique({
		where: {
			caCode: caCode,
		},
	});

	if (!ca) {
		const response = await prisma.certificateAuthority.create({
			data: {
				name: 'Twilight Cert Auth',
				caCode: caCode as string,
				privateKey: process.env.CA_PRIVATE_KEY as string,
				publicKey: process.env.CA_PUBLIC_KEY as string,
			},
		});

		console.log('Certificate Authority created:', response);
	}
}

main()
	.catch((e) => {
		throw e;
	})
	.finally(async () => {
		await prisma.$disconnect();
	});
