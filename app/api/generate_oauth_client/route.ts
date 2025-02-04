import { PrismaClient } from '@prisma/client';
import { NextRequest, NextResponse } from 'next/server';

const prisma = new PrismaClient();

export async function POST(request: NextRequest) {
	const body = await request.json();

	const { orgCode, clientId, clientSecret } = body;

	if (!orgCode || !clientId || !clientSecret) {
		return NextResponse.json({ error: 'Missing required fields' }, { status: 400 });
	}

	try {
		const organization = await prisma.organization.findUnique({
			where: {
				orgCode: orgCode,
			},
		});

		if (!organization) {
			return NextResponse.json({ error: 'Organization not found' }, { status: 404 });
		}

		const response = await prisma.oAuthClient.create({
			data: {
				organizationId: organization.id,
				clientId: clientId,
				clientSecret: clientSecret,
			},
		});

		return NextResponse.json(response);
	} catch (error) {
		console.error('Error in creating organization:', error);
		return NextResponse.json({ error: 'Error in creating organization oauth client' }, { status: 500 });
	}
}
