import { initializeCsv } from '@/utils/generateCSV';
import { PrismaClient } from '@prisma/client';
import { NextRequest, NextResponse } from 'next/server';

const prisma = new PrismaClient();

export async function POST(request: NextRequest) {
	await initializeCsv(); // Ensure the CSV file exists
	const body = await request.json();

	const { org_code, name, op_type, org_type, auth_type, industry } = body;

	try {
		const response = await prisma.organization.create({
			data: {
				name: name, // e.g. 'Bond Bank', 'Anya Bank'
				opType: op_type, // I - New, M - Modify, D - Delete
				orgCode: org_code, // ORG2025001, ORG2025002
				orgType: org_type, // e.g. 01 - Information Provider, 03 - Business Operator, 05 - Integrated Cert Agency
				authType: auth_type, // e.g. 01 - Integrated Auth, 02 - Integrated Auth / Individual Auth
				industry: industry, // e.g. bank, card, invest, insu
			},
		});

		return NextResponse.json(response);
	} catch (error) {
		console.error('Error in creating organization:', error);
		return NextResponse.json({ error: 'Error in creating organization' }, { status: 500 });
	}
}
