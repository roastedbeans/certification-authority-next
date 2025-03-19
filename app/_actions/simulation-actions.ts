'use server';

import { runIterations } from '@/scripts/simulations/simulate';
import { runAttackIterations } from '@/scripts/simulations/simulateV2';

export type Direction = 'anya-to-bond' | 'bond-to-anya';
export type SimulationType = 'normal' | 'attack';

export type ConfigVars = {
	otherBankAPI: string;
	otherOrgCode: string;
	orgCode: string;
	orgSerialCode: string;
	clientId: string;
	clientSecret: string;
	iterations?: number;
	[key: string]: string | number | undefined;
};

export type VariablesConfig = {
	[key in Direction]: ConfigVars;
};

// Define default configurations but don't export directly
const variables: VariablesConfig = {
	'anya-to-bond': {
		otherBankAPI: process.env.NEXT_PUBLIC_BOND_BANK_API || '',
		otherOrgCode: process.env.NEXT_PUBLIC_BOND_ORG_CODE || '',
		orgCode: process.env.NEXT_PUBLIC_ANYA_ORG_CODE || '',
		orgSerialCode: process.env.NEXT_PUBLIC_ANYA_ORG_SERIAL_CODE || '',
		clientId: process.env.NEXT_PUBLIC_ANYA_CLIENT_ID || '',
		clientSecret: process.env.NEXT_PUBLIC_ANYA_CLIENT_SECRET || '',
	},
	'bond-to-anya': {
		otherBankAPI: process.env.NEXT_PUBLIC_ANYA_BANK_API || '',
		otherOrgCode: process.env.NEXT_PUBLIC_ANYA_ORG_CODE || '',
		orgCode: process.env.NEXT_PUBLIC_BOND_ORG_CODE || '',
		orgSerialCode: process.env.NEXT_PUBLIC_BOND_ORG_SERIAL_CODE || '',
		clientId: process.env.NEXT_PUBLIC_BOND_CLIENT_ID || '',
		clientSecret: process.env.NEXT_PUBLIC_BOND_CLIENT_SECRET || '',
	},
};

// Server function to get variables
export async function getVariables(direction: Direction): Promise<ConfigVars> {
	return variables[direction];
}

export async function runSimulation(params: {
	type: SimulationType;
	direction: Direction;
	config?: ConfigVars;
	iterations?: number;
}) {
	try {
		const { type, direction, config, iterations = 5 } = params;

		// Use custom config if provided, otherwise use default
		const envVars = config || variables[direction];

		console.log('Running simulation', type, direction, envVars);

		// Run the appropriate simulation function
		if (type === 'normal') {
			await runIterations(
				iterations,
				envVars.orgCode,
				envVars.clientId,
				envVars.clientSecret,
				envVars.otherOrgCode,
				envVars.otherBankAPI
			);
		} else {
			await runAttackIterations(
				iterations,
				envVars.orgCode,
				envVars.clientId,
				envVars.clientSecret,
				envVars.otherOrgCode,
				envVars.otherBankAPI
			);
		}

		return {
			success: true,
			message: `${type.toUpperCase()} simulation (${direction}) completed successfully`,
			config: envVars,
		};
	} catch (error) {
		console.error('Error running simulation:', error);
		return {
			success: false,
			message: error instanceof Error ? error.message : 'Unknown error occurred',
			config: null,
		};
	}
}
