import { NextResponse } from 'next/server';
import { exec } from 'child_process';
import { promisify } from 'util';

// Convert exec to use promises
const execPromise = promisify(exec);

// Define types
type Direction = 'anya-to-bond' | 'bond-to-anya';
type SimulationType = 'normal' | 'attack';

type ConfigVars = {
	ANYA_ORG_CODE: string;
	BOND_ORG_CODE: string;
	CA_CODE: string;
	BOND_BANK_API: string;
	ANYA_ORG_SERIAL_CODE: string;
	ANYA_CLIENT_ID: string;
	ANYA_CLIENT_SECRET: string;
	ITERATIONS?: string; // Optional iterations parameter
	[key: string]: string | undefined; // Allow for additional environment variables
};

type DefaultConfig = {
	[key in Direction]: ConfigVars;
};

// Define default configurations
const defaultConfig: DefaultConfig = {
	'anya-to-bond': {
		ANYA_ORG_CODE: 'anyabank00',
		BOND_ORG_CODE: 'bondbank00',
		CA_CODE: 'certauth00',
		BOND_BANK_API: 'http://localhost:3001',
		ANYA_ORG_SERIAL_CODE: 'anyaserial00',
		ANYA_CLIENT_ID: 'client_anyabank00',
		ANYA_CLIENT_SECRET: 'secret_anyabank00',
	},
	'bond-to-anya': {
		ANYA_ORG_CODE: 'bondbank00',
		BOND_ORG_CODE: 'anyabank00',
		CA_CODE: 'certauth00',
		BOND_BANK_API: 'http://localhost:3000',
		ANYA_ORG_SERIAL_CODE: 'bondserial00',
		ANYA_CLIENT_ID: 'client_bondbank00',
		ANYA_CLIENT_SECRET: 'secret_bondbank00',
	},
};

export async function POST(req: Request) {
	try {
		const { type, direction, config, iterations } = (await req.json()) as {
			type?: SimulationType;
			direction?: Direction;
			config?: ConfigVars;
			iterations?: number;
		};

		// Validate input
		if (!type || !['normal', 'attack'].includes(type)) {
			return NextResponse.json({ message: 'Invalid simulation type. Must be "normal" or "attack".' }, { status: 400 });
		}

		if (!direction || !['anya-to-bond', 'bond-to-anya'].includes(direction)) {
			return NextResponse.json(
				{ message: 'Invalid direction. Must be "anya-to-bond" or "bond-to-anya".' },
				{ status: 400 }
			);
		}

		// Use custom config if provided, otherwise use default
		let envVars: ConfigVars = config || defaultConfig[direction];

		// Add iterations if provided but not already in config
		if (iterations && !envVars.ITERATIONS) {
			envVars.ITERATIONS = iterations.toString();
		}

		// Validate required environment variables
		const requiredVars = [
			'ANYA_ORG_CODE',
			'BOND_ORG_CODE',
			'CA_CODE',
			'BOND_BANK_API',
			'ANYA_ORG_SERIAL_CODE',
			'ANYA_CLIENT_ID',
			'ANYA_CLIENT_SECRET',
		] as const;

		for (const varName of requiredVars) {
			if (!envVars[varName]) {
				return NextResponse.json({ message: `Missing required configuration variable: ${varName}` }, { status: 400 });
			}
		}

		// Construct environment variables string with custom or default values
		const envString = Object.entries(envVars)
			.filter(([_, value]) => value !== undefined) // Filter out undefined values
			.map(([key, value]) => `${key}=${value}`)
			.join(' ');

		// Determine which script to run
		const scriptPath = type === 'normal' ? 'scripts/simulations/simulate.ts' : 'scripts/simulations/simulateV2.ts';

		// Run the script with environment variables
		const command = `cd ${process.cwd()} && ${envString} npx ts-node ${scriptPath}`;

		console.log(`Running simulation with command: ${command}`);

		// Execute the script
		const { stdout, stderr } = await execPromise(command);

		if (stderr) {
			console.error('Simulation stderr:', stderr);
		}

		return NextResponse.json({
			message: `${type.toUpperCase()} simulation (${direction}) completed successfully`,
			logs: stdout.split('\n').filter(Boolean),
			config: envVars, // Return the used configuration for reference
		});
	} catch (error) {
		console.error('Error running simulation:', error);
		return NextResponse.json({ message: 'Failed to run simulation', error: (error as Error).message }, { status: 500 });
	}
}
