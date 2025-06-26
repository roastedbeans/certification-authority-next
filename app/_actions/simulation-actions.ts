'use server';

import { runIterations } from '@/scripts/simulations/simulate';
import { runAttackIterations } from '@/scripts/simulations/simulateV2';
import { runIterations as runIterationsInvalidFlow } from '@/scripts/simulations/simulate-invalid-flow-v3';
import fs from 'fs';
import path from 'path';

export type Direction = 'anya-to-bond' | 'bond-to-anya';
export type SimulationType = 'normal' | 'attack' | 'attack-invalid-flow';

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

// Global state to track simulation status
let isSimulationRunning = false;
let isSimulationPaused = false;
let currentIteration = 0;
let totalIterations = 0;
let abortController: AbortController | null = null;

// Server function to get variables
export async function getVariables(direction: Direction): Promise<ConfigVars> {
	return variables[direction];
}

// Function to toggle pause state
export async function togglePauseSimulation() {
	isSimulationPaused = !isSimulationPaused;
	return {
		success: true,
		isPaused: isSimulationPaused,
		currentIteration,
		totalIterations,
	};
}

// Function to stop simulation
export async function stopSimulation() {
	// Set a flag to indicate we're forcing termination
	const wasRunning = isSimulationRunning;

	// Reset all state immediately
	isSimulationRunning = false;
	isSimulationPaused = false;

	// Abort any in-progress operation
	if (abortController) {
		abortController.abort();
		abortController = null;
	}

	// Record final iteration number before resetting
	const finalIteration = currentIteration;
	currentIteration = 0;

	// Return detailed information about what was stopped
	return {
		success: true,
		message: wasRunning
			? `Simulation stopped at iteration ${finalIteration}/${totalIterations}`
			: 'No simulation was running',
		wasRunning,
		finalIteration,
		totalIterations,
	};
}

// Function to get simulation status
export async function getSimulationStatus() {
	return {
		isRunning: isSimulationRunning,
		isPaused: isSimulationPaused,
		currentIteration,
		totalIterations,
	};
}

// Function to delete CSV files
export async function deleteCSVFiles() {
	try {
		const publicDir = path.join(process.cwd(), 'public');
		const filesToDelete = [
			'ca_formatted_logs.csv',
			'hybrid_detection_logs.csv',
			'signature_detection_logs.csv',
			'specification_detection_logs.csv',
		];

		let deletedCount = 0;
		const results = [];

		for (const file of filesToDelete) {
			const filePath = path.join(publicDir, file);
			if (fs.existsSync(filePath)) {
				fs.unlinkSync(filePath);
				deletedCount++;
				results.push(`Deleted ${file}`);
			}
		}

		return {
			success: true,
			message: deletedCount > 0 ? `${deletedCount} log files deleted successfully` : 'No log files found to delete',
			results,
		};
	} catch (error) {
		console.error('Error deleting log files:', error);
		return {
			success: false,
			message: error instanceof Error ? error.message : 'Unknown error occurred',
		};
	}
}

// Function to get CSV folder path
export async function getCSVFolderPath() {
	const publicDir = path.resolve(process.cwd(), 'public');
	return {
		success: true,
		path: publicDir,
	};
}

export async function runSimulation(params: {
	type: SimulationType;
	direction: Direction;
	config?: ConfigVars;
	iterations?: number;
}) {
	try {
		const { type, direction, config, iterations = 5 } = params;

		// Prevent multiple simulations from running at once
		if (isSimulationRunning) {
			return {
				success: false,
				message: 'A simulation is already running',
				config: null,
			};
		}

		// Reset state
		isSimulationRunning = true;
		isSimulationPaused = false;
		currentIteration = 0;
		totalIterations = iterations;
		abortController = new AbortController();

		// Use custom config if provided, otherwise use default
		const envVars = config || variables[direction];

		console.log('Running simulation', type, direction, envVars);

		// Create a wrapped version of runIterations that respects pause and abort
		const runWithPauseSupport = async () => {
			// Custom implementation to handle pausing
			const runSingleIteration = async () => {
				if (type === 'normal') {
					try {
						// Run a single normal iteration by calling the runIterations function with iterations=1
						await runIterations(
							1, // Just run one iteration
							envVars.orgCode,
							envVars.clientId,
							envVars.clientSecret,
							envVars.otherOrgCode,
							envVars.otherBankAPI
						);
					} catch (error) {
						console.error('Error running normal iteration:', error);
						throw error;
					}
				} else if (type === 'attack') {
					try {
						// Run a single attack iteration by calling the runAttackIterations function with iterations=1
						await runAttackIterations(
							1, // Just run one iteration
							envVars.orgCode,
							envVars.clientId,
							envVars.clientSecret,
							envVars.otherOrgCode,
							envVars.otherBankAPI
						);
					} catch (error) {
						console.error('Error running attack iteration:', error);
						throw error;
					}
				} else if (type === 'attack-invalid-flow') {
					try {
						// Run a single attack invalid flow iteration by calling the runAttackSimulations function with iterations=1
						await runIterationsInvalidFlow(
							1,
							envVars.orgCode,
							envVars.clientId,
							envVars.clientSecret,
							envVars.otherOrgCode,
							envVars.otherBankAPI
						);
					} catch (error) {
						console.error('Error running attack invalid flow iteration:', error);
						throw error;
					}
				}
			};

			for (let i = 0; i < iterations; i++) {
				// Check if simulation should be aborted
				if (abortController?.signal.aborted) {
					break;
				}

				// Check if simulation is paused
				while (isSimulationPaused && !abortController?.signal.aborted) {
					await new Promise((resolve) => setTimeout(resolve, 1000)); // Check every second
				}

				// Check again after pausing in case simulation was aborted during pause
				if (abortController?.signal.aborted) {
					break;
				}

				// Run one iteration
				try {
					await runSingleIteration();
					currentIteration = i + 1;
					console.log(`Iteration ${i + 1}/${iterations} completed.`);
				} catch (error) {
					console.error(`Error in iteration ${i + 1}:`, error);
				}

				// Add a delay between iterations
				await new Promise((resolve) => setTimeout(resolve, 1000));
			}
		};

		// Run the simulation with pause support
		await runWithPauseSupport();

		// Reset state when complete
		isSimulationRunning = false;
		isSimulationPaused = false;
		currentIteration = 0;
		abortController = null;

		return {
			success: true,
			message: `${type.toUpperCase()} simulation (${direction}) completed successfully`,
			config: envVars,
		};
	} catch (error) {
		console.error('Error running simulation:', error);
		// Reset state on error
		isSimulationRunning = false;
		isSimulationPaused = false;
		currentIteration = 0;
		abortController = null;

		return {
			success: false,
			message: error instanceof Error ? error.message : 'Unknown error occurred',
			config: null,
		};
	}
}
