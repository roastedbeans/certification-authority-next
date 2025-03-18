'use client';

import React, { useState } from 'react';
import { Button } from '@/components/ui/button';
import { AlertCircle, CheckCircle, Play, ChevronDown, ChevronUp, Loader } from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';

export default function SimulationsTab() {
	const [direction, setDirection] = useState('anya-to-bond');
	const [isRunning, setIsRunning] = useState(false);
	const [status, setStatus] = useState<null | { type: 'success' | 'error'; message: string }>(null);
	const [logs, setLogs] = useState<string[]>([]);
	const [showConfig, setShowConfig] = useState(false);
	const [iterations, setIterations] = useState(5); // Default number of iterations

	// Default configuration values
	const defaultConfig = {
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

	// State for custom configuration
	const [config, setConfig] = useState(defaultConfig['anya-to-bond']);

	// Update config when direction changes
	React.useEffect(() => {
		setConfig(defaultConfig[direction as keyof typeof defaultConfig]);
	}, [direction]);

	// Handle config field changes
	const handleConfigChange = (key: string, value: string) => {
		setConfig((prev) => ({
			...prev,
			[key]: value,
		}));
	};

	// Reset config to defaults
	const resetConfig = () => {
		setConfig(defaultConfig[direction as keyof typeof defaultConfig]);
	};

	const runSimulation = async (type: 'normal' | 'attack') => {
		try {
			// Reset state
			setIsRunning(true);
			setStatus(null);
			setLogs([]);

			// Add initial log
			const directionText = direction === 'anya-to-bond' ? 'Anya Bank to Bond Bank' : 'Bond Bank to Anya Bank';

			setLogs((prev) => [...prev, `Starting ${type} simulation (${directionText}) with ${iterations} iterations...`]);

			// Create a copy of the config and add iterations
			const runConfig = {
				...config,
				ITERATIONS: iterations.toString(),
			};

			// Call the API to run the simulation
			const response = await fetch('/api/simulations/run', {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
				},
				body: JSON.stringify({
					type,
					direction,
					config: runConfig,
					iterations,
				}),
			});

			if (!response.ok) {
				const errorData = await response.json();
				throw new Error(errorData.message || 'Failed to run simulation');
			}

			const data = await response.json();

			// Success
			setStatus({
				type: 'success',
				message: `${type.charAt(0).toUpperCase() + type.slice(1)} simulation completed successfully!`,
			});

			// Add completion log
			setLogs((prev) => [...prev, `Simulation completed successfully`]);

			// Add any logs from the server response if available
			if (data.logs && Array.isArray(data.logs)) {
				setLogs((prev) => [...prev, ...data.logs]);
			}
		} catch (error) {
			console.error('Simulation error:', error);
			setStatus({
				type: 'error',
				message: error instanceof Error ? error.message : 'Unknown error occurred',
			});

			// Add error log
			setLogs((prev) => [...prev, `Error: ${error instanceof Error ? error.message : 'Unknown error occurred'}`]);
		} finally {
			setIsRunning(false);
		}
	};

	return (
		<div className='space-y-6'>
			<Card>
				<CardHeader>
					<CardTitle>Simulation Controls</CardTitle>
					<CardDescription>
						Run simulations to test the system behavior under normal and attack conditions
					</CardDescription>
				</CardHeader>
				<CardContent className='space-y-6'>
					<div>
						<h3 className='text-lg font-medium mb-2'>Select Direction</h3>
						<div className='flex flex-col space-y-2'>
							<div className='flex items-center space-x-2'>
								<input
									type='radio'
									name='direction'
									value='anya-to-bond'
									id='anya-to-bond'
									checked={direction === 'anya-to-bond'}
									onChange={(e) => setDirection(e.target.value)}
									className='h-4 w-4 text-primary border-gray-300 focus:ring-primary'
									disabled={isRunning}
								/>
								<label htmlFor='anya-to-bond'>Anya Bank requests to Bond Bank</label>
							</div>
							<div className='flex items-center space-x-2'>
								<input
									type='radio'
									name='direction'
									value='bond-to-anya'
									id='bond-to-anya'
									checked={direction === 'bond-to-anya'}
									onChange={(e) => setDirection(e.target.value)}
									className='h-4 w-4 text-primary border-gray-300 focus:ring-primary'
									disabled={isRunning}
								/>
								<label htmlFor='bond-to-anya'>Bond Bank requests to Anya Bank</label>
							</div>
						</div>
					</div>

					<div>
						<h3 className='text-lg font-medium mb-2'>Iterations</h3>
						<div className='flex items-center space-x-4'>
							<input
								type='range'
								min='1'
								max='100'
								value={iterations}
								onChange={(e) => setIterations(parseInt(e.target.value))}
								className='w-full h-2 bg-gray-200 rounded-lg appearance-none cursor-pointer dark:bg-gray-700'
								disabled={isRunning}
							/>
							<div className='w-16 px-2 py-1 text-center border border-gray-300 rounded dark:border-gray-600'>
								{iterations}
							</div>
						</div>
					</div>

					<hr className='my-4 border-t border-gray-200 dark:border-gray-700' />

					{/* Advanced Configuration Section */}
					<div>
						<button
							type='button'
							onClick={() => setShowConfig(!showConfig)}
							className='flex items-center justify-between w-full text-left text-lg font-medium mb-2'
							disabled={isRunning}>
							<span>Advanced Configuration</span>
							{showConfig ? <ChevronUp size={20} /> : <ChevronDown size={20} />}
						</button>

						{showConfig && (
							<div className='bg-gray-50 dark:bg-gray-800 p-4 rounded-md mb-4'>
								<div className='grid grid-cols-1 md:grid-cols-2 gap-4'>
									{Object.entries(config).map(([key, value]) => (
										<div
											key={key}
											className='flex flex-col'>
											<label
												htmlFor={key}
												className='text-sm font-medium mb-1'>
												{key}
											</label>
											<input
												type='text'
												id={key}
												value={value}
												onChange={(e) => handleConfigChange(key, e.target.value)}
												className='px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md 
													focus:outline-none focus:ring-2 focus:ring-primary dark:bg-gray-700'
												disabled={isRunning}
											/>
										</div>
									))}
								</div>
								<div className='mt-4 flex justify-end'>
									<Button
										onClick={resetConfig}
										variant='outline'
										disabled={isRunning}
										className='text-sm'>
										Reset to Defaults
									</Button>
								</div>
							</div>
						)}
					</div>

					<div>
						<h3 className='text-lg font-medium mb-4'>Run Simulations</h3>
						<div className='flex space-x-4'>
							<Button
								onClick={() => runSimulation('normal')}
								disabled={isRunning}
								className='flex items-center space-x-2'>
								{isRunning ? <Loader className='h-4 w-4 animate-spin' /> : <Play size={16} />}
								<span>Run Normal Simulation</span>
							</Button>

							<Button
								onClick={() => runSimulation('attack')}
								disabled={isRunning}
								variant='destructive'
								className='flex items-center space-x-2'>
								{isRunning ? <Loader className='h-4 w-4 animate-spin' /> : <Play size={16} />}
								<span>Run Attack Simulation</span>
							</Button>
						</div>
					</div>

					{status && (
						<Alert variant={status.type === 'success' ? 'default' : 'destructive'}>
							{status.type === 'success' ? <CheckCircle className='h-4 w-4' /> : <AlertCircle className='h-4 w-4' />}
							<AlertTitle>{status.type === 'success' ? 'Success' : 'Error'}</AlertTitle>
							<AlertDescription>{status.message}</AlertDescription>
						</Alert>
					)}
				</CardContent>
			</Card>

			{logs.length > 0 && (
				<Card>
					<CardHeader>
						<CardTitle className='flex items-center justify-between'>
							Simulation Logs
							<span className='inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200 border border-gray-200 dark:border-gray-600'>
								{isRunning ? (
									<span className='flex items-center'>
										<Loader className='h-3 w-3 animate-spin mr-1' />
										Running
									</span>
								) : (
									'Completed'
								)}
							</span>
						</CardTitle>
					</CardHeader>
					<CardContent>
						<div className='bg-muted p-4 rounded-md max-h-60 overflow-y-auto font-mono text-sm'>
							{logs.map((log, index) => (
								<div
									key={index}
									className='py-1'>
									{log}
								</div>
							))}
							{isRunning && <div className='animate-pulse'>Running simulation...</div>}
						</div>
					</CardContent>
				</Card>
			)}
		</div>
	);
}
