'use client';

import React, { useState, useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { AlertCircle, CheckCircle, Play, Pause, ChevronDown, ChevronUp, Loader, Trash, FolderOpen } from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import {
	runSimulation,
	togglePauseSimulation,
	stopSimulation,
	getSimulationStatus,
	deleteCSVFiles,
	getCSVFolderPath,
	getVariables,
	type ConfigVars,
	type Direction,
} from '@/app/_actions/simulation-actions';

export default function SimulationsTab() {
	const [direction, setDirection] = useState<Direction>('anya-to-bond');
	const [isRunning, setIsRunning] = useState(false);
	const [isPaused, setIsPaused] = useState(false);
	const [status, setStatus] = useState<null | { type: 'success' | 'error'; message: string }>(null);
	const [logs, setLogs] = useState<string[]>([]);
	const [showConfig, setShowConfig] = useState(false);
	const [iterations, setIterations] = useState(5); // Default number of iterations
	const [progress, setProgress] = useState({ current: 0, total: 0 });
	const [isClient, setIsClient] = useState(false);

	useEffect(() => {
		setIsClient(true);
	}, []);

	// Default configuration values
	const [config, setConfig] = useState<ConfigVars>({
		otherBankAPI: '',
		otherOrgCode: '',
		orgCode: '',
		orgSerialCode: '',
		clientId: '',
		clientSecret: '',
	});

	// Load initial config
	useEffect(() => {
		const loadConfig = async () => {
			try {
				const initialConfig = await getVariables(direction);
				setConfig(initialConfig);
			} catch (error) {
				console.error('Error loading initial config:', error);
			}
		};

		loadConfig();
	}, []);

	// Update config when direction changes
	useEffect(() => {
		const updateConfig = async () => {
			try {
				if (isClient) {
					const newConfig = await getVariables(direction);
					setConfig(newConfig);
				}
			} catch (error) {
				console.error('Error updating config:', error);
			}
		};

		updateConfig();
	}, [direction, isClient]);

	// Poll for simulation status when running
	useEffect(() => {
		let interval: NodeJS.Timeout;

		if (isRunning && isClient) {
			interval = setInterval(async () => {
				try {
					const status = await getSimulationStatus();
					setIsPaused(status.isPaused);
					setProgress({
						current: status.currentIteration,
						total: status.totalIterations,
					});

					// Update isRunning based on status
					if (!status.isRunning && progress.current === progress.total) {
						setIsRunning(false);
						clearInterval(interval);
					}
				} catch (error) {
					console.error('Error fetching simulation status:', error);
				}
			}, 1000);
		}

		return () => {
			if (interval) clearInterval(interval);
		};
	}, [isRunning, progress.current, progress.total, isClient]);

	// Handle config field changes
	const handleConfigChange = (key: string, value: string) => {
		setConfig((prev) => ({
			...prev,
			[key]: value,
		}));
	};

	// Reset config to defaults
	const resetConfig = async () => {
		try {
			const defaultConfig = await getVariables(direction);
			setConfig(defaultConfig);
		} catch (error) {
			console.error('Error resetting config:', error);
		}
	};

	// Toggle pause state
	const handlePauseToggle = async () => {
		try {
			const result = await togglePauseSimulation();
			setIsPaused(result.isPaused);
			setLogs((prev) => [
				...prev,
				`Simulation ${result.isPaused ? 'paused' : 'resumed'} at iteration ${result.currentIteration}/${
					result.totalIterations
				}`,
			]);
		} catch (error) {
			console.error('Error toggling pause state:', error);
		}
	};

	// Stop simulation
	const handleStopSimulation = async () => {
		try {
			const result = await stopSimulation();
			setIsRunning(false);
			setIsPaused(false);
			setLogs((prev) => [
				...prev,
				`Simulation stopped at iteration ${result.finalIteration}/${result.totalIterations}`,
			]);
			setStatus({
				type: 'success',
				message: result.message,
			});
		} catch (error) {
			console.error('Error stopping simulation:', error);
			setStatus({
				type: 'error',
				message: error instanceof Error ? error.message : 'Unknown error occurred',
			});
		}
	};

	// Delete all log files
	const handleDeleteLogs = async () => {
		try {
			const result = await deleteCSVFiles();
			if (result.success) {
				// Log each deleted file individually
				if (result.results && result.results.length > 0) {
					setLogs((prev) => [
						...prev,
						`Log files deleted: ${result.message}`,
						...result.results.map((r) => `  - ${r}`),
					]);
				} else {
					setLogs((prev) => [...prev, `Log files deleted: ${result.message}`]);
				}

				setStatus({
					type: 'success',
					message: result.message,
				});
			} else {
				setLogs((prev) => [...prev, `Error deleting log files: ${result.message}`]);
				setStatus({
					type: 'error',
					message: `Error deleting log files: ${result.message}`,
				});
			}
		} catch (error) {
			console.error('Error deleting log files:', error);
			setStatus({
				type: 'error',
				message: error instanceof Error ? error.message : 'Unknown error occurred',
			});
		}
	};

	// Open CSV folder
	const handleOpenFolder = async () => {
		try {
			const result = await getCSVFolderPath();
			if (result.success) {
				// Instead of trying to open the folder directly (which is blocked by browsers),
				// show the path to the user and add it to logs
				setStatus({
					type: 'success',
					message: `CSV folder path: ${result.path}`,
				});
				setLogs((prev) => [...prev, `CSV folder location: ${result.path}`]);

				// Copy path to clipboard for convenience
				navigator.clipboard
					.writeText(result.path)
					.then(() => {
						setLogs((prev) => [...prev, `Path copied to clipboard`]);
					})
					.catch((err) => {
						console.error('Failed to copy path to clipboard:', err);
					});
			}
		} catch (error) {
			console.error('Error getting folder path:', error);
			setStatus({
				type: 'error',
				message: error instanceof Error ? error.message : 'Unknown error occurred',
			});
		}
	};

	const runSimulationHandler = async (type: 'normal' | 'attack' | 'attack-invalid-flow') => {
		try {
			// Reset state
			setIsRunning(true);
			setIsPaused(false);
			setStatus(null);
			setLogs([]);
			setProgress({ current: 0, total: iterations });

			// Add initial log
			const directionText = direction === 'anya-to-bond' ? 'Anya Bank to Bond Bank' : 'Bond Bank to Anya Bank';
			setLogs((prev) => [...prev, `Starting ${type} simulation (${directionText}) with ${iterations} iterations...`]);

			// Create a copy of the config and add iterations
			const runConfig = {
				...config,
				ITERATIONS: iterations.toString(),
			};

			// Run the simulation using the server action
			const result = await runSimulation({
				type,
				direction,
				config: runConfig,
				iterations,
			});

			// Success
			setStatus({
				type: 'success',
				message: result?.message || '',
			});

			// Add completion log
			setLogs((prev) => [...prev, `Simulation completed successfully`]);
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
			setIsPaused(false);
		}
	};

	// Emergency stop for simulation
	const handleEmergencyStop = async () => {
		try {
			const result = await stopSimulation();
			setIsRunning(false);
			setIsPaused(false);
			setProgress({ current: 0, total: 0 });

			if (result.wasRunning) {
				setLogs((prev) => [
					...prev,
					`Emergency stop activated: Simulation terminated at iteration ${result.finalIteration}/${result.totalIterations}`,
				]);
				setStatus({
					type: 'success',
					message: result.message,
				});
			} else {
				setLogs((prev) => [...prev, 'Emergency stop activated: No simulation was running']);
				setStatus({
					type: 'success',
					message: 'No simulation was running',
				});
			}
		} catch (error) {
			console.error('Error stopping simulation:', error);
			setStatus({
				type: 'error',
				message: error instanceof Error ? error.message : 'Unknown error occurred',
			});
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
									onChange={(e) => setDirection(e.target.value as Direction)}
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
									onChange={(e) => setDirection(e.target.value as Direction)}
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
								min='0'
								max='10000'
								step='5'
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
						<div className='flex flex-wrap gap-4'>
							<Button
								onClick={() => runSimulationHandler('normal')}
								disabled={isRunning || iterations === 0}
								className='flex items-center space-x-2'>
								{isRunning && !isPaused ? <Loader className='h-4 w-4 animate-spin' /> : <Play size={16} />}
								<span>Run Normal Simulation</span>
							</Button>

							<Button
								onClick={() => runSimulationHandler('attack')}
								disabled={isRunning || iterations === 0}
								variant='destructive'
								className='flex items-center space-x-2'>
								{isRunning && !isPaused ? <Loader className='h-4 w-4 animate-spin' /> : <Play size={16} />}
								<span>Run Attack Simulation</span>
							</Button>

							<Button
								onClick={() => runSimulationHandler('attack-invalid-flow')}
								disabled={isRunning || iterations === 0}
								variant='destructive'
								className='flex items-center space-x-2'>
								{isRunning && !isPaused ? <Loader className='h-4 w-4 animate-spin' /> : <Play size={16} />}
								<span>Run Attack Invalid Flow Simulation</span>
							</Button>

							{/* Pause/Resume Button */}
							{isRunning && (
								<Button
									onClick={handlePauseToggle}
									variant='outline'
									className='flex items-center space-x-2'>
									{isPaused ? <Play size={16} /> : <Pause size={16} />}
									<span>{isPaused ? 'Resume' : 'Pause'}</span>
								</Button>
							)}

							{/* Stop Button */}
							{isRunning && (
								<Button
									onClick={handleStopSimulation}
									variant='destructive'
									className='flex items-center space-x-2'>
									<AlertCircle size={16} />
									<span>Stop</span>
								</Button>
							)}

							{/* Emergency Stop Button - always visible */}
							<Button
								onClick={handleEmergencyStop}
								variant='destructive'
								className='ml-auto flex items-center space-x-2 bg-red-600 hover:bg-red-700'>
								<AlertCircle size={16} />
								<span>Emergency Stop</span>
							</Button>
						</div>
					</div>

					{/* Logs Management */}
					<div>
						<h3 className='text-lg font-medium mb-4'>Logs Management</h3>
						<div className='flex flex-wrap gap-4'>
							<Button
								onClick={handleDeleteLogs}
								variant='outline'
								disabled={isRunning}
								className='flex items-center space-x-2'>
								<Trash size={16} />
								<span>Delete All Logs</span>
							</Button>

							<Button
								onClick={handleOpenFolder}
								variant='outline'
								className='flex items-center space-x-2'>
								<FolderOpen size={16} />
								<span>Show CSV Folder Path</span>
							</Button>
						</div>
					</div>

					{/* Progress indicator */}
					{isRunning && (
						<div className='mt-4'>
							<h4 className='text-sm font-medium mb-2'>Progress</h4>
							<div className='w-full bg-gray-200 rounded-full h-2.5 dark:bg-gray-700'>
								<div
									className='bg-primary h-2.5 rounded-full'
									style={{ width: `${(progress.current / progress.total) * 100}%` }}></div>
							</div>
							<div className='text-sm text-right mt-1'>
								{progress.current} / {progress.total} iterations {isPaused ? '(Paused)' : ''}
							</div>
						</div>
					)}

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
										{isPaused ? <Pause className='h-3 w-3 mr-1' /> : <Loader className='h-3 w-3 animate-spin mr-1' />}
										{isPaused ? 'Paused' : 'Running'}
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
							{isRunning && !isPaused && <div className='animate-pulse'>Running simulation...</div>}
							{isRunning && isPaused && <div>Simulation paused. Click resume to continue.</div>}
						</div>
					</CardContent>
				</Card>
			)}
		</div>
	);
}
