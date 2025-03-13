'use client';

import React, { useState } from 'react';

export default function DetectionConfig() {
	const [signatureThreshold, setSignatureThreshold] = useState(0.7);
	const [specificationStrictness, setSpecificationStrictness] = useState(0.8);
	const [rateLimitRequests, setRateLimitRequests] = useState(100);
	const [rateLimitWindow, setRateLimitWindow] = useState(60);
	const [saveStatus, setSaveStatus] = useState<'idle' | 'saving' | 'success' | 'error'>('idle');

	const handleSave = async () => {
		setSaveStatus('saving');

		// Simulate saving configuration
		setTimeout(() => {
			setSaveStatus('success');

			// Reset status after 3 seconds
			setTimeout(() => {
				setSaveStatus('idle');
			}, 3000);
		}, 1000);
	};

	return (
		<div className='space-y-6'>
			<div className='bg-white dark:bg-gray-800 p-6 rounded-lg shadow'>
				<h2 className='text-xl font-semibold mb-6'>Detection Configuration</h2>

				<div className='space-y-6'>
					<div>
						<h3 className='text-lg font-medium mb-4'>Signature-based Detection</h3>
						<div className='space-y-4'>
							<div>
								<label className='block text-sm font-medium mb-1'>Detection Threshold</label>
								<div className='flex items-center space-x-4'>
									<input
										type='range'
										min='0'
										max='1'
										step='0.1'
										value={signatureThreshold}
										onChange={(e) => setSignatureThreshold(parseFloat(e.target.value))}
										className='w-full'
									/>
									<span className='text-sm font-medium'>{signatureThreshold}</span>
								</div>
								<p className='text-sm text-muted-foreground mt-1'>
									Higher values increase precision but may miss some attacks
								</p>
							</div>
						</div>
					</div>

					<div className='border-t pt-6'>
						<h3 className='text-lg font-medium mb-4'>Specification-based Detection</h3>
						<div className='space-y-4'>
							<div>
								<label className='block text-sm font-medium mb-1'>Schema Strictness</label>
								<div className='flex items-center space-x-4'>
									<input
										type='range'
										min='0'
										max='1'
										step='0.1'
										value={specificationStrictness}
										onChange={(e) => setSpecificationStrictness(parseFloat(e.target.value))}
										className='w-full'
									/>
									<span className='text-sm font-medium'>{specificationStrictness}</span>
								</div>
								<p className='text-sm text-muted-foreground mt-1'>Controls how strictly the API schema is enforced</p>
							</div>
						</div>
					</div>

					<div className='border-t pt-6'>
						<h3 className='text-lg font-medium mb-4'>Rate Limiting</h3>
						<div className='grid grid-cols-1 md:grid-cols-2 gap-4'>
							<div>
								<label className='block text-sm font-medium mb-1'>Max Requests</label>
								<input
									type='number'
									min='1'
									value={rateLimitRequests}
									onChange={(e) => setRateLimitRequests(parseInt(e.target.value))}
									className='w-full px-3 py-2 border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500'
								/>
								<p className='text-sm text-muted-foreground mt-1'>Maximum number of requests allowed</p>
							</div>

							<div>
								<label className='block text-sm font-medium mb-1'>Time Window (seconds)</label>
								<input
									type='number'
									min='1'
									value={rateLimitWindow}
									onChange={(e) => setRateLimitWindow(parseInt(e.target.value))}
									className='w-full px-3 py-2 border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500'
								/>
								<p className='text-sm text-muted-foreground mt-1'>Time window for rate limiting in seconds</p>
							</div>
						</div>
					</div>
				</div>

				<div className='mt-8 flex items-center space-x-4'>
					<button
						onClick={handleSave}
						disabled={saveStatus === 'saving'}
						className='px-4 py-2 bg-blue-500 text-white rounded-md hover:bg-blue-600 focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50'>
						{saveStatus === 'saving' ? 'Saving...' : 'Save Configuration'}
					</button>

					{saveStatus === 'success' && (
						<span className='text-green-600 dark:text-green-400'>Configuration saved successfully!</span>
					)}

					{saveStatus === 'error' && (
						<span className='text-red-600 dark:text-red-400'>Failed to save configuration.</span>
					)}
				</div>
			</div>

			<div className='bg-white dark:bg-gray-800 p-6 rounded-lg shadow'>
				<h3 className='text-lg font-medium mb-4'>Advanced Settings</h3>
				<p className='text-muted-foreground mb-4'>
					These settings are currently managed through configuration files. For advanced customization, please edit the
					detection scripts directly.
				</p>

				<div className='bg-gray-100 dark:bg-gray-900 p-4 rounded'>
					<code className='text-sm'>
						# Location of detection scripts
						<br />
						/scripts/detectionSignature.ts
						<br />
						/scripts/detectionSpecification.ts
						<br />
						/scripts/detectionHybrid.ts
						<br />
						/scripts/rateLimitAll.ts
					</code>
				</div>
			</div>
		</div>
	);
}
