'use client';

import React, { useState } from 'react';
import {
	runSignatureDetection,
	runSpecificationDetection,
	runHybridDetection,
	runAnalysis,
	runRateLimitDetection,
	DetectionResult,
} from '../_actions/security-actions';

export default function DetectionRuns() {
	const [loading, setLoading] = useState<string | null>(null);
	const [result, setResult] = useState<DetectionResult | null>(null);
	const [output, setOutput] = useState<string>('');

	const handleRun = async (
		type: 'signature' | 'specification' | 'hybrid' | 'analysis' | 'ratelimit',
		action: () => Promise<DetectionResult>
	) => {
		setLoading(type);
		setResult(null);
		setOutput('');

		try {
			const result = await action();

			console.log('result', result);
			setResult(result);
			setOutput(result.data || '');
		} catch (error) {
			// console.error(`Error running ${type} detection:`, error);
			// setResult({
			// 	success: false,
			// 	message: `Failed to run ${type} detection`,
			// 	error: error instanceof Error ? error.message : String(error),
			// });
		} finally {
			setLoading(null);
		}
	};

	return (
		<div className='space-y-6'>
			<div className='bg-white dark:bg-gray-800 p-6 rounded-lg shadow'>
				<h2 className='text-xl font-semibold mb-4'>Run Detection Scripts</h2>
				<p className='text-muted-foreground mb-6'>
					Execute different detection methods to identify potential security threats in your API logs.
				</p>

				<div className='grid grid-cols-1 md:grid-cols-3 gap-4 mb-6'>
					<button
						onClick={() => handleRun('signature', runSignatureDetection)}
						disabled={loading !== null}
						className={`p-4 rounded-lg border ${
							loading === 'signature'
								? 'bg-blue-100 border-blue-300 dark:bg-blue-900 dark:border-blue-700'
								: 'hover:bg-gray-100 dark:hover:bg-gray-700'
						} transition-colors`}>
						<h3 className='font-medium'>Signature-based Detection</h3>
						<p className='text-sm text-muted-foreground mt-1'>Pattern matching against known attack signatures</p>
						{loading === 'signature' && <div className='mt-2 text-blue-600 dark:text-blue-400'>Running...</div>}
					</button>

					<button
						onClick={() => handleRun('specification', runSpecificationDetection)}
						disabled={loading !== null}
						className={`p-4 rounded-lg border ${
							loading === 'specification'
								? 'bg-blue-100 border-blue-300 dark:bg-blue-900 dark:border-blue-700'
								: 'hover:bg-gray-100 dark:hover:bg-gray-700'
						} transition-colors`}>
						<h3 className='font-medium'>Specification-based Detection</h3>
						<p className='text-sm text-muted-foreground mt-1'>Validates requests against API specifications</p>
						{loading === 'specification' && <div className='mt-2 text-blue-600 dark:text-blue-400'>Running...</div>}
					</button>

					<button
						onClick={() => handleRun('hybrid', runHybridDetection)}
						disabled={loading !== null}
						className={`p-4 rounded-lg border ${
							loading === 'hybrid'
								? 'bg-blue-100 border-blue-300 dark:bg-blue-900 dark:border-blue-700'
								: 'hover:bg-gray-100 dark:hover:bg-gray-700'
						} transition-colors`}>
						<h3 className='font-medium'>Hybrid Detection</h3>
						<p className='text-sm text-muted-foreground mt-1'>Combined approach for maximum coverage</p>
						{loading === 'hybrid' && <div className='mt-2 text-blue-600 dark:text-blue-400'>Running...</div>}
					</button>
				</div>

				<div className='grid grid-cols-1 md:grid-cols-2 gap-4'>
					<button
						onClick={() => handleRun('analysis', runAnalysis)}
						disabled={loading !== null}
						className={`p-4 rounded-lg border ${
							loading === 'analysis'
								? 'bg-blue-100 border-blue-300 dark:bg-blue-900 dark:border-blue-700'
								: 'hover:bg-gray-100 dark:hover:bg-gray-700'
						} transition-colors`}>
						<h3 className='font-medium'>Run Analysis</h3>
						<p className='text-sm text-muted-foreground mt-1'>Analyze detection performance and metrics</p>
						{loading === 'analysis' && <div className='mt-2 text-blue-600 dark:text-blue-400'>Running...</div>}
					</button>

					<button
						onClick={() => handleRun('ratelimit', runRateLimitDetection)}
						disabled={loading !== null}
						className={`p-4 rounded-lg border ${
							loading === 'ratelimit'
								? 'bg-blue-100 border-blue-300 dark:bg-blue-900 dark:border-blue-700'
								: 'hover:bg-gray-100 dark:hover:bg-gray-700'
						} transition-colors`}>
						<h3 className='font-medium'>Rate Limit Detection</h3>
						<p className='text-sm text-muted-foreground mt-1'>Identify potential rate limit violations</p>
						{loading === 'ratelimit' && <div className='mt-2 text-blue-600 dark:text-blue-400'>Running...</div>}
					</button>
				</div>
			</div>

			{result && (
				<div
					className={`bg-white dark:bg-gray-800 p-6 rounded-lg shadow border-l-4 ${
						result.success ? 'border-green-500' : 'border-red-500'
					}`}>
					<h3 className='text-lg font-medium mb-2'>{result.success ? 'Success' : 'Error'}</h3>
					<p className='mb-4'>{result.message}</p>
					{result.error && (
						<div className='bg-red-50 dark:bg-red-900/20 p-4 rounded mb-4 text-red-800 dark:text-red-300'>
							{result.error}
						</div>
					)}
				</div>
			)}

			{output && (
				<div className='bg-white dark:bg-gray-800 p-6 rounded-lg shadow'>
					<h3 className='text-lg font-medium mb-2'>Output</h3>
					<pre className='bg-gray-100 dark:bg-gray-900 p-4 rounded overflow-auto max-h-96 text-sm'>{output}</pre>
				</div>
			)}
		</div>
	);
}
