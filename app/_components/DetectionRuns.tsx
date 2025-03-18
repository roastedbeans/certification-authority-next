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
import { DetectionSummary } from '@/scripts/analysis/runAnalysis';

export default function DetectionRuns() {
	const [loading, setLoading] = useState<string | null>(null);
	const [result, setResult] = useState<DetectionResult | null>(null);
	const [output, setOutput] = useState<string>('');
	const [analysisSummary, setAnalysisSummary] = useState<DetectionSummary | null>(null);

	const handleRun = async (type: string, action: () => Promise<any>) => {
		setLoading(type);
		setResult(null);
		setOutput('');

		try {
			const result = await action();

			console.log('result', result);
			setResult(result);

			if (type === 'analysis') {
				setAnalysisSummary(result.data);
				// Don't set output for analysis as it's a complex object
				setOutput('Analysis complete. See summary below.');
			} else {
				setOutput(result.data || '');
			}
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
			{analysisSummary && (
				<div className='bg-white dark:bg-gray-800 p-6 rounded-lg shadow'>
					<h3 className='text-lg font-medium mb-4'>Analysis Summary</h3>
					<div className='space-y-6'>
						{/* Overview Stats */}
						<div>
							<h4 className='text-md font-medium mb-2'>Detection Overview</h4>
							<div className='grid grid-cols-1 md:grid-cols-3 gap-4'>
								<div className='bg-gray-100 dark:bg-gray-900 p-4 rounded'>
									<p className='text-sm font-medium text-gray-500 dark:text-gray-400'>Total Attacks</p>
									<p className='text-2xl font-bold'>{analysisSummary.attackCount || 0}</p>
								</div>
								<div className='bg-gray-100 dark:bg-gray-900 p-4 rounded'>
									<p className='text-sm font-medium text-gray-500 dark:text-gray-400'>Missed Attacks</p>
									<p className='text-2xl font-bold'>{analysisSummary.missedAttacks || 0}</p>
								</div>
								<div className='bg-gray-100 dark:bg-gray-900 p-4 rounded'>
									<p className='text-sm font-medium text-gray-500 dark:text-gray-400'>Detection Rate</p>
									<p className='text-2xl font-bold'>
										{(analysisSummary.attackCount || 0) > 0
											? `${(
													(((analysisSummary.attackCount || 0) - (analysisSummary.missedAttacks || 0)) /
														(analysisSummary.attackCount || 1)) *
													100
											  ).toFixed(1)}%`
											: '0%'}
									</p>
								</div>
							</div>
						</div>

						{/* Detection Method Stats */}
						<div>
							<h4 className='text-md font-medium mb-2'>Detection Methods</h4>
							<div className='grid grid-cols-1 md:grid-cols-3 gap-4'>
								<div className='bg-gray-100 dark:bg-gray-900 p-4 rounded'>
									<p className='text-sm font-medium text-gray-500 dark:text-gray-400'>Signature Detections</p>
									<p className='text-2xl font-bold'>{analysisSummary.sigDetectedCount || 0}</p>
								</div>
								<div className='bg-gray-100 dark:bg-gray-900 p-4 rounded'>
									<p className='text-sm font-medium text-gray-500 dark:text-gray-400'>Specification Anomalies</p>
									<p className='text-2xl font-bold'>{analysisSummary.specAnomalyCount || 0}</p>
								</div>
								<div className='bg-gray-100 dark:bg-gray-900 p-4 rounded'>
									<p className='text-sm font-medium text-gray-500 dark:text-gray-400'>Hybrid Detections</p>
									<p className='text-2xl font-bold'>{analysisSummary.hybridDetectedCount || 0}</p>
								</div>
							</div>
						</div>

						{/* Confusion Matrices */}
						<div>
							<h4 className='text-md font-medium mb-2'>Confusion Matrices</h4>
							<div className='grid grid-cols-1 lg:grid-cols-3 gap-6'>
								{/* Signature Matrix */}
								<div className='bg-gray-100 dark:bg-gray-900 p-4 rounded'>
									<h5 className='text-sm font-medium mb-3'>Signature-based Detection</h5>
									<table className='min-w-full border text-sm'>
										<thead>
											<tr>
												<th className='border p-2'></th>
												<th className='border p-2'>Predicted Normal</th>
												<th className='border p-2'>Predicted Anomaly</th>
											</tr>
										</thead>
										<tbody>
											<tr>
												<th className='border p-2 text-left'>Actual Normal</th>
												<td className='border p-2 text-center'>{analysisSummary.signatureMatrix?.trueNegative || 0}</td>
												<td className='border p-2 text-center'>
													{analysisSummary.signatureMatrix?.falsePositive || 0}
												</td>
											</tr>
											<tr>
												<th className='border p-2 text-left'>Actual Anomaly</th>
												<td className='border p-2 text-center'>
													{analysisSummary.signatureMatrix?.falseNegative || 0}
												</td>
												<td className='border p-2 text-center'>{analysisSummary.signatureMatrix?.truePositive || 0}</td>
											</tr>
										</tbody>
									</table>
								</div>

								{/* Specification Matrix */}
								<div className='bg-gray-100 dark:bg-gray-900 p-4 rounded'>
									<h5 className='text-sm font-medium mb-3'>Specification-based Detection</h5>
									<table className='min-w-full border text-sm'>
										<thead>
											<tr>
												<th className='border p-2'></th>
												<th className='border p-2'>Predicted Normal</th>
												<th className='border p-2'>Predicted Anomaly</th>
											</tr>
										</thead>
										<tbody>
											<tr>
												<th className='border p-2 text-left'>Actual Normal</th>
												<td className='border p-2 text-center'>
													{analysisSummary.specificationMatrix?.trueNegative || 0}
												</td>
												<td className='border p-2 text-center'>
													{analysisSummary.specificationMatrix?.falsePositive || 0}
												</td>
											</tr>
											<tr>
												<th className='border p-2 text-left'>Actual Anomaly</th>
												<td className='border p-2 text-center'>
													{analysisSummary.specificationMatrix?.falseNegative || 0}
												</td>
												<td className='border p-2 text-center'>
													{analysisSummary.specificationMatrix?.truePositive || 0}
												</td>
											</tr>
										</tbody>
									</table>
								</div>

								{/* Hybrid Matrix */}
								<div className='bg-gray-100 dark:bg-gray-900 p-4 rounded'>
									<h5 className='text-sm font-medium mb-3'>Hybrid Detection</h5>
									<table className='min-w-full border text-sm'>
										<thead>
											<tr>
												<th className='border p-2'></th>
												<th className='border p-2'>Predicted Normal</th>
												<th className='border p-2'>Predicted Anomaly</th>
											</tr>
										</thead>
										<tbody>
											<tr>
												<th className='border p-2 text-left'>Actual Normal</th>
												<td className='border p-2 text-center'>{analysisSummary.hybridMatrix?.trueNegative || 0}</td>
												<td className='border p-2 text-center'>{analysisSummary.hybridMatrix?.falsePositive || 0}</td>
											</tr>
											<tr>
												<th className='border p-2 text-left'>Actual Anomaly</th>
												<td className='border p-2 text-center'>{analysisSummary.hybridMatrix?.falseNegative || 0}</td>
												<td className='border p-2 text-center'>{analysisSummary.hybridMatrix?.truePositive || 0}</td>
											</tr>
										</tbody>
									</table>
								</div>
							</div>
						</div>

						{/* Performance Metrics */}
						<div>
							<h4 className='text-md font-medium mb-2'>Performance Metrics</h4>
							<div className='overflow-x-auto'>
								<table className='min-w-full border text-sm'>
									<thead>
										<tr>
											<th className='border p-2'>Detection Method</th>
											<th className='border p-2'>Accuracy</th>
											<th className='border p-2'>Precision</th>
											<th className='border p-2'>Recall</th>
											<th className='border p-2'>F1 Score</th>
										</tr>
									</thead>
									<tbody>
										<tr>
											<th className='border p-2 text-left'>Signature-based</th>
											<td className='border p-2'>
												{((analysisSummary.signatureMetrics?.accuracy || 0) * 100).toFixed(2)}%
											</td>
											<td className='border p-2'>
												{((analysisSummary.signatureMetrics?.precision || 0) * 100).toFixed(2)}%
											</td>
											<td className='border p-2'>
												{((analysisSummary.signatureMetrics?.recall || 0) * 100).toFixed(2)}%
											</td>
											<td className='border p-2'>
												{((analysisSummary.signatureMetrics?.f1Score || 0) * 100).toFixed(2)}%
											</td>
										</tr>
										<tr>
											<th className='border p-2 text-left'>Specification-based</th>
											<td className='border p-2'>
												{((analysisSummary.specificationMetrics?.accuracy || 0) * 100).toFixed(2)}%
											</td>
											<td className='border p-2'>
												{((analysisSummary.specificationMetrics?.precision || 0) * 100).toFixed(2)}%
											</td>
											<td className='border p-2'>
												{((analysisSummary.specificationMetrics?.recall || 0) * 100).toFixed(2)}%
											</td>
											<td className='border p-2'>
												{((analysisSummary.specificationMetrics?.f1Score || 0) * 100).toFixed(2)}%
											</td>
										</tr>
										<tr>
											<th className='border p-2 text-left'>Hybrid</th>
											<td className='border p-2'>
												{((analysisSummary.hybridMetrics?.accuracy || 0) * 100).toFixed(2)}%
											</td>
											<td className='border p-2'>
												{((analysisSummary.hybridMetrics?.precision || 0) * 100).toFixed(2)}%
											</td>
											<td className='border p-2'>{((analysisSummary.hybridMetrics?.recall || 0) * 100).toFixed(2)}%</td>
											<td className='border p-2'>
												{((analysisSummary.hybridMetrics?.f1Score || 0) * 100).toFixed(2)}%
											</td>
										</tr>
									</tbody>
								</table>
							</div>
						</div>

						{/* Recent Attacks */}
						{analysisSummary.recentAttacks && analysisSummary.recentAttacks.length > 0 && (
							<div>
								<h4 className='text-md font-medium mb-2'>Recent Attacks</h4>
								<div className='overflow-x-auto'>
									<table className='min-w-full border text-sm'>
										<thead>
											<tr>
												<th className='border p-2'>Index</th>
												<th className='border p-2'>Attack Type</th>
												<th className='border p-2'>Method</th>
												<th className='border p-2'>URL</th>
											</tr>
										</thead>
										<tbody>
											{analysisSummary.recentAttacks.map((attack, index) => (
												<tr key={index}>
													<td className='border p-2'>{attack.index !== undefined ? attack.index : 'N/A'}</td>
													<td className='border p-2'>{attack['attack.type'] || 'Unknown'}</td>
													<td className='border p-2'>{attack['request.method'] || 'N/A'}</td>
													<td className='border p-2 truncate max-w-xs'>{attack['request.url'] || 'N/A'}</td>
												</tr>
											))}
										</tbody>
									</table>
								</div>
							</div>
						)}
					</div>
				</div>
			)}
		</div>
	);
}
