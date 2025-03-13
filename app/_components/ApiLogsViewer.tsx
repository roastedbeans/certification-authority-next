'use client';

import React, { useEffect, useState } from 'react';
import { getDetectionLogs, LogEntry } from '../_actions/security-actions';

export default function ApiLogsViewer() {
	const [logs, setLogs] = useState<LogEntry[]>([]);
	const [loading, setLoading] = useState(true);
	const [error, setError] = useState<string | null>(null);
	const [logType, setLogType] = useState<'all' | 'signature' | 'specification' | 'hybrid'>('all');
	const [expandedLog, setExpandedLog] = useState<number | null>(null);

	useEffect(() => {
		const fetchLogs = async () => {
			setLoading(true);
			setError(null);

			try {
				const result = await getDetectionLogs(logType);
				if (result.error) {
					setError(result.error);
				} else {
					setLogs(result.logs);
				}
			} catch (error) {
				setError('Failed to fetch logs');
				console.error('Error fetching logs:', error);
			} finally {
				setLoading(false);
			}
		};

		fetchLogs();
	}, [logType]);

	const toggleExpand = (index: number) => {
		setExpandedLog(expandedLog === index ? null : index);
	};

	const formatJson = (jsonString: string) => {
		try {
			const parsed = JSON.parse(jsonString);
			return JSON.stringify(parsed, null, 2);
		} catch {
			return jsonString;
		}
	};

	return (
		<div className='space-y-6'>
			<div className='bg-white dark:bg-gray-800 p-6 rounded-lg shadow'>
				<div className='flex justify-between items-center mb-6'>
					<h2 className='text-xl font-semibold'>API Logs & Detection Results</h2>

					<div className='flex space-x-2'>
						<select
							value={logType}
							onChange={(e) => setLogType(e.target.value as any)}
							className='px-3 py-2 border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500'>
							<option value='all'>All Logs</option>
							<option value='signature'>Signature Detection</option>
							<option value='specification'>Specification Detection</option>
							<option value='hybrid'>Hybrid Detection</option>
						</select>

						<button
							onClick={() =>
								getDetectionLogs(logType).then((result) => {
									if (result.error) {
										setError(result.error);
									} else {
										setLogs(result.logs);
									}
								})
							}
							className='px-3 py-2 bg-blue-500 text-white rounded-md hover:bg-blue-600 focus:outline-none focus:ring-2 focus:ring-blue-500'>
							Refresh
						</button>
					</div>
				</div>

				{loading ? (
					<div className='text-center py-8'>
						<div className='inline-block animate-spin rounded-full h-8 w-8 border-4 border-blue-500 border-t-transparent'></div>
						<p className='mt-2 text-muted-foreground'>Loading logs...</p>
					</div>
				) : error ? (
					<div className='bg-red-50 dark:bg-red-900/20 p-4 rounded text-red-800 dark:text-red-300'>{error}</div>
				) : logs.length === 0 ? (
					<div className='text-center py-8 text-muted-foreground'>
						No logs found. Run detection scripts to generate logs.
					</div>
				) : (
					<div className='overflow-x-auto'>
						<table className='w-full border-collapse'>
							<thead>
								<tr className='bg-gray-100 dark:bg-gray-700'>
									<th className='px-4 py-2 text-left'>Timestamp</th>
									<th className='px-4 py-2 text-left'>Type</th>
									<th className='px-4 py-2 text-left'>Status</th>
									<th className='px-4 py-2 text-left'>Reason</th>
									<th className='px-4 py-2 text-left'>Details</th>
								</tr>
							</thead>
							<tbody>
								{logs.map((log, index) => (
									<React.Fragment key={index}>
										<tr
											className={`border-t hover:bg-gray-50 dark:hover:bg-gray-800 cursor-pointer ${
												typeof log.detected === 'boolean' && log.detected ? 'bg-red-50 dark:bg-red-900/10' : ''
											}`}
											onClick={() => toggleExpand(index)}>
											<td className='px-4 py-3'>{new Date(log.timestamp).toLocaleString()}</td>
											<td className='px-4 py-3'>{log.detectionType}</td>
											<td className='px-4 py-3'>
												<span
													className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
														typeof log.detected === 'boolean' && log.detected
															? 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300'
															: 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-300'
													}`}>
													{typeof log.detected === 'boolean' ? (log.detected ? 'Detected' : 'Clean') : log.detected}
												</span>
											</td>
											<td className='px-4 py-3 max-w-md truncate'>{log.reason}</td>
											<td className='px-4 py-3'>
												<button className='text-blue-500 hover:text-blue-700'>
													{expandedLog === index ? 'Hide' : 'View'}
												</button>
											</td>
										</tr>
										{expandedLog === index && (
											<tr className='bg-gray-50 dark:bg-gray-800/50'>
												<td
													colSpan={5}
													className='px-4 py-3'>
													<div className='grid grid-cols-1 md:grid-cols-2 gap-4'>
														<div>
															<h4 className='font-medium mb-2'>Request</h4>
															<pre className='bg-gray-100 dark:bg-gray-900 p-3 rounded text-xs overflow-auto max-h-60'>
																{formatJson(log.request)}
															</pre>
														</div>
														<div>
															<h4 className='font-medium mb-2'>Response</h4>
															<pre className='bg-gray-100 dark:bg-gray-900 p-3 rounded text-xs overflow-auto max-h-60'>
																{formatJson(log.response)}
															</pre>
														</div>
													</div>
												</td>
											</tr>
										)}
									</React.Fragment>
								))}
							</tbody>
						</table>
					</div>
				)}
			</div>
		</div>
	);
}
