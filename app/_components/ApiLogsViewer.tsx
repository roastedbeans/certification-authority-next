'use client';

import React, { useEffect, useState } from 'react';
import { getDetectionLogs, LogEntry } from '../_actions/security-actions';

// Improved JSON parsing function with better error handling
const formatJson = (jsonString: string): Record<string, any> => {
	try {
		// First try parsing the string directly
		return JSON.parse(jsonString);
	} catch (firstError) {
		try {
			// If direct parsing fails, try replacing double quotes with single quotes
			const normalizedJson = jsonString.replace(/""/g, '"');

			// Check if the string starts with a quote followed by a curly brace
			// This handles cases where there's an extra quote at the beginning
			if (normalizedJson.match(/^"{\s*"/)) {
				// Remove the first quote and the last quote if it exists
				const trimmedJson = normalizedJson.replace(/^"/, '').replace(/"$/, '');
				return JSON.parse(trimmedJson);
			}

			return JSON.parse(normalizedJson);
		} catch (secondError) {
			// Third attempt: try to detect and fix more complex quote issues
			try {
				// This handles cases where the string might have been double-stringified
				// or has other quoting issues
				const cleanedJson = jsonString
					.replace(/^"+|"+$/g, '') // Remove quotes at start/end
					.replace(/""/g, '"'); // Replace double quotes with single quotes

				return JSON.parse(cleanedJson);
			} catch (thirdError) {
				console.error('Error parsing JSON:', thirdError);
				return { rawValue: String(jsonString) };
			}
		}
	}
};

type JsonViewerProps = {
	data: any;
	isBodyField?: boolean;
};

// Helper component to display parsed JSON content
const JsonViewer: React.FC<JsonViewerProps> = ({ data, isBodyField = false }) => {
	if (!data) return null;

	if (typeof data === 'object') {
		console.log('here');
		return (
			<>
				{Object.entries(data).map(([key, value]) => (
					<div
						key={key}
						className='text-wrap max-w-full whitespace-normal break-words'>
						<strong>{key}:</strong>{' '}
						{isBodyField && key === 'body' && typeof value === 'string' ? (
							<JsonBodyContent body={value} />
						) : typeof value === 'object' ? (
							<JsonBodyContent body={JSON.stringify(value)} />
						) : (
							String(value)
						)}
					</div>
				))}
			</>
		);
	}

	return <div>{String(data)}</div>;
};

type JsonBodyContentProps = {
	body: string;
};

// Helper component to parse and display JSON body content
const JsonBodyContent: React.FC<JsonBodyContentProps> = ({ body }) => {
	if (!body || typeof body !== 'string') return null;

	console.log(body);

	try {
		// Only try to parse if it looks like JSON
		if (body.trim().startsWith('{') || body.trim().startsWith('[')) {
			const parsedBody = JSON.parse(body);
			return (
				<>
					<br />
					{Object.entries(parsedBody).map(([key, value]) => (
						<div
							key={key}
							className='ml-4'>
							<strong>{key}:</strong>{' '}
							{typeof value === 'object' ? (
								<pre className='text-xs'>{JSON.stringify(value, null, 2)}</pre>
							) : (
								String(value)
							)}
						</div>
					))}
				</>
			);
		}
	} catch (e) {
		// If parsing fails, just show the raw body
		console.error('Error parsing body:', e);
	}

	return <span>{body}</span>;
};

type DataSectionProps = {
	title: string;
	data: any;
};

// Request/Response data display component
const DataSection: React.FC<DataSectionProps> = ({ title, data }) => {
	return (
		<div>
			<h4 className='font-medium mb-2'>{title}</h4>
			<pre className='bg-gray-100 dark:bg-gray-900 p-3 rounded text-xs min-h-32 overflow-auto'>
				<JsonViewer
					data={data}
					isBodyField={true}
				/>
			</pre>
		</div>
	);
};

export default function ApiLogsViewer() {
	const [logs, setLogs] = useState<LogEntry[]>([]);
	const [loading, setLoading] = useState(true);
	const [error, setError] = useState<string | null>(null);
	const [logType, setLogType] = useState<'all' | 'signature' | 'specification' | 'hybrid'>('all');
	const [expandedLog, setExpandedLog] = useState<number | null>(null);
	const [isClient, setIsClient] = useState(false);

	useEffect(() => {
		setIsClient(true);
	}, []);

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

		if (isClient) {
			fetchLogs();
		}
		// const interval = setInterval(() => {
		// 	fetchLogs();
		// }, 5000);

		// return () => clearInterval(interval);
	}, [logType, isClient]);

	const toggleExpand = (index: number) => {
		setExpandedLog(expandedLog === index ? null : index);
	};

	// Process and parse request/response data completely
	const processData = (data: any): any => {
		if (!data) return null;

		// If it's a string, try to parse it as JSON
		if (typeof data === 'string') {
			const parsedData = formatJson(data);

			// If the parsed data has a body field that's a string, parse that too
			if (parsedData && typeof parsedData.body === 'string') {
				parsedData.body = formatJson(parsedData.body);
				try {
					if (parsedData.body.trim().startsWith('{') || parsedData.body.trim().startsWith('[')) {
						parsedData.body = formatJson(parsedData.body);
					}
				} catch (e) {
					// If body parsing fails, keep it as a string
					console.error('Error parsing body:', e);
				}
			}

			return parsedData;
		}

		// If it's already an object, check if it has a body to parse
		if (data && typeof data === 'object' && typeof data.body === 'string') {
			console.log('data.body', data.body);
			try {
				if (data.body.trim().startsWith('{') || data.body.trim().startsWith('[')) {
					data.body = formatJson(data.body);
				}
			} catch (e) {
				// If body parsing fails, keep it as a string
				console.error('Error parsing body:', e);
			}
		}

		return data;
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
					<div className='overflow-x-auto max-h-[540px] overflow-y-auto relative'>
						<table className='w-full border-collapse '>
							<thead className='sticky top-0 bg-gray-100 dark:bg-gray-700'>
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
														<DataSection
															title='Request'
															data={processData(log.request)}
														/>
														<DataSection
															title='Response'
															data={processData(log.response)}
														/>
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
