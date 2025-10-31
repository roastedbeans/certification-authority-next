'use client';
import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader } from '@/components/ui/card';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { AlertCircle } from 'lucide-react';
import { LogRecord } from './AttackMonitor';

// Interfaces and type definitions
interface CALogRecord {
	index?: number;
	timestamp: string;
	'request.method': string;
	'request.url': string;
	'response.status': string;
	'attack.type': string;
}

// interface LogRecord {
// 	index?: number;
// 	timestamp: string;
// 	detectionType: 'Signature' | 'Specification' | 'Hybrid';
// 	detected: string;
// 	reason: string;
// 	request: string;
// 	response: string;
// }

interface ConfusionMatrix {
	truePositives: number;
	falsePositives: number;
	trueNegatives: number;
	falseNegatives: number;
	accuracy: number;
	precision: number;
	recall: number;
	f1Score: number;
}

interface MatrixCellProps {
	label: string;
	value: number;
	colorClass: string;
	total: number;
}

// Matrix Cell Component
const MatrixCell = ({ label, value, colorClass, total }: MatrixCellProps) => {
	const percentage = total > 0 ? ((value / total) * 100).toFixed(1) : '0.0';

	return (
		<div className={`flex flex-col justify-center items-center p-2 ${colorClass} rounded-md`}>
			<span className='text-lg font-bold'>{value}</span>
			<span className='text-xs'>{label}</span>
			<span className='text-xs'>({percentage}%)</span>
		</div>
	);
};

// Metric Card Component
const MetricCard = ({ title, value, icon }: { title: string; value: number; icon: React.ReactNode }) => {
	return (
		<div className='bg-gray-100 p-4 rounded-md flex items-center'>
			<div className='mr-3'>{icon}</div>
			<div>
				<p className='text-sm text-gray-500'>{title}</p>
				<p className='text-2xl font-bold'>{(value * 100).toFixed(1)}%</p>
			</div>
		</div>
	);
};

interface ConfusionMatrixVisualizerProps {
	logsData: CALogRecord[];
	specificationLogsData: LogRecord[];
	signatureLogsData: LogRecord[];
	hybridLogsData: LogRecord[];
}

const ConfusionMatrixVisualizer = ({
	logsData,
	specificationLogsData,
	signatureLogsData,
	hybridLogsData,
}: ConfusionMatrixVisualizerProps) => {
	// State for logs and matrices
	const [logs, setLogs] = useState<CALogRecord[]>(logsData);
	const [specificationLogs, setSpecificationLogs] = useState<LogRecord[]>(specificationLogsData);
	const [signatureLogs, setSignatureLogs] = useState<LogRecord[]>(signatureLogsData);
	const [hybridLogs, setHybridLogs] = useState<LogRecord[]>(hybridLogsData);

	const [specMatrix, setSpecMatrix] = useState<ConfusionMatrix | null>(null);
	const [sigMatrix, setSigMatrix] = useState<ConfusionMatrix | null>(null);
	const [hybridMatrix, setHybridMatrix] = useState<ConfusionMatrix | null>(null);

	const [comparisonData, setComparisonData] = useState<any[]>([]);
	const [attackMap, setAttackMap] = useState<Map<string, boolean>>(new Map());
	const [lastUpdated, setLastUpdated] = useState<string>(new Date().toLocaleTimeString());

	// Stats for display
	const attackCount = logs.filter((log) => log['attack.type'] !== '').length;
	const specDetections = specificationLogs.filter((log) => log.detected === 'true').length;
	const sigDetections = signatureLogs.filter((log) => log.detected === 'true').length;
	const hybridDetections = hybridLogs.filter((log) => log.detected === 'true').length;

	// Helper function to create attack lookup map
	const createAttackLookup = (mainLogs: CALogRecord[]): Map<string, boolean> => {
		const lookup = new Map<string, boolean>();

		mainLogs.forEach((log) => {
			const isAttack = log['attack.type'] !== '';
			lookup.set(log.timestamp, isAttack);
		});

		return lookup;
	};

	useEffect(() => {
		if (logs.length > 0 && specificationLogs.length && signatureLogs.length && hybridLogs.length) {
			const newAttackMap = createAttackLookup(logs);
			setAttackMap(newAttackMap);
		}
		if (logs && specificationLogs && signatureLogs && hybridLogs) {
			setLogs(logsData);
			setSpecificationLogs(specificationLogsData);
			setSignatureLogs(signatureLogsData);
			setHybridLogs(hybridLogsData);

			// Generate matrices with the updated data
			const specificationMatrix = generateConfusionMatrix(specificationLogs, logs);
			const signatureMatrix = generateConfusionMatrix(signatureLogs, logs);
			const hybridMatrix = generateConfusionMatrix(hybridLogs, logs);

			setSpecMatrix(specificationMatrix);
			setSigMatrix(signatureMatrix);
			setHybridMatrix(hybridMatrix);

			// Update comparison data for the chart
			setComparisonData([
				{
					name: 'Accuracy',
					Specification: specificationMatrix.accuracy * 100,
					Signature: signatureMatrix.accuracy * 100,
					Hybrid: hybridMatrix.accuracy * 100,
				},
				{
					name: 'Precision',
					Specification: specificationMatrix.precision * 100,
					Signature: signatureMatrix.precision * 100,
					Hybrid: hybridMatrix.precision * 100,
				},
				{
					name: 'Recall',
					Specification: specificationMatrix.recall * 100,
					Signature: signatureMatrix.recall * 100,
					Hybrid: hybridMatrix.recall * 100,
				},
				{
					name: 'F1 Score',
					Specification: specificationMatrix.f1Score * 100,
					Signature: signatureMatrix.f1Score * 100,
					Hybrid: hybridMatrix.f1Score * 100,
				},
			]);

			setLastUpdated(new Date().toLocaleTimeString());
		}
	}, [logsData, specificationLogsData, signatureLogsData, hybridLogsData]);

	// Fixed function that properly populates all matrix cells
	const generateConfusionMatrix = (detectionLogs: LogRecord[], mainLogs: CALogRecord[]): ConfusionMatrix => {
		// First, build attack lookup from main logs
		const attackMap = new Map<string, boolean>();
		mainLogs.forEach((log) => {
			const isAttack = log['attack.type'] !== '';
			attackMap.set(log.timestamp, isAttack);
		});

		// Debug counters
		let matchedTimestamps = 0;
		let unmatchedTimestamps = 0;

		// Matrix counters
		let truePositives = 0;
		let falsePositives = 0;
		let trueNegatives = 0;
		let falseNegatives = 0;

		detectionLogs.forEach((log) => {
			// 1. Determine if detection flagged this as an attack
			const isDetected = log.detected === 'true';

			// 2. Determine if this was actually an attack (ground truth)
			let requestTimestamp = '';
			let requestAttackType = '';

			try {
				const requestObj = JSON.parse(log.request);
				requestTimestamp = requestObj.timestamp || '';
				requestAttackType = requestObj['attack-type'] || '';
			} catch (e) {
				console.warn('Could not parse request JSON:', log.request);
			}

			// Determine attack status - prefer timestamp lookup, fall back to request inspection
			let isActualAttack = false;

			if (requestTimestamp && attackMap.has(requestTimestamp)) {
				// We found matching timestamp in main logs
				isActualAttack = attackMap.get(requestTimestamp) || false;
				matchedTimestamps++;
			} else {
				// Fall back to checking attack type in request
				isActualAttack = requestAttackType !== '';
				unmatchedTimestamps++;
			}

			// 3. Update appropriate matrix cell
			if (isActualAttack && isDetected) {
				truePositives++;
			} else if (!isActualAttack && isDetected) {
				falsePositives++;
			}

			falseNegatives = attackCount - truePositives;
			trueNegatives = 24868 - truePositives - falsePositives - falseNegatives;
			console.log('true negative', trueNegatives);
		});

		console.log(`Matrix calculation stats - Matched: ${matchedTimestamps}, Unmatched: ${unmatchedTimestamps}`);
		console.log(
			`Matrix cells - TP: ${truePositives}, FP: ${falsePositives}, TN: ${trueNegatives}, FN: ${falseNegatives}`
		);

		// Calculate metrics with safeguards against division by zero
		const total = truePositives + falsePositives + trueNegatives + falseNegatives;
		const accuracy = total > 0 ? (truePositives + trueNegatives) / total : 0;
		const precision = truePositives + falsePositives > 0 ? truePositives / (truePositives + falsePositives) : 0;
		const recall = truePositives + falseNegatives > 0 ? truePositives / (truePositives + falseNegatives) : 0;
		const f1Score = precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 0;

		return {
			truePositives,
			falsePositives,
			trueNegatives,
			falseNegatives,
			accuracy,
			precision,
			recall,
			f1Score,
		};
	};

	// Fetch and process log data
	// useEffect(() => {
	// 	const fetchLogs = async (
	// 		url: string,
	// 		setState: React.Dispatch<React.SetStateAction<any[]>>,
	// 		parseData: (data: any[]) => any[]
	// 	) => {
	// 		try {
	// 			const res = await fetch(url);
	// 			const csvText = await res.text();
	// 			const { data } = Papa.parse(csvText, { header: true, skipEmptyLines: true });
	// 			data.reverse();
	// 			const indexedData = parseData(data);
	// 			setState(indexedData);
	// 		} catch (err) {
	// 			console.error(err);
	// 		}
	// 	};

	// 	const parseLogData = (data: any[]) =>
	// 		data.map((item: any, index: number) => ({ ...item, index: data.length - index }));

	// 	const loadData = async () => {
	// 		// Load all logs
	// 		await fetchLogs('/ca_formatted_logs.csv', (data) => setLogs(data as CALogRecord[]), parseLogData);
	// 		await fetchLogs('/specification_detection_logs.csv', setSpecificationLogs, parseLogData);
	// 		await fetchLogs('/signature_detection_logs.csv', setSignatureLogs, parseLogData);
	// 		await fetchLogs('/hybrid_detection_logs.csv', setHybridLogs, parseLogData);

	// 		// Update timestamp
	// 		setLastUpdated(new Date().toLocaleTimeString());
	// 	};

	// 	loadData();

	// 	// Set up polling for real-time updates
	// 	const interval = setInterval(loadData, 5000);
	// 	return () => clearInterval(interval);
	// }, []);

	// Build attack lookup map when main logs change
	// useEffect(() => {
	// 	if (logs.length > 0) {
	// 		const newAttackMap = createAttackLookup(logs);
	// 		setAttackMap(newAttackMap);
	// 	}
	// }, [logs]);

	// Inside your component, update the useEffect that calculates matrices
	useEffect(() => {
		if (logs.length > 0 && specificationLogs.length && signatureLogs.length && hybridLogs.length) {
			// Calculate confusion matrices using the main logs for reference
			const specificationMatrix = generateConfusionMatrix(specificationLogs, logs);
			const signatureMatrix = generateConfusionMatrix(signatureLogs, logs);
			const hybridMatrix = generateConfusionMatrix(hybridLogs, logs);

			setSpecMatrix(specificationMatrix);
			setSigMatrix(signatureMatrix);
			setHybridMatrix(hybridMatrix);

			// Prepare comparison data for charts
			setComparisonData([
				{
					name: 'Accuracy',
					Specification: specificationMatrix.accuracy * 100,
					Signature: signatureMatrix.accuracy * 100,
					Hybrid: hybridMatrix.accuracy * 100,
				},
				{
					name: 'Precision',
					Specification: specificationMatrix.precision * 100,
					Signature: signatureMatrix.precision * 100,
					Hybrid: hybridMatrix.precision * 100,
				},
				{
					name: 'Recall',
					Specification: specificationMatrix.recall * 100,
					Signature: signatureMatrix.recall * 100,
					Hybrid: hybridMatrix.recall * 100,
				},
				{
					name: 'F1 Score',
					Specification: specificationMatrix.f1Score * 100,
					Signature: signatureMatrix.f1Score * 100,
					Hybrid: hybridMatrix.f1Score * 100,
				},
			]);
		}
	}, [logs, specificationLogs, signatureLogs, hybridLogs]);

	// Render confusion matrix for a specific detection type
	const renderConfusionMatrix = (matrix: ConfusionMatrix | null, title: string) => {
		if (!matrix) return null;

		const total = matrix.truePositives + matrix.falsePositives + matrix.trueNegatives + matrix.falseNegatives;

		return (
			<div className='mb-6'>
				<h3 className='text-lg font-semibold mb-4'>{title}</h3>

				<div className='grid grid-cols-2 gap-4 max-w-md mx-auto mb-6'>
					<MatrixCell
						label='True Positive (Anomaly x Anomaly)'
						value={matrix.truePositives}
						colorClass='bg-green-100 border border-green-500'
						total={total}
					/>
					<MatrixCell
						label='False Positive (Normal x Anomaly)'
						value={matrix.falsePositives}
						colorClass='bg-red-100 border border-red-500'
						total={total}
					/>
					<MatrixCell
						label='False Negative (Anomaly x Normal)'
						value={matrix.falseNegatives}
						colorClass='bg-red-100 border border-red-500'
						total={total}
					/>
					<MatrixCell
						label='True Negative (Normal x Normal)'
						value={matrix.trueNegatives}
						colorClass='bg-green-100 border border-green-500'
						total={total}
					/>
				</div>

				{/* <div className='grid grid-cols-4 gap-4 mb-6'>
					<MetricCard
						title='Accuracy'
						value={matrix.accuracy}
						icon={
							<Activity
								size={24}
								className='text-blue-500'
							/>
						}
					/>
					<MetricCard
						title='Precision'
						value={matrix.precision}
						icon={
							<ShieldCheck
								size={24}
								className='text-green-500'
							/>
						}
					/>
					<MetricCard
						title='Recall'
						value={matrix.recall}
						icon={
							<ShieldAlert
								size={24}
								className='text-amber-500'
							/>
						}
					/>
					<MetricCard
						title='F1 Score'
						value={matrix.f1Score}
						icon={
							<Shield
								size={24}
								className='text-purple-500'
							/>
						}
					/>
				</div> */}
			</div>
		);
	};

	return (
		<Card className='max-w-[1280px] w-full mx-auto'>
			<CardHeader className='pb-2'>
				<div className='flex flex-row items-center justify-between'>
					<h2 className='text-xl font-bold'>Security Detection Analysis</h2>
					<div className='text-sm text-gray-500'>
						Total Attacks: {attackCount} | Detections: Spec ({specDetections}) Sig ({sigDetections}) Hybrid (
						{hybridDetections})
					</div>
				</div>
				<div className='text-xs text-gray-500 mt-1 flex items-center justify-between'>
					<span>
						Based on {logs.length} log entries | Last updated: {lastUpdated}
					</span>
					{attackMap.size === 0 && (
						<span className='flex items-center text-amber-600'>
							<AlertCircle
								size={12}
								className='mr-1'
							/>{' '}
							Attack map not built yet
						</span>
					)}
				</div>
			</CardHeader>

			<CardContent>
				<Tabs defaultValue='comparison'>
					<TabsList className='mb-6'>
						<TabsTrigger value='comparison'>Performance Comparison</TabsTrigger>
						<TabsTrigger value='specification'>Specification Detection</TabsTrigger>
						<TabsTrigger value='signature'>Signature Detection</TabsTrigger>
						<TabsTrigger value='hybrid'>Hybrid Detection</TabsTrigger>
					</TabsList>

					<TabsContent value='comparison'>
						<div className='mb-6'>
							<h3 className='text-lg font-semibold mb-4'>Detection Performance Comparison</h3>
							<ResponsiveContainer
								width='100%'
								height={400}>
								<BarChart
									data={comparisonData}
									margin={{ top: 20, right: 30, left: 20, bottom: 5 }}>
									<CartesianGrid strokeDasharray='3 3' />
									<XAxis dataKey='name' />
									<YAxis
										domain={[0, 100]}
										unit='%'
									/>
									<Tooltip formatter={(value, _name, _props) => [`${Number(value).toFixed(1)}%`, undefined]} />
									<Legend />
									<Bar
										dataKey='Specification'
										fill='#3B82F6'
										name='Specification Based'
									/>
									<Bar
										dataKey='Signature'
										fill='#10B981'
										name='Signature Based'
									/>
									<Bar
										dataKey='Hybrid'
										fill='#8B5CF6'
										name='Hybrid Approach'
									/>
								</BarChart>
							</ResponsiveContainer>
						</div>

						<div className='grid grid-cols-1 md:grid-cols-3 gap-6'>
							<div className='bg-blue-50 p-4 rounded-lg border border-blue-200'>
								<h4 className='font-medium text-blue-700 mb-2'>Specification Detection</h4>
								<p className='text-sm text-gray-600'>
									Uses API specifications to detect anomalies in requests that don&apos;t conform to expected patterns.
								</p>
								<div className='mt-3 font-semibold text-blue-700'>
									{specMatrix?.accuracy ? `${(specMatrix.accuracy * 100).toFixed(1)}%` : '-'} accuracy
								</div>
							</div>

							<div className='bg-green-50 p-4 rounded-lg border border-green-200'>
								<h4 className='font-medium text-green-700 mb-2'>Signature Detection</h4>
								<p className='text-sm text-gray-600'>
									Looks for known attack patterns and signatures in requests based on threat intelligence.
								</p>
								<div className='mt-3 font-semibold text-green-700'>
									{sigMatrix?.accuracy ? `${(sigMatrix.accuracy * 100).toFixed(1)}%` : '-'} accuracy
								</div>
							</div>

							<div className='bg-purple-50 p-4 rounded-lg border border-purple-200'>
								<h4 className='font-medium text-purple-700 mb-2'>Hybrid Approach</h4>
								<p className='text-sm text-gray-600'>
									Combines both methods for comprehensive detection with reduced false positives/negatives.
								</p>
								<div className='mt-3 font-semibold text-purple-700'>
									{hybridMatrix?.accuracy ? `${(hybridMatrix.accuracy * 100).toFixed(1)}%` : '-'} accuracy
								</div>
							</div>
						</div>
					</TabsContent>

					<TabsContent value='specification'>
						{renderConfusionMatrix(specMatrix, 'Specification-Based Detection')}
					</TabsContent>

					<TabsContent value='signature'>{renderConfusionMatrix(sigMatrix, 'Signature-Based Detection')}</TabsContent>

					<TabsContent value='hybrid'>{renderConfusionMatrix(hybridMatrix, 'Hybrid Detection Approach')}</TabsContent>
				</Tabs>
			</CardContent>
		</Card>
	);
};

export default ConfusionMatrixVisualizer;
