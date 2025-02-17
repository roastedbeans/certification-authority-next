'use client';
import React, { useState, useEffect } from 'react';
import { Shield, ShieldAlert } from 'lucide-react';
import { Card, CardContent, CardHeader } from '@/components/ui/card';
import Papa from 'papaparse';

interface LogRecord {
	index?: number;
	timestamp: string;
	detectionType: 'Signature' | 'Specification';
	detected: boolean | string;
	reason: string;
	request: string;
	response: string;
}

const LogMonitor = () => {
	const [logs, setLogs] = useState<any[]>([]);
	const [specificationLogs, setSpecificationLogs] = useState<LogRecord[]>([]);
	const [signatureLogs, setSignatureLogs] = useState<LogRecord[]>([]);

	useEffect(() => {
		const fetchLogs = async (
			url: string,
			setState: React.Dispatch<React.SetStateAction<any[]>>,
			parseData: (data: any[]) => any[]
		) => {
			try {
				const res = await fetch(url);
				const csvText = await res.text();
				const { data } = Papa.parse(csvText, { header: true, skipEmptyLines: true });
				data.reverse();
				const indexedData = parseData(data);
				setState(indexedData);
			} catch (err) {
				console.error(err);
			}
		};

		const parseLogData = (data: any[]) =>
			data.map((item: any, index: number) => ({ ...item, index: data.length - index }));

		const timeout = setInterval(async () => {
			await fetchLogs('/ca_formatted_logs.csv', setLogs, parseLogData);
			await fetchLogs('/specification_detection_logs.csv', setSpecificationLogs, parseLogData);
			await fetchLogs('/signature_detection_logs.csv', setSignatureLogs, parseLogData);
		}, 2000);
		return () => clearInterval(timeout);
	}, []);

	return (
		<div className='flex gap-4 w-full max-h-screen p-16 mx-auto'>
			<div>
				<Card className='w-full'>
					<CardHeader className='font-semibold justify-between items-center flex flex-row'>
						<span>Certification Authority API Logs</span>
						<span>
							Count:{' '}
							{logs.filter((log) => log['attack.type'] !== '').length +
								logs.filter((log) => log['attack.type'] === '' && log['response.status'] === '400').length}{' '}
							(Attacks)
						</span>
					</CardHeader>
					<CardContent className='w-full'>
						<div className='flex flex-col pr-2 h-[680px] overflow-y-scroll'>
							{logs.map((row: any, index) => (
								<div
									key={index}
									className='flex border-t p-2 gap-4'>
									<div>
										<p>{row.index}</p>
									</div>
									<div className='w-24 overflow-clip'>
										<p className='uppercase font-semibold text-red-500'>
											{row['attack.type'] as string}
											{row['attack.type'] === '' && row['response.status'] === '400' && 'Invalid'}
										</p>
									</div>
									<div className='w-16'>
										<p>{row['request.method']}</p>
									</div>
									<div className='w-[600px] overflow-clip'>
										<p className='overflow-hidden'>{row['request.url']}</p>
									</div>
								</div>
							))}
						</div>
					</CardContent>
				</Card>
			</div>
			<div className='flex flex-col gap-4 w-[600px] h-full justify-between'>
				<Card className='w-full h-fit'>
					<CardHeader className='font-semibold justify-between items-center flex flex-row'>
						<span>Specification Detection Logs</span>
						<span>Count: {specificationLogs.filter((log) => log.detected !== 'false').length} (Anomalies)</span>
					</CardHeader>
					<CardContent className='w-full overflow-hidden'>
						<div className='flex flex-col pr-2 h-[280px] w-full overflow-y-scroll'>
							{specificationLogs
								.filter((log) => log.detected !== 'false')
								.map((row, index) => {
									return (
										<div
											key={index}
											className='flex border-t p-2 gap-4'>
											<div>
												<p>{row.index}</p>
											</div>
											<div className='w-24'>
												{row.detected ? (
													<ShieldAlert
														className='text-red-500'
														size={24}
													/>
												) : (
													<Shield
														className='text-green-500'
														size={24}
													/>
												)}
											</div>
											<div className='w-full'>
												<p className='font-semibold'>{row.reason}</p>
											</div>
										</div>
									);
								})}
						</div>
					</CardContent>
				</Card>
				<Card className='w-full h-fit'>
					<CardHeader className='font-semibold justify-between items-center flex flex-row'>
						<span>Signature Detection Logs</span>
						<span>Count: {signatureLogs.filter((log) => log.detected !== 'false').length} (Detected)</span>
					</CardHeader>
					<CardContent className='w-full'>
						<div className='flex flex-col pr-2 h-[280px] w-full overflow-y-scroll'>
							{signatureLogs
								.filter((log) => log.detected !== 'false')
								.map((row, index) => {
									return (
										<div
											key={index}
											className='flex border-t p-2 gap-4'>
											<div>
												<p>{row.index}</p>
											</div>
											<div className='w-24'>
												{row.detected ? (
													<ShieldAlert
														className='text-red-500'
														size={24}
													/>
												) : (
													<Shield
														className='text-green-500'
														size={24}
													/>
												)}
											</div>
											<div className='w-full'>
												<p className='font-semibold'>{row.reason}</p>
											</div>
										</div>
									);
								})}
						</div>
					</CardContent>
				</Card>
			</div>
		</div>
	);
};

export default LogMonitor;
