'use client';
import React, { useState, useEffect } from 'react';
import { Shield, ShieldAlert } from 'lucide-react';
import { Card, CardContent, CardHeader } from '@/components/ui/card';
import Papa from 'papaparse';
import AttackMonitorV2 from './AttackMonitorV2';

export interface LogRecord {
	index?: number;
	timestamp: string;
	detectionType: 'Signature' | 'Specification' | 'Hybrid';
	detected: boolean | string;
	reason: string;
	request: string;
	response: string;
}

const headers = [
	{ name: 'Index', width: 'w-16' },
	{ name: 'Attack Type', width: 'w-24' },
	{ name: 'Method', width: 'w-16' },
	{ name: 'URL', width: 'w-[560px]' },
	{ name: 'Signature', width: 'w-28' },
	{ name: 'Specification', width: 'w-28' },
	{ name: 'Hybrid', width: 'w-28' },
];

const LogMonitor = () => {
	const [logs, setLogs] = useState<any[]>([]);
	const [specificationLogs, setSpecificationLogs] = useState<LogRecord[]>([]);
	const [signatureLogs, setSignatureLogs] = useState<LogRecord[]>([]);
	const [hybridLogs, setHybridLogs] = useState<LogRecord[]>([]);

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

				const indexedData = parseData(data).filter((_, index) => index < 10000);
				setState(indexedData);
			} catch (err) {
				console.error(err);
			}
		};

		const parseLogData = (data: any[]) => data.map((item: any, index: number) => ({ ...item, index: index }));

		const timeout = setInterval(async () => {
			await fetchLogs('/ca_formatted_logs.csv', setLogs, parseLogData);
			await fetchLogs('/specification_detection_logs.csv', setSpecificationLogs, parseLogData);
			await fetchLogs('/signature_detection_logs.csv', setSignatureLogs, parseLogData);
			await fetchLogs('/hybrid_detection_logs.csv', setHybridLogs, parseLogData);
		}, 2000);
		return () => clearInterval(timeout);
	}, []);

	return (
		<div className='flex gap-4 w-full max-h-screen p-16 mx-auto'>
			<div className='flex flex-col gap-4 w-[1280px] h-full'>
				<Card className='w-full'>
					<CardHeader className='font-semibold justify-between items-center flex flex-row'>
						<span>Certification Authority API Logs</span>
						<span>Count: {logs.filter((_) => _['attack.type'] !== '').length} (Attacks)</span>
					</CardHeader>
					<CardContent className='w-full'>
						<div className='flex flex-col pr-2 h-[680px] overflow-y-scroll'>
							<div className='flex border-t p-2 gap-4 font-semibold'>
								{headers.map((header) => (
									<div
										className={`${header.width}`}
										key={header.name}>
										{header.name}
									</div>
								))}
							</div>
							{logs.map((row: any, index) => (
								<div
									key={index}
									className={`flex border-t p-2 gap-4 ${
										hybridLogs[index]?.detected === 'false' && (row['attack.type'] as string) ? 'bg-red-200' : ''
									}`}>
									<div className='w-16'>
										<p>{row.index}</p>
									</div>
									<div className='w-24 overflow-clip text-ellipsis'>
										<p className='uppercase font-semibold text-red-500'>
											{row['attack.type'] as string}
											{row['attack.type'] === '' && row['response.status'] === '400' && 'Invalid'}
										</p>
									</div>
									<div className='w-16'>
										<p>{row['request.method']}</p>
									</div>
									<div className='w-[560px] overflow-clip'>
										<p className='overflow-hidden'>{row['request.url']}</p>
									</div>
									<div className='w-28 overflow-hidden text-ellipsis'>
										[
										{signatureLogs[index]?.detected === 'true' ? (
											<span>{signatureLogs[index] && JSON.parse(signatureLogs[index].request)?.['attack-type']}</span>
										) : (
											<span>none</span>
										)}
										]
									</div>
									<div className='w-28 overflow-hidden text-ellipsis'>
										[
										{specificationLogs[index]?.detected === 'true' ? (
											<span>
												{specificationLogs[index] && JSON.parse(specificationLogs[index].request)?.['attack-type']}
											</span>
										) : (
											<span>none</span>
										)}
										]
									</div>
									<div className='w-28 overflow-hidden text-ellipsis'>
										[
										{hybridLogs[index]?.detected === 'true' ? (
											<span>{hybridLogs[index] && JSON.parse(hybridLogs[index].request)?.['attack-type']}</span>
										) : (
											<span>none</span>
										)}
										]
									</div>
								</div>
							))}
						</div>
					</CardContent>
				</Card>
				<AttackMonitorV2
					logsData={logs}
					specificationLogsData={specificationLogs}
					signatureLogsData={signatureLogs}
					hybridLogsData={hybridLogs}
				/>
			</div>
			<div className='flex flex-col gap-4 w-[680px] h-full justify-between'>
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
											<div className='w-32 text-wrap overflow-hidden'>
												<p>{JSON.parse(row.request)?.['attack-type']}</p>
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
											<div className='w-32 text-wrap overflow-hidden'>
												<p>{JSON.parse(row.request)?.['attack-type']}</p>
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
						<span>Hybrid Detection Logs</span>
						<span>Count: {hybridLogs.filter((log) => log.detected !== 'false').length} (Detected)</span>
					</CardHeader>
					<CardContent className='w-full'>
						<div className='flex flex-col pr-2 h-[280px] w-full overflow-y-scroll'>
							{hybridLogs
								.filter((log) => log.detected !== 'false')
								.map((row, index) => {
									return (
										<div
											key={index}
											className='flex border-t p-2 gap-4'>
											<div>
												<p>{row.index}</p>
											</div>
											<div className='w-32 text-wrap overflow-hidden'>
												<p>{JSON.parse(row.request)?.['attack-type']}</p>
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
