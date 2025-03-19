'use client';

import React, { useEffect, useState } from 'react';
import { getApiLogsSummary } from '../_actions/security-actions';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';

interface SummaryStats {
	total: number;
	attacks: number;
	signatureDetections: number;
	specificationDetections: number;
	hybridDetections: number;
}

export default function SecuritySummary() {
	const [stats, setStats] = useState<SummaryStats>({
		total: 0,
		attacks: 0,
		signatureDetections: 0,
		specificationDetections: 0,
		hybridDetections: 0,
	});
	const [loading, setLoading] = useState(true);

	useEffect(() => {
		const fetchStats = async () => {
			try {
				const data = await getApiLogsSummary();
				setStats(data);
			} catch (error) {
				console.error('Failed to fetch security stats:', error);
			} finally {
				setLoading(false);
			}
		};

		fetchStats();

		const interval = setInterval(() => {
			console.log('fetching stats');
			fetchStats();
		}, 5000);

		return () => clearInterval(interval);
	}, []);

	const chartData = [
		{ name: 'Total Logs', value: stats?.total },
		{ name: 'Actual Attacks', value: stats?.attacks },
		{ name: 'Signature Detections', value: stats?.signatureDetections },
		{ name: 'Specification Detections', value: stats?.specificationDetections },
		{ name: 'Hybrid Detections', value: stats?.hybridDetections },
	];

	const detectionEfficiency = stats?.attacks > 0 ? Math.round((stats?.hybridDetections / stats?.attacks) * 100) : 0;

	return (
		<div className='space-y-8'>
			<div className='grid grid-cols-1 md:grid-cols-3 gap-4'>
				<div className='bg-white dark:bg-gray-800 p-6 rounded-lg shadow'>
					<h3 className='text-lg font-medium mb-2'>API Logs</h3>
					<p className='text-3xl font-bold'>{stats?.total}</p>
					<p className='text-muted-foreground'>Total logs processed</p>
				</div>

				<div className='bg-white dark:bg-gray-800 p-6 rounded-lg shadow'>
					<h3 className='text-lg font-medium mb-2'>Actual Attacks</h3>
					<p className='text-3xl font-bold'>{stats?.attacks}</p>
					<p className='text-muted-foreground'>Malicious requests detected</p>
				</div>

				<div className='bg-white dark:bg-gray-800 p-6 rounded-lg shadow'>
					<h3 className='text-lg font-medium mb-2'>Detection Efficiency</h3>
					<p className='text-3xl font-bold'>{detectionEfficiency}%</p>
					<p className='text-muted-foreground'>Using hybrid approach</p>
				</div>
			</div>

			<div className='bg-white dark:bg-gray-800 p-6 rounded-lg shadow'>
				<h3 className='text-lg font-medium mb-4'>Detection Methods Comparison</h3>
				<div className='h-80'>
					<ResponsiveContainer
						width='100%'
						height='100%'>
						<BarChart
							data={chartData}
							margin={{ top: 20, right: 30, left: 20, bottom: 5 }}>
							<CartesianGrid strokeDasharray='3 3' />
							<XAxis dataKey='name' />
							<YAxis />
							<Tooltip />
							<Legend />
							<Bar
								dataKey='value'
								fill='#3b82f6'
								name='Count'
							/>
						</BarChart>
					</ResponsiveContainer>
				</div>
			</div>

			<div className='grid grid-cols-1 md:grid-cols-3 gap-4'>
				<div className='bg-white dark:bg-gray-800 p-6 rounded-lg shadow'>
					<h3 className='text-lg font-medium mb-2'>Signature-based</h3>
					<p className='text-3xl font-bold'>{stats?.signatureDetections}</p>
					<p className='text-muted-foreground'>Pattern matching detections</p>
				</div>

				<div className='bg-white dark:bg-gray-800 p-6 rounded-lg shadow'>
					<h3 className='text-lg font-medium mb-2'>Specification-based</h3>
					<p className='text-3xl font-bold'>{stats?.specificationDetections}</p>
					<p className='text-muted-foreground'>Schema validation detections</p>
				</div>

				<div className='bg-white dark:bg-gray-800 p-6 rounded-lg shadow'>
					<h3 className='text-lg font-medium mb-2'>Hybrid</h3>
					<p className='text-3xl font-bold'>{stats?.hybridDetections}</p>
					<p className='text-muted-foreground'>Combined approach detections</p>
				</div>
			</div>
		</div>
	);
}
