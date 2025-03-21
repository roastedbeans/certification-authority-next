'use client';

import React, { useState } from 'react';
import * as Tabs from '@radix-ui/react-tabs';
import SecuritySummary from './SecuritySummary';
import ApiLogsViewer from './ApiLogsViewer';
import DetectionRuns from './DetectionRuns';
import SimulationsTab from './SimulationsTab';

const tabs = [
	{ id: 'summary', label: 'Summary' },
	{ id: 'detection', label: 'Detection Controls' },
	{ id: 'logs', label: 'Logs Viewer' },
	{ id: 'simulations', label: 'Simulations' },
];

export default function SecurityDashboardContent() {
	const [activeTab, setActiveTab] = useState('summary');

	return (
		<Tabs.Root
			className='flex flex-col w-full'
			value={activeTab}
			onValueChange={setActiveTab}>
			<Tabs.List className='flex border-b mb-6'>
				{tabs.map((tab) => (
					<Tabs.Trigger
						key={tab.id}
						value={tab.id}
						className={`px-4 py-2 focus:outline-none transition-colors ${
							activeTab === tab.id
								? 'border-b-2 border-primary text-primary'
								: 'text-muted-foreground hover:text-foreground'
						}`}>
						{tab.label}
					</Tabs.Trigger>
				))}
			</Tabs.List>

			<Tabs.Content
				value='summary'
				className='outline-none'>
				<SecuritySummary />
			</Tabs.Content>

			<Tabs.Content
				value='detection'
				className='outline-none'>
				<DetectionRuns />
			</Tabs.Content>

			<Tabs.Content
				value='logs'
				className='outline-none'>
				<ApiLogsViewer />
			</Tabs.Content>

			<Tabs.Content
				value='simulations'
				className='outline-none'>
				<SimulationsTab />
			</Tabs.Content>
		</Tabs.Root>
	);
}
