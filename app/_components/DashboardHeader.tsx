import React from 'react';

interface DashboardHeaderProps {
	title: string;
	description: string;
}

const DashboardHeader: React.FC<DashboardHeaderProps> = ({ title, description }) => {
	return (
		<div className='mb-8'>
			<h1 className='text-3xl font-bold tracking-tight'>{title}</h1>
			<p className='text-muted-foreground mt-2'>{description}</p>
		</div>
	);
};

export default DashboardHeader;
