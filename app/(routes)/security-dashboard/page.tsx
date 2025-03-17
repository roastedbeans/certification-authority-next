import { Metadata } from 'next';
import { DashboardHeader, SecurityDashboardContent } from '@/app/_components';

export const metadata: Metadata = {
	title: 'Security Dashboard | Certification Authority',
	description: 'Monitor API logs and detect anomalies with signature, specification, and hybrid approaches',
};

export default function SecurityDashboardPage() {
	return (
		<div className='container mx-auto py-8'>
			<DashboardHeader
				title='Security Dashboard'
				description='Monitor API logs and detect anomalies'
			/>
			<SecurityDashboardContent />
		</div>
	);
}
