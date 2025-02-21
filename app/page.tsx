import AttackMonitor from './_components/AttackMonitor';
import AttackMonitorV2 from './_components/AttackMonitorV2';

export default function Home() {
	return (
		<div>
			<div className='flex flex-col items-center justify-center font-[family-name:var(--font-geist-sans)]'>
				<AttackMonitor />
			</div>
		</div>
	);
}
